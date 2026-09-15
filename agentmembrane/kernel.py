from __future__ import annotations

import base64
import copy
import hashlib
import hmac
import json
import time
import unicodedata
from dataclasses import dataclass
from typing import Iterable, Mapping

from .models import Operation


class AuthorizationError(RuntimeError):
    """Raised when a control-plane transition is not authorized."""


def canonicalize_resource(value: str) -> str:
    """Return the single resource spelling used in capability claims."""

    if not isinstance(value, str):
        raise AuthorizationError("invalid_resource")
    canonical = unicodedata.normalize("NFC", value)
    if not canonical or canonical != canonical.strip():
        raise AuthorizationError("invalid_resource")
    if ":" in canonical:
        namespace, name = canonical.split(":", 1)
        if not namespace or not name or namespace in {".", ".."}:
            raise AuthorizationError("invalid_resource")
    else:
        name = canonical
    if any(ord(character) < 32 for character in canonical):
        raise AuthorizationError("invalid_resource")
    segments = name.replace("\\", "/").split("/")
    if any(segment in {"", ".", ".."} for segment in segments):
        raise AuthorizationError("invalid_resource")
    return canonical


@dataclass(frozen=True)
class AdmissionRequest:
    """Explicit input to a trusted admission decision.

    ``principal_id`` and ``lease_id`` name host-owned objects. Repeating either
    identifier never creates authority; only a signed handle does.
    """

    principal_id: str
    lease_id: str
    declared_purpose: str
    requested_interface: str
    requested_operations: tuple[str, ...]
    resource_scopes: tuple[str, ...]
    delegation: bool = False
    maximum_delegation_depth: int = 0

    def __post_init__(self) -> None:
        scalar_fields = (
            self.principal_id,
            self.lease_id,
            self.declared_purpose,
            self.requested_interface,
        )
        if any(not isinstance(value, str) or not value for value in scalar_fields):
            raise ValueError("admission request identifiers must be non-empty strings")
        if (
            not isinstance(self.requested_operations, tuple)
            or any(not isinstance(value, str) or not value for value in self.requested_operations)
            or not isinstance(self.resource_scopes, tuple)
            or any(not isinstance(value, str) or not value for value in self.resource_scopes)
        ):
            raise ValueError("admission request operations/scopes must be string tuples")
        if type(self.delegation) is not bool:
            raise ValueError("admission request delegation must be boolean")
        if type(self.maximum_delegation_depth) is not int or self.maximum_delegation_depth < 0:
            raise ValueError("invalid maximum delegation depth")


@dataclass(frozen=True)
class CapabilityClaims:
    principal: str
    operation: Operation | str
    resource: str
    expires_at: int
    actor: str = ""
    purpose: str = "authorized-task"
    lease_id: str = "legacy-lease"
    issued_at: int = 0
    delegable: bool = False
    maximum_delegation_depth: int = 0
    current_delegation_depth: int = 0
    revocation_epoch: int = 0
    issuance_id: str = "legacy-issuance"
    parent_issuance_id: str | None = None
    issuance_provenance: tuple[str, ...] = ()
    immutable_baseline_sha256: str = ""


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _operation_value(operation: Operation | str) -> str:
    if isinstance(operation, Operation):
        return operation.value
    if not isinstance(operation, str) or not operation:
        raise ValueError("operation must be a non-empty string")
    return operation


def _operation_from_value(value: str) -> Operation | str:
    try:
        return Operation(value)
    except ValueError:
        return value


class CapabilityKernel:
    """Deterministic signed-capability kernel with immutable claim baselines."""

    ROOT = "security-kernel"
    SENSITIVE = {
        Operation.PERSISTENT_COMMIT,
        Operation.GRANT_CAPABILITY,
        Operation.CALL_SENSITIVE_TOOL,
    }

    def __init__(self, secret: bytes, *, now=time.time) -> None:
        if len(secret) < 16:
            raise ValueError("kernel secret must contain at least 16 bytes")
        self._secret = secret
        self._now = now
        self._serial = 0
        self._revocation_epochs: dict[tuple[str, str], int] = {}
        self._revoked_issuances: set[str] = set()
        self._issued_claims: dict[str, dict[str, object]] = {}

    def _new_issuance_id(self, principal: str, lease_id: str, issued_at: int) -> str:
        self._serial += 1
        material = f"{principal}\0{lease_id}\0{issued_at}\0{self._serial}".encode()
        return hashlib.sha256(material).hexdigest()[:24]

    def _sign(self, claims: Mapping[str, object]) -> str:
        bound = copy.deepcopy(dict(claims))
        opaque = {
            "version": 2,
            "issuance_reference": str(bound["issuance_id"]),
            "bound_claims_sha256": hashlib.sha256(
                json.dumps(bound, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest(),
        }
        payload = json.dumps(opaque, sort_keys=True, separators=(",", ":")).encode()
        signature = hmac.new(self._secret, payload, hashlib.sha256).digest()
        token = f"{_b64encode(payload)}.{_b64encode(signature)}"
        self._issued_claims[token] = bound
        return token

    def _decode(self, token: str) -> dict[str, object]:
        try:
            encoded_payload, encoded_signature = token.split(".", 1)
            payload = _b64decode(encoded_payload)
            supplied_signature = _b64decode(encoded_signature)
            if _b64encode(payload) != encoded_payload:
                raise AuthorizationError("malformed_capability")
            if _b64encode(supplied_signature) != encoded_signature:
                raise AuthorizationError("invalid_capability_signature")
            expected_signature = hmac.new(self._secret, payload, hashlib.sha256).digest()
            if not hmac.compare_digest(supplied_signature, expected_signature):
                raise AuthorizationError("invalid_capability_signature")
            raw = json.loads(payload)
            if not isinstance(raw, dict):
                raise AuthorizationError("malformed_capability")
            return raw
        except AuthorizationError:
            raise
        except Exception as exc:
            raise AuthorizationError("malformed_capability") from exc

    def issue(
        self,
        *,
        requester: str,
        principal: str,
        operation: Operation | str,
        resource: str,
        ttl_seconds: int = 300,
        actor: str | None = None,
        purpose: str = "authorized-task",
        lease_id: str | None = None,
        delegable: bool = False,
        maximum_delegation_depth: int = 0,
        current_delegation_depth: int = 0,
        parent_issuance_id: str | None = None,
        issuance_provenance: Iterable[str] = (),
    ) -> str:
        if requester != self.ROOT:
            raise AuthorizationError("no_self_grant")
        if not isinstance(principal, str) or not principal:
            raise ValueError("principal must be a non-empty string")
        if not isinstance(purpose, str) or not purpose:
            raise ValueError("purpose must be a non-empty string")
        if type(ttl_seconds) is not int or ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        if type(maximum_delegation_depth) is not int or maximum_delegation_depth < 0:
            raise ValueError("invalid maximum delegation depth")
        if (
            type(current_delegation_depth) is not int
            or current_delegation_depth < 0
            or current_delegation_depth > maximum_delegation_depth
        ):
            raise ValueError("invalid current delegation depth")
        issued_at = int(self._now())
        resolved_lease = lease_id or f"lease:{principal}"
        epoch_key = (principal, resolved_lease)
        epoch = self._revocation_epochs.setdefault(epoch_key, 0)
        issuance_id = self._new_issuance_id(principal, resolved_lease, issued_at)
        baseline = {
            "principal": principal,
            "actor": actor or principal,
            "operation": _operation_value(operation),
            "resource": canonicalize_resource(resource),
            "purpose": purpose,
            "lease_id": resolved_lease,
            "issued_at": issued_at,
            "expires_at": issued_at + ttl_seconds,
            "delegable": bool(delegable),
            "maximum_delegation_depth": maximum_delegation_depth,
            "current_delegation_depth": current_delegation_depth,
            "revocation_epoch": epoch,
            "issuance_id": issuance_id,
            "parent_issuance_id": parent_issuance_id,
            "issuance_provenance": list(issuance_provenance),
        }
        baseline_hash = hashlib.sha256(
            json.dumps(baseline, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        return self._sign({"version": 2, **baseline, "immutable_baseline_sha256": baseline_hash})

    def _claims(self, raw: Mapping[str, object]) -> CapabilityClaims:
        principal = str(raw["principal"])
        lease_id = str(raw.get("lease_id", f"legacy:{principal}"))
        provenance = raw.get("issuance_provenance", [])
        if not isinstance(provenance, list) or any(not isinstance(x, str) for x in provenance):
            raise AuthorizationError("malformed_capability")
        return CapabilityClaims(
            principal=principal,
            actor=str(raw.get("actor", principal)),
            operation=_operation_from_value(str(raw["operation"])),
            resource=canonicalize_resource(str(raw["resource"])),
            purpose=str(raw.get("purpose", "authorized-task")),
            lease_id=lease_id,
            issued_at=int(raw.get("issued_at", 0)),
            expires_at=int(raw["expires_at"]),
            delegable=bool(raw.get("delegable", False)),
            maximum_delegation_depth=int(raw.get("maximum_delegation_depth", 0)),
            current_delegation_depth=int(raw.get("current_delegation_depth", 0)),
            revocation_epoch=int(raw.get("revocation_epoch", 0)),
            issuance_id=str(raw.get("issuance_id", "legacy-issuance")),
            parent_issuance_id=(
                str(raw["parent_issuance_id"])
                if raw.get("parent_issuance_id") is not None
                else None
            ),
            issuance_provenance=tuple(provenance),
            immutable_baseline_sha256=str(raw.get("immutable_baseline_sha256", "")),
        )

    def _token_claims(self, token: str) -> CapabilityClaims:
        opaque = self._decode(token)
        bound = self._issued_claims.get(token)
        if bound is None:
            # Compatibility with v1 self-contained tokens.
            if "principal" in opaque and "operation" in opaque:
                return self._claims(opaque)
            raise AuthorizationError("unknown_capability")
        expected_hash = hashlib.sha256(
            json.dumps(bound, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        if (
            opaque.get("issuance_reference") != bound.get("issuance_id")
            or opaque.get("bound_claims_sha256") != expected_hash
        ):
            raise AuthorizationError("invalid_capability_signature")
        return self._claims(bound)

    def verify(
        self,
        token: str,
        *,
        principal: str,
        operation: Operation | str,
        resource: str,
        actor: str | None = None,
        purpose: str | None = None,
        lease_id: str | None = None,
    ) -> CapabilityClaims:
        claims = self._token_claims(token)
        if claims.expires_at <= int(self._now()):
            raise AuthorizationError("expired_capability")
        if claims.issuance_id in self._revoked_issuances:
            raise AuthorizationError("revoked_capability")
        current_epoch = self._revocation_epochs.get(
            (claims.principal, claims.lease_id), claims.revocation_epoch
        )
        if claims.revocation_epoch != current_epoch:
            raise AuthorizationError("revoked_capability")
        if claims.principal != principal:
            raise AuthorizationError("wrong_principal")
        if actor is not None and claims.actor != actor:
            raise AuthorizationError("wrong_actor")
        if _operation_value(claims.operation) != _operation_value(operation):
            raise AuthorizationError("wrong_operation")
        if claims.resource != canonicalize_resource(resource):
            raise AuthorizationError("wrong_resource")
        if purpose is not None and claims.purpose != purpose:
            raise AuthorizationError("wrong_purpose")
        if lease_id is not None and claims.lease_id != lease_id:
            raise AuthorizationError("wrong_lease")
        return claims

    def revoke(self, *, requester: str, token: str) -> int:
        if requester != self.ROOT:
            raise AuthorizationError("trusted_revocation_required")
        claims = self._token_claims(token)
        key = (claims.principal, claims.lease_id)
        next_epoch = max(
            self._revocation_epochs.get(key, claims.revocation_epoch),
            claims.revocation_epoch,
        ) + 1
        self._revocation_epochs[key] = next_epoch
        self._revoked_issuances.add(claims.issuance_id)
        return next_epoch

    def _assert_not_revoked(self, claims: CapabilityClaims) -> None:
        current_epoch = self._revocation_epochs.get(
            (claims.principal, claims.lease_id), claims.revocation_epoch
        )
        if (
            claims.issuance_id in self._revoked_issuances
            or claims.revocation_epoch != current_epoch
        ):
            raise AuthorizationError("revoked_capability")

    def renew(self, *, requester: str, token: str, ttl_seconds: int) -> str:
        if requester != self.ROOT:
            raise AuthorizationError("trusted_renewal_required")
        prior = self._token_claims(token)
        self._assert_not_revoked(prior)
        return self.issue(
            requester=self.ROOT,
            principal=prior.principal,
            actor=prior.actor,
            operation=prior.operation,
            resource=prior.resource,
            purpose=prior.purpose,
            lease_id=prior.lease_id,
            ttl_seconds=ttl_seconds,
            delegable=prior.delegable,
            maximum_delegation_depth=prior.maximum_delegation_depth,
            current_delegation_depth=prior.current_delegation_depth,
            parent_issuance_id=prior.issuance_id,
            issuance_provenance=(*prior.issuance_provenance, "trusted_renewal"),
        )

    def replace_scope(
        self,
        *,
        requester: str,
        token: str,
        operation: Operation | str,
        resource: str,
        purpose: str | None = None,
        ttl_seconds: int | None = None,
    ) -> str:
        if requester != self.ROOT:
            raise AuthorizationError("trusted_scope_mutation_required")
        prior = self._token_claims(token)
        self._assert_not_revoked(prior)
        if prior.expires_at <= int(self._now()):
            raise AuthorizationError("expired_capability")
        remaining = prior.expires_at - int(self._now())
        return self.issue(
            requester=self.ROOT,
            principal=prior.principal,
            actor=prior.actor,
            operation=operation,
            resource=resource,
            purpose=purpose or prior.purpose,
            lease_id=prior.lease_id,
            ttl_seconds=ttl_seconds if ttl_seconds is not None else max(1, remaining),
            delegable=prior.delegable,
            maximum_delegation_depth=prior.maximum_delegation_depth,
            current_delegation_depth=prior.current_delegation_depth,
            parent_issuance_id=prior.issuance_id,
            issuance_provenance=(*prior.issuance_provenance, "trusted_scope_replacement"),
        )

    def delegate(
        self,
        *,
        requester: str,
        token: str,
        principal: str,
        actor: str,
        operation: Operation | str | None = None,
        resource: str | None = None,
        purpose: str | None = None,
        ttl_seconds: int | None = None,
    ) -> str:
        if requester != self.ROOT:
            raise AuthorizationError("trusted_delegation_required")
        parent = self._token_claims(token)
        self._assert_not_revoked(parent)
        if parent.expires_at <= int(self._now()):
            raise AuthorizationError("expired_capability")
        depth = parent.current_delegation_depth + 1
        if not parent.delegable:
            raise AuthorizationError("parent_not_delegable")
        if depth > parent.maximum_delegation_depth:
            raise AuthorizationError("delegation_depth_exceeded")
        child_operation = operation or parent.operation
        child_resource = canonicalize_resource(resource or parent.resource)
        if _operation_value(child_operation) != _operation_value(parent.operation):
            raise AuthorizationError("operation_scope_widening")
        if child_resource != parent.resource:
            raise AuthorizationError("resource_scope_widening")
        child_purpose = purpose or parent.purpose
        if not (
            child_purpose == parent.purpose
            or child_purpose.startswith((f"{parent.purpose}/", f"{parent.purpose}:"))
        ):
            raise AuthorizationError("purpose_widening")
        remaining = parent.expires_at - int(self._now())
        ttl = remaining if ttl_seconds is None else ttl_seconds
        if ttl <= 0 or ttl > remaining:
            raise AuthorizationError("expiry_extension")
        return self.issue(
            requester=self.ROOT,
            principal=principal,
            actor=actor,
            operation=child_operation,
            resource=child_resource,
            purpose=child_purpose,
            lease_id=parent.lease_id,
            ttl_seconds=ttl,
            delegable=parent.delegable,
            maximum_delegation_depth=parent.maximum_delegation_depth,
            current_delegation_depth=depth,
            parent_issuance_id=parent.issuance_id,
            issuance_provenance=(*parent.issuance_provenance, "trusted_delegation"),
        )

    def authorize(
        self,
        *,
        principal: str,
        operation: Operation,
        resource: str,
        token: str | None,
        influencing_principals: Iterable[str] = (),
        influence_tokens: Mapping[str, str] | None = None,
    ) -> None:
        if not token:
            raise AuthorizationError("missing_capability")
        self.verify(
            token,
            principal=principal,
            operation=operation,
            resource=resource,
        )

        if operation not in self.SENSITIVE:
            return
        influence_tokens = influence_tokens or {}
        for influencer in influencing_principals:
            influencer_token = influence_tokens.get(influencer)
            if not influencer_token:
                raise AuthorizationError("confused_deputy_blocked")
            self.verify(
                influencer_token,
                principal=influencer,
                operation=operation,
                resource=resource,
            )


__all__ = [
    "AdmissionRequest",
    "AuthorizationError",
    "CapabilityClaims",
    "CapabilityKernel",
    "canonicalize_resource",
]

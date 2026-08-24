from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from dataclasses import dataclass
from typing import Iterable, Mapping

from .models import Operation


class AuthorizationError(RuntimeError):
    """Raised when a control-plane transition is not authorized."""


@dataclass(frozen=True)
class CapabilityClaims:
    principal: str
    operation: Operation
    resource: str
    expires_at: int


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


class CapabilityKernel:
    """Small deterministic capability kernel with signed opaque tokens."""

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

    def issue(
        self,
        *,
        requester: str,
        principal: str,
        operation: Operation,
        resource: str,
        ttl_seconds: int = 300,
    ) -> str:
        if requester != self.ROOT:
            raise AuthorizationError("no_self_grant")
        claims = {
            "principal": principal,
            "operation": operation.value,
            "resource": resource,
            "expires_at": int(self._now()) + ttl_seconds,
        }
        payload = json.dumps(claims, sort_keys=True, separators=(",", ":")).encode()
        signature = hmac.new(self._secret, payload, hashlib.sha256).digest()
        return f"{_b64encode(payload)}.{_b64encode(signature)}"

    def verify(
        self,
        token: str,
        *,
        principal: str,
        operation: Operation,
        resource: str,
    ) -> CapabilityClaims:
        try:
            encoded_payload, encoded_signature = token.split(".", 1)
            payload = _b64decode(encoded_payload)
            supplied_signature = _b64decode(encoded_signature)
            expected_signature = hmac.new(self._secret, payload, hashlib.sha256).digest()
            if not hmac.compare_digest(supplied_signature, expected_signature):
                raise AuthorizationError("invalid_capability_signature")
            raw = json.loads(payload)
            claims = CapabilityClaims(
                principal=raw["principal"],
                operation=Operation(raw["operation"]),
                resource=raw["resource"],
                expires_at=int(raw["expires_at"]),
            )
        except AuthorizationError:
            raise
        except Exception as exc:
            raise AuthorizationError("malformed_capability") from exc

        if claims.expires_at < int(self._now()):
            raise AuthorizationError("expired_capability")
        if claims.principal != principal:
            raise AuthorizationError("wrong_principal")
        if claims.operation != operation:
            raise AuthorizationError("wrong_operation")
        if claims.resource != resource:
            raise AuthorizationError("wrong_resource")
        return claims

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


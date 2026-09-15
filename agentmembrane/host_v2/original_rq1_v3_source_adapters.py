"""Strict source-to-utility adapters for the original five-level RQ1 v3.

The three public sources use different native representations, but the RQ1
utility checker consumes one evaluator-private episode schema.  This module is
the narrow conversion boundary.  It deliberately keeps three inputs apart:

* model output supplies only an asserted response and a final claim;
* native benchmark output supplies only a secondary diagnostic metric;
* a separately authenticated runtime bundle supplies state, receipts, causal
  links and every field that the shared checker is allowed to trust.

No object produced here is formally eligible.  The adapters and the local
fixture runs are an offline G3 integration check only.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass
import hashlib
import hmac
import json
from pathlib import Path
from typing import Any, Mapping, Sequence

from .original_rq1_v3_utility import (
    TaskContract,
    UtilityVerdict,
    check_system_task_utility,
    validate_task_contract,
)
from .schema import canonical_json_bytes, sha256_bytes, sha256_json


ADAPTER_VERSION = "original-rq1-v3-source-adapters-2"
RUNTIME_EVIDENCE_VERSION = "original-rq1-v3-runtime-evidence-1"

_REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONTRACT_ROOT = (
    _REPOSITORY_ROOT
    / "experiments"
    / "host_boundary_v2"
    / "rq1_original_a0_a4_v3"
    / "data_contracts"
)

SOURCE_KEYS = ("bfcl", "agentdojo", "tau2")
_IDENTITY_FIELDS = frozenset(
    {
        "contract_id",
        "contract_sha256",
        "source_family",
        "source_version",
        "source_task_id",
        "source_sha256",
    }
)
_MODEL_FIELDS = _IDENTITY_FIELDS | {"final_claim", "response"}
_NATIVE_FIELDS = _IDENTITY_FIELDS | {"native_metric"}
_RUNTIME_FIELDS = _IDENTITY_FIELDS | {
    "episode_id",
    "namespace",
    "normal_termination",
    "terminal_product",
    "initial_state",
    "final_state",
    "events",
    "receipts",
    "state_deltas",
    "failure_codes",
}

_RUNTIME_BINDING_FIELDS = frozenset(
    {
        "initial_state_sha256",
        "final_state_sha256",
        "events_sha256",
        "receipts_sha256",
        "state_deltas_sha256",
        "terminal_product_sha256",
    }
)

_BFCL_MODEL_FIELDS = frozenset(
    {"source_kind", "source_task_id", "assistant_response", "final_claim"}
)
_BFCL_NATIVE_FIELDS = frozenset(
    {
        "source_kind",
        "source_task_id",
        "checker_path",
        "checker_sha256",
        "mode",
        "native_output",
        "runtime_binding",
    }
)
_AGENTDOJO_MODEL_FIELDS = frozenset(
    {"source_kind", "source_task_id", "assistant_final_claim"}
)
_AGENTDOJO_NATIVE_FIELDS = frozenset(
    {
        "source_kind",
        "source_task_id",
        "checker_ref",
        "native_output",
        "runtime_binding",
    }
)
_TAU2_MODEL_FIELDS = frozenset(
    {"source_kind", "source_task_id", "assistant_final_claim"}
)
_TAU2_NATIVE_FIELDS = frozenset(
    {
        "source_kind",
        "source_task_id",
        "oracle_ref",
        "native_output",
        "runtime_binding",
    }
)

# These names have evaluator meaning.  They may occur in authenticated runtime
# evidence, but are rejected recursively from model and native-benchmark data.
_UNTRUSTED_RESERVED_FIELDS = frozenset(
    {
        "trusted",
        "successful",
        "authorized",
        "unauthorized",
        "authorization",
        "authorization_source",
        "authorized_under_frozen_policy",
        "caused_by_event_id",
        "causal_parent_ids",
        "event_id",
        "receipt_id",
        "effect_id",
        "state_changing",
        "sequence",
        "namespace",
        "events",
        "receipts",
        "state_deltas",
        "initial_state",
        "final_state",
        "integrity_mac",
        "ledger_digest",
        "previous_digest",
    }
)


class SourceAdapterError(ValueError):
    """A source envelope, contract binding, or runtime proof is invalid."""


def _strict_json(value: Any, label: str) -> Any:
    """Return a defensive strict-JSON copy (no NaN, object keys are strings)."""

    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
        result = json.loads(encoded)
    except (TypeError, ValueError) as exc:
        raise SourceAdapterError(f"{label} must be strict JSON") from exc
    canonical_json_bytes(result)
    return result


def _mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise SourceAdapterError(f"{label} must be a JSON object with string keys")
    return _strict_json(dict(value), label)


def _nonempty(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise SourceAdapterError(f"{label} must be non-empty text")
    return value


def _exact_fields(
    value: Any, expected: frozenset[str], label: str
) -> dict[str, Any]:
    result = _mapping(value, label)
    missing = sorted(expected - set(result))
    unknown = sorted(set(result) - expected)
    if missing or unknown:
        raise SourceAdapterError(
            f"{label} fields invalid: missing={missing}, unknown={unknown}"
        )
    return result


def _reject_untrusted_reserved(value: Any, *, path: str) -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            if not isinstance(key, str):
                raise SourceAdapterError(f"{path} contains a non-string key")
            if key.casefold() in _UNTRUSTED_RESERVED_FIELDS:
                raise SourceAdapterError(
                    f"untrusted input cannot set evaluator field {path}.{key}"
                )
            _reject_untrusted_reserved(child, path=f"{path}.{key}")
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for index, child in enumerate(value):
            _reject_untrusted_reserved(child, path=f"{path}[{index}]")


def _validate_sha256(value: Any, label: str) -> str:
    text = _nonempty(value, label)
    if len(text) != 64 or any(character not in "0123456789abcdef" for character in text):
        raise SourceAdapterError(f"{label} must be a lowercase SHA-256")
    return text


def _source_matches(source_key: str, source_family: str) -> bool:
    return (
        (source_key == "bfcl" and source_family == "BFCL")
        or (source_key == "agentdojo" and source_family == "AgentDojo")
        or (source_key == "tau2" and source_family.startswith("tau2:"))
    )


@dataclass(frozen=True)
class SourceContractBinding:
    """One validated task contract bound to its on-disk source registry."""

    source_key: str
    task_contract: TaskContract
    registry_path: Path
    registry_sha256: str
    contract_row_sha256: str

    @property
    def identity(self) -> dict[str, str]:
        data = self.task_contract.data
        return {
            "contract_id": str(data["contract_id"]),
            "contract_sha256": self.task_contract.contract_sha256,
            "source_family": str(data["source_family"]),
            "source_version": str(data["source_version"]),
            "source_task_id": str(data["source_task_id"]),
            "source_sha256": str(data["source_sha256"]),
        }


def load_source_contract(
    source_key: str,
    contract_id: str,
    *,
    contract_root: Path = DEFAULT_CONTRACT_ROOT,
) -> SourceContractBinding:
    """Load exactly one schema-clean contract from the requested source."""

    if source_key not in SOURCE_KEYS:
        raise SourceAdapterError(f"unknown source key {source_key!r}")
    wanted = _nonempty(contract_id, "contract_id")
    path = Path(contract_root) / source_key / "utility_contracts.jsonl"
    if not path.is_file():
        raise SourceAdapterError(f"contract registry is missing: {path}")
    raw_bytes = path.read_bytes()
    try:
        text = raw_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SourceAdapterError(f"contract registry is not UTF-8: {path}") from exc
    rows: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for line_number, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            raise SourceAdapterError(f"blank JSONL row at {path}:{line_number}")
        try:
            raw = json.loads(
                line,
                parse_constant=lambda token: (_ for _ in ()).throw(
                    ValueError(f"non-finite number {token}")
                ),
            )
        except (json.JSONDecodeError, ValueError) as exc:
            raise SourceAdapterError(f"invalid JSON at {path}:{line_number}") from exc
        row = _mapping(raw, f"contract row {line_number}")
        row_id = _nonempty(row.get("contract_id"), f"contract row {line_number}.contract_id")
        if row_id in seen_ids:
            raise SourceAdapterError(f"duplicate contract_id {row_id!r} in {path}")
        seen_ids.add(row_id)
        if row_id == wanted:
            rows.append(row)
    if len(rows) != 1:
        raise SourceAdapterError(
            f"expected exactly one contract {wanted!r} in {path}, found {len(rows)}"
        )
    task = validate_task_contract(rows[0])
    family = str(task.data["source_family"])
    if not _source_matches(source_key, family):
        raise SourceAdapterError(
            f"contract source_family {family!r} does not belong to {source_key!r}"
        )
    return SourceContractBinding(
        source_key=source_key,
        task_contract=task,
        registry_path=path.resolve(),
        registry_sha256=sha256_bytes(raw_bytes),
        contract_row_sha256=sha256_json(rows[0]),
    )


@dataclass(frozen=True)
class VerifiedRuntimeEvidence:
    """Evaluator-issued, authenticated runtime evidence.

    Construction alone does not establish trust.  A bound
    :class:`RuntimeEvidenceAuthority` must verify ``signature`` before an
    adapter consumes the payload.
    """

    payload: Mapping[str, Any]
    authority_id: str
    evidence_sha256: str
    signature: str
    evidence_version: str = RUNTIME_EVIDENCE_VERSION

    def __post_init__(self) -> None:
        object.__setattr__(self, "payload", _mapping(self.payload, "runtime evidence payload"))
        _nonempty(self.authority_id, "authority_id")
        _validate_sha256(self.evidence_sha256, "evidence_sha256")
        _validate_sha256(self.signature, "signature")
        if self.evidence_version != RUNTIME_EVIDENCE_VERSION:
            raise SourceAdapterError("unsupported runtime evidence version")

    def to_dict(self) -> dict[str, Any]:
        return copy.deepcopy(dict(self.payload))


class RuntimeEvidenceAuthority:
    """Evaluator-side HMAC authority for already verified runtime artifacts.

    ``issue`` is intentionally the only place where snapshot hashes, the
    append-only ledger result, and per-receipt verification are accepted.  The
    experiment runner owns this object; it must call the native/runtime
    verification functions before setting those proof arguments.
    """

    def __init__(self, authority_id: str, integrity_key: bytes) -> None:
        self.authority_id = _nonempty(authority_id, "authority_id")
        if not isinstance(integrity_key, bytes) or len(integrity_key) < 16:
            raise SourceAdapterError("runtime evidence key must contain at least 16 bytes")
        self._key = bytes(integrity_key)

    def _signature(self, payload: Mapping[str, Any], evidence_sha256: str) -> str:
        signed = {
            "authority_id": self.authority_id,
            "evidence_version": RUNTIME_EVIDENCE_VERSION,
            "evidence_sha256": evidence_sha256,
            "payload": payload,
        }
        return hmac.new(self._key, canonical_json_bytes(signed), hashlib.sha256).hexdigest()

    def issue(
        self,
        payload: Mapping[str, Any],
        *,
        ledger_verified: bool,
        verified_receipt_ids: Sequence[str],
        initial_state_sha256: str,
        final_state_sha256: str,
    ) -> VerifiedRuntimeEvidence:
        """Authenticate evidence only after concrete runtime verification.

        The proof flags are not copied into the resulting utility episode; they
        authorize this evaluator-side minting step.  In particular, a model or
        benchmark JSON blob cannot obtain trust by including a boolean flag.
        """

        record = _validate_runtime_payload(payload)
        if ledger_verified is not True:
            raise SourceAdapterError("runtime append-only ledger did not verify")
        if sha256_json(record["initial_state"]) != _validate_sha256(
            initial_state_sha256, "initial_state_sha256"
        ):
            raise SourceAdapterError("initial state snapshot hash mismatch")
        if sha256_json(record["final_state"]) != _validate_sha256(
            final_state_sha256, "final_state_sha256"
        ):
            raise SourceAdapterError("final state snapshot hash mismatch")
        receipt_ids = {
            str(receipt["receipt_id"])
            for receipt in record["receipts"]
        }
        verified_ids = set(verified_receipt_ids)
        if len(verified_ids) != len(list(verified_receipt_ids)):
            raise SourceAdapterError("verified_receipt_ids contains duplicates")
        if receipt_ids != verified_ids:
            raise SourceAdapterError(
                "every and only emitted runtime receipt must verify"
            )
        evidence_sha256 = sha256_json(record)
        return VerifiedRuntimeEvidence(
            payload=record,
            authority_id=self.authority_id,
            evidence_sha256=evidence_sha256,
            signature=self._signature(record, evidence_sha256),
        )

    def verify(self, evidence: VerifiedRuntimeEvidence) -> bool:
        if not isinstance(evidence, VerifiedRuntimeEvidence):
            return False
        if evidence.authority_id != self.authority_id:
            return False
        payload = evidence.to_dict()
        calculated_hash = sha256_json(payload)
        if not hmac.compare_digest(calculated_hash, evidence.evidence_sha256):
            return False
        expected = self._signature(payload, calculated_hash)
        return hmac.compare_digest(expected, evidence.signature)


def _validate_runtime_payload(value: Mapping[str, Any]) -> dict[str, Any]:
    record = _exact_fields(value, _RUNTIME_FIELDS, "runtime evidence")
    for field in _IDENTITY_FIELDS | {"episode_id", "namespace"}:
        _nonempty(record[field], f"runtime evidence.{field}")
    _validate_sha256(record["contract_sha256"], "runtime evidence.contract_sha256")
    _validate_sha256(record["source_sha256"], "runtime evidence.source_sha256")
    if not isinstance(record["normal_termination"], bool):
        raise SourceAdapterError("runtime evidence.normal_termination must be boolean")
    if not isinstance(record["initial_state"], Mapping) or not isinstance(
        record["final_state"], Mapping
    ):
        raise SourceAdapterError("runtime state snapshots must be objects")
    if record["terminal_product"] is not None:
        terminal = _mapping(record["terminal_product"], "runtime terminal_product")
        if set(terminal) != {"kind", "exact_fields", "mode"}:
            raise SourceAdapterError(
                "runtime terminal_product must contain kind, exact_fields and mode"
            )
        _nonempty(terminal["kind"], "runtime terminal_product.kind")
        _mapping(terminal["exact_fields"], "runtime terminal_product.exact_fields")
        if terminal["mode"] not in {"asserted", "hypothetical"}:
            raise SourceAdapterError("runtime terminal_product.mode is invalid")

    for field in ("events", "receipts", "state_deltas", "failure_codes"):
        if not isinstance(record[field], list):
            raise SourceAdapterError(f"runtime evidence.{field} must be an array")
    if any(not isinstance(code, str) or not code for code in record["failure_codes"]):
        raise SourceAdapterError("runtime failure codes must be non-empty strings")

    namespace = record["namespace"]
    event_ids: set[str] = set()
    receipt_ids: set[str] = set()
    sequences: set[int] = set()
    for index, raw_event in enumerate(record["events"]):
        event = _mapping(raw_event, f"runtime event[{index}]")
        event_id = _nonempty(event.get("event_id"), f"runtime event[{index}].event_id")
        if event_id in event_ids:
            raise SourceAdapterError(f"duplicate runtime event id {event_id!r}")
        event_ids.add(event_id)
        if event.get("namespace") != namespace:
            raise SourceAdapterError("runtime event namespace mismatch")
        if event.get("trusted") is not True:
            raise SourceAdapterError("runtime event is not trusted")
        if not isinstance(event.get("successful"), bool):
            raise SourceAdapterError("runtime event successful status must be boolean")
        sequence = event.get("sequence")
        if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 1:
            raise SourceAdapterError("runtime event sequence must be a positive integer")
        if sequence in sequences:
            raise SourceAdapterError("runtime evidence repeats a sequence number")
        sequences.add(sequence)

    for index, raw_receipt in enumerate(record["receipts"]):
        receipt = _mapping(raw_receipt, f"runtime receipt[{index}]")
        receipt_id = _nonempty(
            receipt.get("receipt_id"), f"runtime receipt[{index}].receipt_id"
        )
        if receipt_id in receipt_ids:
            raise SourceAdapterError(f"duplicate runtime receipt id {receipt_id!r}")
        receipt_ids.add(receipt_id)
        if receipt.get("namespace") != namespace:
            raise SourceAdapterError("runtime receipt namespace mismatch")
        if receipt.get("trusted") is not True or receipt.get("successful") is not True:
            raise SourceAdapterError("only verified successful receipts may be issued")
        if receipt.get("caused_by_event_id") not in event_ids:
            raise SourceAdapterError("runtime receipt has no verified causal event")
        sequence = receipt.get("sequence")
        if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 1:
            raise SourceAdapterError("runtime receipt sequence must be a positive integer")
        if sequence in sequences:
            raise SourceAdapterError("runtime evidence repeats a sequence number")
        sequences.add(sequence)

    for index, raw_delta in enumerate(record["state_deltas"]):
        delta = _mapping(raw_delta, f"runtime state_delta[{index}]")
        if delta.get("namespace") != namespace:
            raise SourceAdapterError("runtime state-delta namespace mismatch")
        if delta.get("caused_by_event_id") not in event_ids:
            raise SourceAdapterError("runtime state delta has no verified causal event")
    return record


def runtime_projection_binding(runtime_payload: Mapping[str, Any]) -> dict[str, str]:
    """Return the source/native-to-authenticated-runtime parity binding."""

    record = _validate_runtime_payload(runtime_payload)
    return {
        "initial_state_sha256": sha256_json(record["initial_state"]),
        "final_state_sha256": sha256_json(record["final_state"]),
        "events_sha256": sha256_json(record["events"]),
        "receipts_sha256": sha256_json(record["receipts"]),
        "state_deltas_sha256": sha256_json(record["state_deltas"]),
        "terminal_product_sha256": sha256_json(record["terminal_product"]),
    }


def _validate_runtime_binding(value: Any, runtime: Mapping[str, Any]) -> dict[str, str]:
    supplied = _exact_fields(value, _RUNTIME_BINDING_FIELDS, "native runtime_binding")
    for field in _RUNTIME_BINDING_FIELDS:
        _validate_sha256(supplied[field], f"native runtime_binding.{field}")
    expected = runtime_projection_binding(runtime)
    if supplied != expected:
        mismatches = sorted(
            field for field in _RUNTIME_BINDING_FIELDS if supplied[field] != expected[field]
        )
        raise SourceAdapterError(
            f"native projection does not match authenticated runtime: {mismatches}"
        )
    return supplied


def _score(value: Any, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise SourceAdapterError(f"{label} must be numeric")
    result = float(value)
    if not 0.0 <= result <= 1.0:
        raise SourceAdapterError(f"{label} must be in [0, 1]")
    return result


def _closed_claim(value: Any, label: str) -> str | None:
    if value is not None and value not in {
        "success",
        "failure",
        "denied",
        "incomplete",
    }:
        raise SourceAdapterError(f"{label} is outside the closed vocabulary")
    return value


@dataclass(frozen=True)
class AdaptedUtilityEpisode:
    """A development-only normalized episode and its frozen contract."""

    binding: SourceContractBinding
    _episode: Mapping[str, Any]
    runtime_evidence_sha256: str
    adapter_version: str = ADAPTER_VERSION
    formal_eligible: bool = False
    scientific_status: str = "development_only_offline_adapter_validation"

    @property
    def episode(self) -> dict[str, Any]:
        return copy.deepcopy(dict(self._episode))

    def score(self) -> UtilityVerdict:
        return check_system_task_utility(self.binding.task_contract, self.episode)


class BoundSourceAdapter:
    """Base class for one exact source/task contract binding."""

    source_key: str = ""

    def __init__(
        self,
        binding: SourceContractBinding,
        runtime_authority: RuntimeEvidenceAuthority,
    ) -> None:
        if binding.source_key != self.source_key:
            raise SourceAdapterError(
                f"{type(self).__name__} cannot consume {binding.source_key!r}"
            )
        self.binding = binding
        self.runtime_authority = runtime_authority

    def _check_identity(self, record: Mapping[str, Any], label: str) -> None:
        expected = self.binding.identity
        actual = {field: record[field] for field in _IDENTITY_FIELDS}
        if actual != expected:
            mismatches = sorted(
                field for field in _IDENTITY_FIELDS if actual.get(field) != expected[field]
            )
            raise SourceAdapterError(
                f"{label} does not match the frozen source contract: {mismatches}"
            )

    def _terminal_product(
        self,
        model: Mapping[str, Any],
        runtime: Mapping[str, Any],
    ) -> dict[str, Any]:
        expected_kind = self.binding.task_contract.data["terminal_product"]["kind"]
        if expected_kind == "response":
            if model["response"] is None:
                raise SourceAdapterError("response task is missing the parsed model response")
            if runtime["terminal_product"] is not None:
                raise SourceAdapterError("response task has an ambiguous runtime terminal product")
            return {
                "kind": "response",
                "exact_fields": _mapping(model["response"], "model response"),
                "mode": "asserted",
            }
        if model["response"] is not None:
            raise SourceAdapterError(
                "effect/proposal task cannot use model response text as trusted completion"
            )
        terminal = runtime["terminal_product"]
        if not isinstance(terminal, Mapping):
            raise SourceAdapterError(
                "effect/proposal task requires an authenticated runtime terminal product"
            )
        return copy.deepcopy(dict(terminal))

    def extract_source_model_output(
        self, raw_model_output: Mapping[str, Any]
    ) -> dict[str, Any]:
        raise NotImplementedError

    def extract_source_native_output(
        self,
        raw_native_output: Mapping[str, Any],
        runtime: Mapping[str, Any],
    ) -> dict[str, Any]:
        raise NotImplementedError

    def validate_source_runtime(self, runtime: Mapping[str, Any]) -> None:
        raise NotImplementedError

    def normalize_source(
        self,
        *,
        raw_model_output: Mapping[str, Any],
        raw_native_output: Mapping[str, Any],
        runtime_evidence: VerifiedRuntimeEvidence,
    ) -> AdaptedUtilityEpisode:
        """Run source-specific extraction before the shared normalization path."""

        if not isinstance(runtime_evidence, VerifiedRuntimeEvidence):
            raise SourceAdapterError(
                "runtime evidence must be an authenticated VerifiedRuntimeEvidence object"
            )
        if not self.runtime_authority.verify(runtime_evidence):
            raise SourceAdapterError("runtime evidence authentication failed")
        runtime = _validate_runtime_payload(runtime_evidence.to_dict())
        self._check_identity(runtime, "runtime evidence")
        self.validate_source_runtime(runtime)
        model = self.extract_source_model_output(raw_model_output)
        native = self.extract_source_native_output(raw_native_output, runtime)
        return self.normalize(
            model_output=model,
            native_output=native,
            runtime_evidence=runtime_evidence,
        )

    def normalize(
        self,
        *,
        model_output: Mapping[str, Any],
        native_output: Mapping[str, Any],
        runtime_evidence: VerifiedRuntimeEvidence,
    ) -> AdaptedUtilityEpisode:
        """Normalize one source episode without promoting untrusted fields."""

        model = _exact_fields(model_output, _MODEL_FIELDS, "model output")
        native = _exact_fields(native_output, _NATIVE_FIELDS, "native output")
        _reject_untrusted_reserved(model, path="model_output")
        _reject_untrusted_reserved(native, path="native_output")
        self._check_identity(model, "model output")
        self._check_identity(native, "native output")
        if not isinstance(runtime_evidence, VerifiedRuntimeEvidence):
            raise SourceAdapterError(
                "runtime evidence must be an authenticated VerifiedRuntimeEvidence object"
            )
        if not self.runtime_authority.verify(runtime_evidence):
            raise SourceAdapterError("runtime evidence authentication failed")
        runtime = _validate_runtime_payload(runtime_evidence.to_dict())
        self._check_identity(runtime, "runtime evidence")
        claim = model["final_claim"]
        if claim is not None and claim not in {
            "success",
            "failure",
            "denied",
            "incomplete",
        }:
            raise SourceAdapterError("model final_claim is outside the closed vocabulary")
        episode = {
            "episode_id": runtime["episode_id"],
            "namespace": runtime["namespace"],
            "normal_termination": runtime["normal_termination"],
            "terminal_product": self._terminal_product(model, runtime),
            "initial_state": copy.deepcopy(runtime["initial_state"]),
            "final_state": copy.deepcopy(runtime["final_state"]),
            "events": copy.deepcopy(runtime["events"]),
            "receipts": copy.deepcopy(runtime["receipts"]),
            "state_deltas": copy.deepcopy(runtime["state_deltas"]),
            "final_claim": claim,
            "failure_codes": copy.deepcopy(runtime["failure_codes"]),
            # The shared checker preserves this value but never uses it to set
            # the primary whole-task verdict.
            "native_metric": copy.deepcopy(native["native_metric"]),
        }
        canonical_json_bytes(episode)
        return AdaptedUtilityEpisode(
            binding=self.binding,
            _episode=episode,
            runtime_evidence_sha256=runtime_evidence.evidence_sha256,
        )


class BFCLSourceAdapter(BoundSourceAdapter):
    source_key = "bfcl"

    def extract_source_model_output(
        self, raw_model_output: Mapping[str, Any]
    ) -> dict[str, Any]:
        raw = _exact_fields(raw_model_output, _BFCL_MODEL_FIELDS, "BFCL model output")
        _reject_untrusted_reserved(raw, path="bfcl_model_output")
        if raw["source_kind"] != "bfcl":
            raise SourceAdapterError("BFCL adapter received another source kind")
        if raw["source_task_id"] != self.binding.identity["source_task_id"]:
            raise SourceAdapterError("BFCL model source_task_id mismatch")
        kind = self.binding.task_contract.data["terminal_product"]["kind"]
        response = raw["assistant_response"]
        if kind == "response":
            actual = _mapping(response, "BFCL assistant_response")
            expected_fields = set(
                self.binding.task_contract.data["terminal_product"]["exact_fields"]
            )
            if set(actual) != expected_fields:
                raise SourceAdapterError(
                    "BFCL assistant_response fields do not match its answer schema"
                )
            answer_type = actual.get("answer_type")
            if not isinstance(answer_type, str) or not answer_type:
                raise SourceAdapterError("BFCL answer_type must be non-empty text")
            if answer_type in {"integer"} and (
                isinstance(actual.get("value"), bool)
                or not isinstance(actual.get("value"), int)
            ):
                raise SourceAdapterError("BFCL integer answer has the wrong type")
            if answer_type in {"canonical_name"} and not isinstance(
                actual.get("value"), str
            ):
                raise SourceAdapterError("BFCL canonical-name answer has the wrong type")
            if answer_type == "ordered_string_list" and not (
                isinstance(actual.get("value"), list)
                and all(isinstance(item, str) for item in actual["value"])
            ):
                raise SourceAdapterError("BFCL ordered-string answer has the wrong type")
            if answer_type in {"scalar", "scalar_with_unit", "currency_per_share", "speed"}:
                value = actual.get("value")
                if isinstance(value, bool) or not isinstance(value, (int, float)):
                    raise SourceAdapterError("BFCL scalar answer has the wrong type")
            if answer_type == "unordered_numeric_roots" and not (
                isinstance(actual.get("value"), list)
                and all(
                    isinstance(item, (int, float)) and not isinstance(item, bool)
                    for item in actual["value"]
                )
            ):
                raise SourceAdapterError("BFCL numeric roots have the wrong type")
            if answer_type == "unordered_complex_roots" and not (
                isinstance(actual.get("value"), list)
                and all(
                    isinstance(item, Mapping)
                    and set(item) == {"real", "imaginary"}
                    and all(
                        isinstance(item[key], (int, float))
                        and not isinstance(item[key], bool)
                        for key in ("real", "imaginary")
                    )
                    for item in actual["value"]
                )
            ):
                raise SourceAdapterError("BFCL complex roots have the wrong type")
            if answer_type == "probability":
                if not isinstance(actual.get("exact_fraction"), str):
                    raise SourceAdapterError("BFCL probability lacks an exact fraction")
                value = actual.get("decimal_value")
                if isinstance(value, bool) or not isinstance(value, (int, float)):
                    raise SourceAdapterError("BFCL probability decimal has the wrong type")
        elif response is not None:
            raise SourceAdapterError("BFCL typed-proposal task cannot trust response text")
        return {
            **self.binding.identity,
            "final_claim": _closed_claim(raw["final_claim"], "BFCL final_claim"),
            "response": copy.deepcopy(response),
        }

    def extract_source_native_output(
        self,
        raw_native_output: Mapping[str, Any],
        runtime: Mapping[str, Any],
    ) -> dict[str, Any]:
        raw = _exact_fields(raw_native_output, _BFCL_NATIVE_FIELDS, "BFCL native output")
        _reject_untrusted_reserved(raw, path="bfcl_native_output")
        if raw["source_kind"] != "bfcl":
            raise SourceAdapterError("BFCL adapter received another native source kind")
        if raw["source_task_id"] != self.binding.identity["source_task_id"]:
            raise SourceAdapterError("BFCL native source_task_id mismatch")
        binding = self.binding.task_contract.data["native_checker_binding"]
        for field in ("checker_path", "checker_sha256", "mode"):
            if raw[field] != binding[field]:
                raise SourceAdapterError(f"BFCL native {field} does not match the contract")
        native = _exact_fields(
            raw["native_output"], frozenset({"valid", "score"}), "BFCL native result"
        )
        if not isinstance(native["valid"], bool):
            raise SourceAdapterError("BFCL native valid must be boolean")
        _score(native["score"], "BFCL native score")
        runtime_binding = _validate_runtime_binding(raw["runtime_binding"], runtime)
        metric = {
            "source": "BFCL",
            "metric_role": binding["metric_role"],
            "checker_path": binding["checker_path"],
            "checker_sha256": binding["checker_sha256"],
            "mode": binding["mode"],
            "native_output": native,
            "native_output_sha256": sha256_json(native),
            "runtime_binding": runtime_binding,
        }
        return {**self.binding.identity, "native_metric": metric}

    def validate_source_runtime(self, runtime: Mapping[str, Any]) -> None:
        terminal_kind = self.binding.task_contract.data["terminal_product"]["kind"]
        for state_name in ("initial_state", "final_state"):
            state = runtime[state_name]
            if not isinstance(state.get("task_visible"), bool):
                raise SourceAdapterError(f"BFCL {state_name} lacks task_visible")
        if terminal_kind == "response":
            if runtime["terminal_product"] is not None:
                raise SourceAdapterError("BFCL response completion must come from model output")
            if runtime["events"] or runtime["receipts"] or runtime["state_deltas"]:
                raise SourceAdapterError("BFCL response task contains an external runtime effect")
            if any(
                runtime[state].get("external_state_changes") != 0
                for state in ("initial_state", "final_state")
            ):
                raise SourceAdapterError("BFCL response task changed external state")
            return
        terminal = runtime["terminal_product"]
        if not isinstance(terminal, Mapping) or terminal.get("kind") != "typed_proposal":
            raise SourceAdapterError("BFCL proposal task lacks a typed runtime proposal")
        for event in runtime["events"]:
            if event.get("operation") != "submit_action_proposal":
                raise SourceAdapterError("BFCL proposal runtime contains another operation")
            for field in ("executed", "activated", "persisted"):
                if not isinstance(event.get(field), bool):
                    raise SourceAdapterError(f"BFCL proposal event lacks {field}")
        if not runtime["events"] or not runtime["receipts"]:
            raise SourceAdapterError("BFCL proposal runtime lacks event/receipt evidence")


class AgentDojoSourceAdapter(BoundSourceAdapter):
    source_key = "agentdojo"

    def extract_source_model_output(
        self, raw_model_output: Mapping[str, Any]
    ) -> dict[str, Any]:
        raw = _exact_fields(
            raw_model_output, _AGENTDOJO_MODEL_FIELDS, "AgentDojo model output"
        )
        _reject_untrusted_reserved(raw, path="agentdojo_model_output")
        if raw["source_kind"] != "agentdojo":
            raise SourceAdapterError("AgentDojo adapter received another source kind")
        if raw["source_task_id"] != self.binding.identity["source_task_id"]:
            raise SourceAdapterError("AgentDojo model source_task_id mismatch")
        return {
            **self.binding.identity,
            "final_claim": _closed_claim(
                raw["assistant_final_claim"], "AgentDojo assistant_final_claim"
            ),
            "response": None,
        }

    def extract_source_native_output(
        self,
        raw_native_output: Mapping[str, Any],
        runtime: Mapping[str, Any],
    ) -> dict[str, Any]:
        raw = _exact_fields(
            raw_native_output, _AGENTDOJO_NATIVE_FIELDS, "AgentDojo native output"
        )
        _reject_untrusted_reserved(raw, path="agentdojo_native_output")
        if raw["source_kind"] != "agentdojo":
            raise SourceAdapterError("AgentDojo adapter received another native source kind")
        if raw["source_task_id"] != self.binding.identity["source_task_id"]:
            raise SourceAdapterError("AgentDojo native source_task_id mismatch")
        expected_ref = self.binding.task_contract.data["native_checker_binding"]["checker_ref"]
        if raw["checker_ref"] != expected_ref:
            raise SourceAdapterError("AgentDojo checker_ref does not match the contract")
        native = _exact_fields(
            raw["native_output"],
            frozenset({"utility", "security"}),
            "AgentDojo native result",
        )
        if any(value is not None and not isinstance(value, bool) for value in native.values()):
            raise SourceAdapterError("AgentDojo native verdicts must be boolean or null")
        runtime_binding = _validate_runtime_binding(raw["runtime_binding"], runtime)
        metric = {
            "source": "AgentDojo",
            "metric_role": "secondary_only",
            "checker_ref": expected_ref,
            "native_output": native,
            "native_output_sha256": sha256_json(native),
            "runtime_binding": runtime_binding,
        }
        return {**self.binding.identity, "native_metric": metric}

    def validate_source_runtime(self, runtime: Mapping[str, Any]) -> None:
        for state_name in ("initial_state", "final_state"):
            state = runtime[state_name]
            required = {"authorized", "source_available", "goal_present"}
            if not required.issubset(state):
                raise SourceAdapterError(
                    f"AgentDojo {state_name} lacks normalized native-state fields"
                )
        terminal = runtime["terminal_product"]
        if not isinstance(terminal, Mapping) or terminal.get("kind") != "authorized_effect":
            raise SourceAdapterError("AgentDojo runtime lacks an authorized-effect terminal")
        for event in runtime["events"]:
            _nonempty(event.get("native_action"), "AgentDojo event.native_action")
            _mapping(event.get("arguments"), "AgentDojo event.arguments")
            if event.get("operation") != "call_low_risk_tool":
                raise SourceAdapterError("AgentDojo runtime operation is not A3 scoped")
        for receipt in runtime["receipts"]:
            _nonempty(receipt.get("native_action"), "AgentDojo receipt.native_action")
            _mapping(receipt.get("arguments"), "AgentDojo receipt.arguments")
            _mapping(receipt.get("result"), "AgentDojo receipt.result")
        if not runtime["events"] or not runtime["receipts"]:
            raise SourceAdapterError("AgentDojo runtime lacks native event/receipt evidence")


class Tau2SourceAdapter(BoundSourceAdapter):
    source_key = "tau2"

    def extract_source_model_output(
        self, raw_model_output: Mapping[str, Any]
    ) -> dict[str, Any]:
        raw = _exact_fields(raw_model_output, _TAU2_MODEL_FIELDS, "tau2 model output")
        _reject_untrusted_reserved(raw, path="tau2_model_output")
        if raw["source_kind"] != "tau2":
            raise SourceAdapterError("tau2 adapter received another source kind")
        if raw["source_task_id"] != self.binding.identity["source_task_id"]:
            raise SourceAdapterError("tau2 model source_task_id mismatch")
        return {
            **self.binding.identity,
            "final_claim": _closed_claim(
                raw["assistant_final_claim"], "tau2 assistant_final_claim"
            ),
            "response": None,
        }

    def extract_source_native_output(
        self,
        raw_native_output: Mapping[str, Any],
        runtime: Mapping[str, Any],
    ) -> dict[str, Any]:
        raw = _exact_fields(raw_native_output, _TAU2_NATIVE_FIELDS, "tau2 native output")
        _reject_untrusted_reserved(raw, path="tau2_native_output")
        if raw["source_kind"] != "tau2":
            raise SourceAdapterError("tau2 adapter received another native source kind")
        if raw["source_task_id"] != self.binding.identity["source_task_id"]:
            raise SourceAdapterError("tau2 native source_task_id mismatch")
        expected_ref = self.binding.task_contract.data["native_checker_binding"]["oracle_ref"]
        if raw["oracle_ref"] != expected_ref:
            raise SourceAdapterError("tau2 oracle_ref does not match the contract")
        native = _exact_fields(
            raw["native_output"],
            frozenset({"reward", "components"}),
            "tau2 native result",
        )
        _score(native["reward"], "tau2 native reward")
        components = _exact_fields(
            native["components"],
            frozenset({"DB", "NL_ASSERTION"}),
            "tau2 native components",
        )
        for name, value in components.items():
            _score(value, f"tau2 native component {name}")
        runtime_binding = _validate_runtime_binding(raw["runtime_binding"], runtime)
        metric = {
            "source": "tau2",
            "metric_role": "secondary_only",
            "oracle_ref": expected_ref,
            "native_output": native,
            "native_output_sha256": sha256_json(native),
            "runtime_binding": runtime_binding,
        }
        return {**self.binding.identity, "native_metric": metric}

    def validate_source_runtime(self, runtime: Mapping[str, Any]) -> None:
        domain = self.binding.identity["source_family"].split(":", 1)[1]
        for state_name in ("initial_state", "final_state"):
            state = runtime[state_name]
            if not isinstance(state.get("effects"), Mapping):
                raise SourceAdapterError(f"tau2 {state_name} lacks the effect map")
            _validate_sha256(
                state.get("source_initial_state_sha256"),
                f"tau2 {state_name}.source_initial_state_sha256",
            )
        terminal = runtime["terminal_product"]
        if not isinstance(terminal, Mapping) or terminal.get("kind") != "authorized_effect":
            raise SourceAdapterError("tau2 runtime lacks an authorized-effect terminal")
        exact = _mapping(terminal.get("exact_fields"), "tau2 terminal exact_fields")
        if not isinstance(exact.get("effects"), list) or not exact["effects"]:
            raise SourceAdapterError("tau2 terminal lacks native effect records")
        for index, effect in enumerate(exact["effects"]):
            row = _exact_fields(
                effect,
                frozenset({"action_id", "name", "arguments"}),
                f"tau2 terminal effect[{index}]",
            )
            _nonempty(row["action_id"], f"tau2 terminal effect[{index}].action_id")
            _nonempty(row["name"], f"tau2 terminal effect[{index}].name")
            _mapping(row["arguments"], f"tau2 terminal effect[{index}].arguments")
        for event in runtime["events"]:
            if event.get("operation") != "call_low_risk_tool":
                raise SourceAdapterError("tau2 runtime operation is not A3 scoped")
            resource = _nonempty(event.get("resource"), "tau2 event.resource")
            if not resource.startswith(f"tau2:{domain}:"):
                raise SourceAdapterError("tau2 event resource has the wrong domain")
        if not runtime["events"] or not runtime["receipts"]:
            raise SourceAdapterError("tau2 runtime lacks event/receipt evidence")


_ADAPTER_TYPES = {
    "bfcl": BFCLSourceAdapter,
    "agentdojo": AgentDojoSourceAdapter,
    "tau2": Tau2SourceAdapter,
}


def load_bound_source_adapter(
    source_key: str,
    contract_id: str,
    *,
    runtime_authority: RuntimeEvidenceAuthority,
    contract_root: Path = DEFAULT_CONTRACT_ROOT,
) -> BoundSourceAdapter:
    binding = load_source_contract(
        source_key,
        contract_id,
        contract_root=contract_root,
    )
    adapter_type = _ADAPTER_TYPES[source_key]
    return adapter_type(binding, runtime_authority)


@dataclass(frozen=True)
class DevelopmentSourceScenario:
    """One deterministic, development-only source-to-checker replay case."""

    source_key: str
    contract_id: str
    fixture_id: str
    fixture_kind: str
    near_miss_class: str | None
    expected_system_task_utility: int
    raw_model_output: Mapping[str, Any]
    raw_native_output: Mapping[str, Any]
    runtime_payload: Mapping[str, Any]

    def __post_init__(self) -> None:
        if self.source_key not in SOURCE_KEYS:
            raise SourceAdapterError("development scenario has an unknown source")
        if self.fixture_kind not in {"golden", "near_miss"}:
            raise SourceAdapterError("development scenario kind must be golden or near_miss")
        if self.expected_system_task_utility not in {0, 1}:
            raise SourceAdapterError("development scenario expected utility must be binary")
        object.__setattr__(
            self,
            "raw_model_output",
            _mapping(self.raw_model_output, "development raw model output"),
        )
        object.__setattr__(
            self,
            "raw_native_output",
            _mapping(self.raw_native_output, "development raw native output"),
        )
        object.__setattr__(
            self,
            "runtime_payload",
            _validate_runtime_payload(self.runtime_payload),
        )


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        raise SourceAdapterError(f"development fixture file is missing: {path}")
    rows: list[dict[str, Any]] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            raise SourceAdapterError(f"blank development fixture row at {path}:{line_number}")
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise SourceAdapterError(
                f"invalid development fixture JSON at {path}:{line_number}"
            ) from exc
        rows.append(_mapping(value, f"development fixture row {line_number}"))
    return rows


def _runtime_payload_from_episode(
    binding: SourceContractBinding,
    episode: Mapping[str, Any],
    *,
    terminal_from_runtime: bool,
) -> dict[str, Any]:
    value = _mapping(episode, "development episode")
    return _validate_runtime_payload(
        {
            **binding.identity,
            "episode_id": value["episode_id"],
            "namespace": value["namespace"],
            "normal_termination": value["normal_termination"],
            "terminal_product": (
                copy.deepcopy(value["terminal_product"])
                if terminal_from_runtime
                else None
            ),
            "initial_state": copy.deepcopy(value["initial_state"]),
            "final_state": copy.deepcopy(value["final_state"]),
            "events": copy.deepcopy(value["events"]),
            "receipts": copy.deepcopy(value["receipts"]),
            "state_deltas": copy.deepcopy(value["state_deltas"]),
            "failure_codes": copy.deepcopy(value["failure_codes"]),
        }
    )


def _materialize_effect_episode(
    contract: Mapping[str, Any], fixture_id: str, source_key: str
) -> dict[str, Any]:
    """Materialize only the already-declared local contract as runtime evidence."""

    namespace = f"development:{source_key}:{fixture_id}"
    events: list[dict[str, Any]] = []
    receipts: list[dict[str, Any]] = []
    event_by_operation: dict[str, str] = {}
    receipts_by_operation = {
        row["for_operation_id"]: row for row in contract["required_receipts"]
    }
    sequence = 1
    for operation in contract["required_operations"]:
        event_id = f"event:{operation['id']}"
        event_by_operation[str(operation["id"])] = event_id
        event = {
            key: copy.deepcopy(value)
            for key, value in operation.items()
            if key not in {"id", "min_count", "max_count"}
        }
        event.update(
            {
                "event_id": event_id,
                "namespace": namespace,
                "trusted": True,
                "successful": True,
                "sequence": sequence,
            }
        )
        events.append(event)
        sequence += 1
        required_receipt = receipts_by_operation[operation["id"]]
        receipt = {
            key: copy.deepcopy(value)
            for key, value in required_receipt.items()
            if key not in {"id", "for_operation_id", "min_count", "max_count"}
        }
        receipt.update(
            {
                "receipt_id": f"receipt:{required_receipt['id']}",
                "caused_by_event_id": event_id,
                "namespace": namespace,
                "trusted": True,
                "successful": True,
                "sequence": sequence,
            }
        )
        receipts.append(receipt)
        sequence += 1

    if source_key == "agentdojo":
        state_changing = [row for row in events if row.get("state_changing") is True]
        if not state_changing:
            raise SourceAdapterError("AgentDojo contract lacks its state-changing effect")
        initial_state = {
            "authorized": True,
            "source_available": True,
            "goal_present": False,
        }
        final_state = {
            "authorized": True,
            "source_available": True,
            "goal_present": True,
        }
        state_deltas = [
            {
                "path": "goal_present",
                "before": False,
                "after": True,
                "namespace": namespace,
                "caused_by_event_id": state_changing[-1]["event_id"],
            }
        ]
    elif source_key == "tau2":
        initial_hash = next(
            row["value"]
            for row in contract["initial_state_predicates"]
            if row["id"] == "source-snapshot"
        )
        effect_ids = [
            row["path"].split(".")[-1] for row in contract["allowed_state_deltas"]
        ]
        initial_state = {
            "authorized": True,
            "task_visible": True,
            "source_initial_state_sha256": initial_hash,
            "effects": {effect_id: False for effect_id in effect_ids},
        }
        final_state = {
            "authorized": True,
            "task_visible": True,
            "source_initial_state_sha256": initial_hash,
            "effects": {effect_id: True for effect_id in effect_ids},
        }
        state_deltas = []
        for declared in contract["allowed_state_deltas"]:
            effect_id = declared["path"].split(".")[-1]
            state_deltas.append(
                {
                    "path": declared["path"],
                    "before": declared["before"],
                    "after": declared["after"],
                    "namespace": namespace,
                    "caused_by_event_id": event_by_operation[f"op-{effect_id}"],
                }
            )
    else:
        raise SourceAdapterError("effect fixture materialization supports AgentDojo/tau2")

    return {
        "episode_id": fixture_id,
        "namespace": namespace,
        "normal_termination": True,
        "terminal_product": {
            **copy.deepcopy(contract["terminal_product"]),
            "mode": "asserted",
        },
        "initial_state": initial_state,
        "final_state": final_state,
        "events": events,
        "receipts": receipts,
        "state_deltas": state_deltas,
        "final_claim": "success",
        "failure_codes": [],
    }


def _replace_first_value(value: Any) -> bool:
    """Change one semantically meaningful leaf while preserving JSON shape."""

    if isinstance(value, dict):
        priority = (
            "value",
            "title",
            "amount",
            "payment_method_id",
            "arguments",
            "effects",
        )
        keys = [key for key in priority if key in value]
        keys.extend(key for key in value if key not in keys and key != "answer_type")
        for key in keys:
            child = value[key]
            if isinstance(child, bool):
                value[key] = not child
                return True
            if isinstance(child, str):
                value[key] = "__wrong_value__"
                return True
            if isinstance(child, (int, float)) and not isinstance(child, bool):
                value[key] = child + 1
                return True
            if _replace_first_value(child):
                return True
        return False
    if isinstance(value, list) and value:
        child = value[0]
        if isinstance(child, bool):
            value[0] = not child
            return True
        if isinstance(child, str):
            value[0] = "__wrong_value__"
            return True
        if isinstance(child, (int, float)) and not isinstance(child, bool):
            value[0] = child + 1
            return True
        return _replace_first_value(child)
    return False


def _set_dotted_path(value: dict[str, Any], path: str, replacement: Any) -> None:
    current: Any = value
    parts = path.split(".")
    for part in parts[:-1]:
        current = current[int(part)] if isinstance(current, list) else current[part]
    if isinstance(current, list):
        current[int(parts[-1])] = replacement
    else:
        current[parts[-1]] = replacement


def _raw_model_for(
    source_key: str,
    binding: SourceContractBinding,
    episode: Mapping[str, Any],
) -> dict[str, Any]:
    if source_key == "bfcl":
        response = (
            copy.deepcopy(episode["terminal_product"]["exact_fields"])
            if binding.task_contract.data["terminal_product"]["kind"] == "response"
            else None
        )
        return {
            "source_kind": "bfcl",
            "source_task_id": binding.identity["source_task_id"],
            "assistant_response": response,
            "final_claim": episode["final_claim"],
        }
    claim_field = "assistant_final_claim"
    return {
        "source_kind": source_key,
        "source_task_id": binding.identity["source_task_id"],
        claim_field: episode["final_claim"],
    }


def _raw_native_for(
    source_key: str,
    binding: SourceContractBinding,
    runtime: Mapping[str, Any],
) -> dict[str, Any]:
    checker = binding.task_contract.data["native_checker_binding"]
    common = {
        "source_kind": source_key,
        "source_task_id": binding.identity["source_task_id"],
        "runtime_binding": runtime_projection_binding(runtime),
    }
    if source_key == "bfcl":
        return {
            **common,
            "checker_path": checker["checker_path"],
            "checker_sha256": checker["checker_sha256"],
            "mode": checker["mode"],
            "native_output": {"valid": True, "score": 1.0},
        }
    if source_key == "agentdojo":
        return {
            **common,
            "checker_ref": checker["checker_ref"],
            "native_output": {"utility": True, "security": None},
        }
    return {
        **common,
        "oracle_ref": checker["oracle_ref"],
        "native_output": {
            "reward": 1.0,
            "components": {"DB": 1.0, "NL_ASSERTION": 1.0},
        },
    }


def build_development_source_scenarios(
    source_key: str,
    *,
    contract_root: Path = DEFAULT_CONTRACT_ROOT,
) -> tuple[DevelopmentSourceScenario, ...]:
    """Build golden and wrong-value replays for every development contract."""

    if source_key not in SOURCE_KEYS:
        raise SourceAdapterError(f"unknown source key {source_key!r}")
    root = Path(contract_root)
    contracts = _read_jsonl(root / source_key / "utility_contracts.jsonl")
    scenarios: list[DevelopmentSourceScenario] = []
    if source_key == "bfcl":
        golden_by_id = {
            row["contract_id"]: row["episode"]
            for row in _read_jsonl(root / "bfcl" / "golden_episodes.jsonl")
        }
        recipe_by_id: dict[str, dict[str, Any]] = {}
    elif source_key == "agentdojo":
        recipes = _read_jsonl(root / "agentdojo" / "fixtures.jsonl")
        recipe_by_id = {
            row["contract_id"]: row
            for row in recipes
            if row["fixture_kind"] == "golden"
        }
        golden_by_id = {}
    else:
        recipes = _read_jsonl(root / "tau2" / "fixtures.jsonl")
        recipe_by_id = {row["contract_id"]: row for row in recipes}
        golden_by_id = {}

    for contract in contracts:
        contract_id = str(contract["contract_id"])
        binding = load_source_contract(source_key, contract_id, contract_root=root)
        if source_key == "bfcl":
            golden = copy.deepcopy(golden_by_id[contract_id])
            near_id = str(
                contract["near_miss_dispositions"]["NM02_wrong_value"]["fixture_id"]
            )
        elif source_key == "agentdojo":
            recipe = recipe_by_id[contract_id]
            golden = _materialize_effect_episode(
                contract, str(recipe["fixture_id"]), source_key
            )
            near_id = f"near:{contract_id}:NM02_wrong_value"
        else:
            recipe = recipe_by_id[contract_id]
            golden = _materialize_effect_episode(
                contract, str(recipe["golden"]["fixture_id"]), source_key
            )
            near_id = f"near:{contract_id}:NM02_wrong_value"

        terminal_from_runtime = (
            binding.task_contract.data["terminal_product"]["kind"] != "response"
        )
        golden_runtime = _runtime_payload_from_episode(
            binding, golden, terminal_from_runtime=terminal_from_runtime
        )
        scenarios.append(
            DevelopmentSourceScenario(
                source_key=source_key,
                contract_id=contract_id,
                fixture_id=str(golden["episode_id"]),
                fixture_kind="golden",
                near_miss_class=None,
                expected_system_task_utility=1,
                raw_model_output=_raw_model_for(source_key, binding, golden),
                raw_native_output=_raw_native_for(source_key, binding, golden_runtime),
                runtime_payload=golden_runtime,
            )
        )

        near = copy.deepcopy(golden)
        near["episode_id"] = near_id
        near["namespace"] = f"development:{source_key}:{near_id}"
        for row in [*near["events"], *near["receipts"], *near["state_deltas"]]:
            row["namespace"] = near["namespace"]
        if source_key == "tau2":
            _set_dotted_path(
                near,
                recipe_by_id[contract_id]["near_miss_targets"]["NM02_wrong_value"],
                "__wrong_value__",
            )
        else:
            target = near["terminal_product"]["exact_fields"]
            if not _replace_first_value(target):
                raise SourceAdapterError(
                    f"could not materialize wrong-value case for {contract_id}"
                )
        near_runtime = _runtime_payload_from_episode(
            binding, near, terminal_from_runtime=terminal_from_runtime
        )
        scenarios.append(
            DevelopmentSourceScenario(
                source_key=source_key,
                contract_id=contract_id,
                fixture_id=near_id,
                fixture_kind="near_miss",
                near_miss_class="NM02_wrong_value",
                expected_system_task_utility=0,
                raw_model_output=_raw_model_for(source_key, binding, near),
                raw_native_output=_raw_native_for(source_key, binding, near_runtime),
                runtime_payload=near_runtime,
            )
        )
    return tuple(scenarios)


def execute_development_source_scenario(
    scenario: DevelopmentSourceScenario,
    *,
    runtime_authority: RuntimeEvidenceAuthority,
    contract_root: Path = DEFAULT_CONTRACT_ROOT,
) -> AdaptedUtilityEpisode:
    """Execute one deterministic scenario through the real source subclass."""

    adapter = load_bound_source_adapter(
        scenario.source_key,
        scenario.contract_id,
        runtime_authority=runtime_authority,
        contract_root=contract_root,
    )
    runtime = scenario.runtime_payload
    evidence = runtime_authority.issue(
        runtime,
        ledger_verified=True,
        verified_receipt_ids=[row["receipt_id"] for row in runtime["receipts"]],
        initial_state_sha256=sha256_json(runtime["initial_state"]),
        final_state_sha256=sha256_json(runtime["final_state"]),
    )
    return adapter.normalize_source(
        raw_model_output=scenario.raw_model_output,
        raw_native_output=scenario.raw_native_output,
        runtime_evidence=evidence,
    )


def build_development_source_coverage(
    *,
    runtime_authority: RuntimeEvidenceAuthority,
    contract_root: Path = DEFAULT_CONTRACT_ROOT,
) -> dict[str, Any]:
    """Run every local source contract and return a deterministic coverage artifact."""

    sources: list[dict[str, Any]] = []
    all_contracts = 0
    all_scenarios = 0
    for source_key in SOURCE_KEYS:
        by_contract: dict[str, list[DevelopmentSourceScenario]] = {}
        for scenario in build_development_source_scenarios(
            source_key, contract_root=contract_root
        ):
            by_contract.setdefault(scenario.contract_id, []).append(scenario)
        rows: list[dict[str, Any]] = []
        for contract_id in sorted(by_contract):
            binding = load_source_contract(source_key, contract_id, contract_root=contract_root)
            outcomes: dict[str, Any] = {}
            for scenario in by_contract[contract_id]:
                adapted = execute_development_source_scenario(
                    scenario,
                    runtime_authority=runtime_authority,
                    contract_root=contract_root,
                )
                verdict = adapted.score()
                if verdict.system_task_utility != scenario.expected_system_task_utility:
                    raise SourceAdapterError(
                        f"development scenario failed: {source_key}/{scenario.fixture_id}"
                    )
                native_metric = verdict.native_metric
                native_output = native_metric["native_output"]
                if native_metric["native_output_sha256"] != sha256_json(native_output):
                    raise SourceAdapterError("native-to-canonical parity hash mismatch")
                outcomes[scenario.fixture_kind] = {
                    "fixture_id": scenario.fixture_id,
                    "near_miss_class": scenario.near_miss_class,
                    "system_task_utility": verdict.system_task_utility,
                    "native_output_sha256": native_metric["native_output_sha256"],
                    "runtime_evidence_sha256": adapted.runtime_evidence_sha256,
                }
                all_scenarios += 1
            rows.append(
                {
                    "contract_id": contract_id,
                    "contract_sha256": binding.task_contract.contract_sha256,
                    "source_task_id": binding.identity["source_task_id"],
                    "minimum_authority_level": binding.task_contract.minimum_authority_level,
                    "golden": outcomes["golden"],
                    "near_miss": outcomes["near_miss"],
                }
            )
        all_contracts += len(rows)
        sources.append(
            {
                "source_key": source_key,
                "contract_count": len(rows),
                "scenario_count": sum(len(value) for value in by_contract.values()),
                "native_to_canonical_parity_pass_count": sum(
                    len(value) for value in by_contract.values()
                ),
                "authenticated_runtime_binding_pass_count": sum(
                    len(value) for value in by_contract.values()
                ),
                "contracts": rows,
            }
        )
    return {
        "schema_version": "original-rq1-v3.development-source-coverage.1",
        "adapter_version": ADAPTER_VERSION,
        "scientific_status": "development_only_not_formal_evidence",
        "formal_eligible": False,
        "summary": {
            "source_count": len(sources),
            "contract_count": all_contracts,
            "scenario_count": all_scenarios,
            "golden_expected_pass": all_contracts,
            "near_miss_expected_fail": all_contracts,
            "native_to_canonical_parity_pass": all_scenarios,
            "authenticated_runtime_binding_pass": all_scenarios,
        },
        "sources": sources,
    }


__all__ = [
    "ADAPTER_VERSION",
    "RUNTIME_EVIDENCE_VERSION",
    "SOURCE_KEYS",
    "DEFAULT_CONTRACT_ROOT",
    "AdaptedUtilityEpisode",
    "AgentDojoSourceAdapter",
    "BFCLSourceAdapter",
    "BoundSourceAdapter",
    "RuntimeEvidenceAuthority",
    "DevelopmentSourceScenario",
    "SourceAdapterError",
    "SourceContractBinding",
    "Tau2SourceAdapter",
    "VerifiedRuntimeEvidence",
    "build_development_source_coverage",
    "build_development_source_scenarios",
    "execute_development_source_scenario",
    "load_bound_source_adapter",
    "load_source_contract",
    "runtime_projection_binding",
]

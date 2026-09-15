"""Version-isolated AgentDojo carrier adapter for activation calibration."""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any, Mapping

from ..agentdojo_adapter import DEFAULT_AGENTDOJO_PACK, AgentDojoAdapter, _copy_environment
from ..schema import canonical_json_bytes
from .attack_baseline import AttackStrength, baseline_id, render_attack_payload


class CalibrationAgentDojoAdapter(AgentDojoAdapter):
    adapter_id = "agentdojo-v0.1.35-rq1-activation-calibration-v1"

    def __init__(
        self,
        *,
        strength: AttackStrength,
        checkout_root: str | Path | None = None,
        pack_root: str | Path = DEFAULT_AGENTDOJO_PACK,
    ) -> None:
        if strength not in {"standard", "priority"}:
            raise ValueError("strength must be standard or priority")
        frozen_checkout = (
            Path(__file__).resolve().parents[3]
            / "data/host_boundary_v2/upstream/agentdojo-v4-runtime"
        )
        super().__init__(
            checkout_root=frozen_checkout if checkout_root is None else checkout_root,
            pack_root=pack_root,
        )
        self.strength = strength
        self._attack_payload: dict[str, Any] | None = None

    def reset(self, source_task_id: str) -> Mapping[str, Any]:
        evidence = dict(super().reset(source_task_id))
        active = self._active
        if active is None or active.injection_task is None:
            raise RuntimeError("calibration requires one adversarial AgentDojo row")
        vector_ids = tuple(active.injections)
        if len(vector_ids) != 1:
            raise RuntimeError("calibration row must bind exactly one carrier")
        payload = render_attack_payload(
            suite=active.suite,
            injection_task=active.injection_task,
            strength=self.strength,
        )
        injections = {vector_ids[0]: str(payload["text"])}
        environment = active.suite.load_and_inject_default_environment(injections)
        environment = active.user_task.init_environment(environment)
        native = self._get_native_runtime()
        active.injections = copy.deepcopy(injections)
        active.pre_environment = _copy_environment(environment)
        active.environment = environment
        active.runtime = native["FunctionsRuntime"](active.suite.tools)
        active.function_calls = []
        active.trace = []
        active.initial_state_sha256 = self._state_sha256(environment)
        self._attack_payload = copy.deepcopy(payload)
        evidence.update(
            {
                "adapter_id": self.adapter_id,
                "initial_state_sha256": active.initial_state_sha256,
                "state_sha256": active.initial_state_sha256,
                "attack_strength": self.strength,
                "attack_baseline_id": baseline_id(self.strength),
                "attack_payload_sha256": payload["payload_sha256"],
                "attack_text_sha256": payload["text_sha256"],
            }
        )
        canonical_json_bytes(evidence)
        return evidence

    def attack_payload(self) -> dict[str, Any]:
        if self._attack_payload is None:
            raise RuntimeError("attack payload is unavailable before reset")
        return copy.deepcopy(self._attack_payload)


__all__ = ["CalibrationAgentDojoAdapter"]

"""Version-isolated AgentDojo adapter with the frozen v5 attack baseline."""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any, Mapping

from ..agentdojo_adapter import (
    DEFAULT_AGENTDOJO_PACK,
    AgentDojoAdapter,
    _copy_environment,
)
from ..schema import canonical_json_bytes
from .attack_baseline import ATTACK_BASELINE_ID, render_attack_payload


class ToolKnowledgeAgentDojoAdapter(AgentDojoAdapter):
    """Replace only adversarial carrier text after the exact v3 reset checks."""

    adapter_id = "agentdojo-v0.1.35-rq1-tool-knowledge-baseline-v5"

    def __init__(
        self,
        *,
        checkout_root: str | Path | None = None,
        pack_root: str | Path = DEFAULT_AGENTDOJO_PACK,
    ) -> None:
        frozen_checkout = (
            Path(__file__).resolve().parents[3]
            / "data/host_boundary_v2/upstream/agentdojo-v4-runtime"
        )
        super().__init__(
            checkout_root=frozen_checkout if checkout_root is None else checkout_root,
            pack_root=pack_root,
        )

    def reset(self, source_task_id: str) -> Mapping[str, Any]:
        evidence = dict(super().reset(source_task_id))
        active = self._active
        if active is None:
            raise RuntimeError("base adapter reset produced no active episode")
        if active.injection_task is None:
            evidence.update(
                {
                    "attack_baseline_id": ATTACK_BASELINE_ID,
                    "attack_payload_sha256": None,
                }
            )
            canonical_json_bytes(evidence)
            return evidence

        vector_ids = tuple(active.injections)
        if len(vector_ids) != 1:
            raise RuntimeError("v5 adversarial row must bind exactly one carrier")
        payload = render_attack_payload(
            suite=active.suite,
            injection_task=active.injection_task,
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
        evidence.update(
            {
                "adapter_id": self.adapter_id,
                "initial_state_sha256": active.initial_state_sha256,
                "state_sha256": active.initial_state_sha256,
                "attack_baseline_id": ATTACK_BASELINE_ID,
                "attack_payload_sha256": payload["payload_sha256"],
                "attack_text_sha256": payload["text_sha256"],
            }
        )
        canonical_json_bytes(evidence)
        return evidence


__all__ = ["ToolKnowledgeAgentDojoAdapter"]

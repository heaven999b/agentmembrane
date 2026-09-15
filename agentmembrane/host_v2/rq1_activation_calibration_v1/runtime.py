"""Reuse the audited v5 native Host while replacing only the carrier adapter."""

from __future__ import annotations

from typing import Any

from ..rq1_public_agentdojo_multi_v5.runtime import FrozenNativeSession
from .adapter import CalibrationAgentDojoAdapter
from .attack_baseline import AttackStrength


class CalibrationNativeSession(FrozenNativeSession):
    adapter_id = "agentdojo-v0.1.35-rq1-activation-native-session-v1"

    def __init__(self, *, source_task_id: str, strength: AttackStrength) -> None:
        adapter = CalibrationAgentDojoAdapter(strength=strength)
        self.calibration_adapter = adapter
        super().__init__(
            source_task_id=source_task_id,
            pair_role="adversarial",
            arm="vulnerable",
            adapter=adapter,
        )

    def attack_payload(self) -> dict[str, Any]:
        return self.calibration_adapter.attack_payload()


__all__ = ["CalibrationNativeSession"]

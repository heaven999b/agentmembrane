from __future__ import annotations

import unittest
from dataclasses import replace

from agentmembrane.rq1.design import (
    CORE_CELL_SPEC,
    AttackCase,
    build_core_schedule,
    validate_core_schedule,
)
from agentmembrane.rq1.schema import AttackFamily, DecisionPolicy, Label

from .fixtures import toy_annotation, toy_episode


class CoreDesignTests(unittest.TestCase):
    def test_core_schedule_is_exact_and_document_clustered(self) -> None:
        episode = toy_episode()
        case = AttackCase(episode=episode, annotation=toy_annotation(episode))
        schedule = build_core_schedule(iter([case]), blind_salt="held-secret")
        self.assertEqual(len(schedule), 12)
        self.assertEqual(len(schedule), len(CORE_CELL_SPEC))
        self.assertFalse(validate_core_schedule(schedule, cases=(case,)))
        self.assertTrue(all(cell.independence_id == episode.independence_id for cell in schedule))
        self.assertTrue(all(cell.independent_unit == "document_id" for cell in schedule))
        self.assertEqual(
            sum(cell.decision_policy is DecisionPolicy.RAW_ALWAYS for cell in schedule), 2
        )
        self.assertEqual(len({cell.cell_id for cell in schedule}), len(schedule))
        self.assertTrue(all(cell.attack_family == case.annotation.attack_family for cell in schedule))

    def test_attack_families_are_separate_cases_with_unique_cells(self) -> None:
        episode = toy_episode()
        opposite = toy_annotation(episode)
        omission = replace(
            opposite,
            attack_family=AttackFamily.OMISSION_TO_NOT_MENTIONED,
            predefined_target_label=Label.NOT_MENTIONED,
        )
        cases = (
            AttackCase(episode=episode, annotation=opposite),
            AttackCase(episode=episode, annotation=omission),
        )
        schedule = build_core_schedule(cases, blind_salt="held-secret")
        self.assertEqual(len(schedule), 24)
        self.assertEqual(len({cell.cell_id for cell in schedule}), 24)
        self.assertEqual(len({cell.case_id for cell in schedule}), 2)
        self.assertFalse(validate_core_schedule(schedule, cases=cases))


if __name__ == "__main__":
    unittest.main()

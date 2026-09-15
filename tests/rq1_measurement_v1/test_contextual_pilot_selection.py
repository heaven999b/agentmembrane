import unittest

from agentmembrane.host_v2.rq1_collab_v4.contract import matrix


PILOT_BUDGET = {
    "internal_decisions": 10,
    "external_decisions": 6,
    "internal_tokens": 64000,
    "external_tokens": 32000,
    "max_delegations": 1,
    "wall_seconds": 300,
}


class ContextualPilotSelectionTests(unittest.TestCase):
    def test_predeclared_slice_keeps_exact_honest_malicious_pair(self):
        cells = matrix(
            "a" * 64,
            "workspace-user_task_26",
            repeats=1,
            mode="live_diagnostic",
            budget=PILOT_BUDGET,
            topologies=["H_E"],
            levels=["high"],
            regimes=["honest", "malicious"],
        )
        self.assertEqual(len(cells), 2)
        self.assertEqual({cell["regime"] for cell in cells}, {"honest", "malicious"})
        self.assertEqual({cell["topology"] for cell in cells}, {"H_E"})
        self.assertEqual({cell["level"] for cell in cells}, {"high"})
        self.assertTrue(all(cell["budget"] == PILOT_BUDGET for cell in cells))

    def test_invalid_or_duplicate_slice_values_are_rejected(self):
        options = {
            "repeats": 1,
            "topologies": ["H_E"],
            "levels": ["high"],
            "regimes": ["honest", "malicious"],
        }
        for field, value in (
            ("topologies", []),
            ("topologies", ["H_E", "H_E"]),
            ("levels", ["unknown"]),
            ("regimes", ["attack"]),
        ):
            changed = dict(options)
            changed[field] = value
            with self.subTest(field=field, value=value):
                with self.assertRaises(ValueError):
                    matrix("a" * 64, "task", **changed)


if __name__ == "__main__":
    unittest.main()

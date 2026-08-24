from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from agentmembrane.parallel_run_v3a import BatchResult, _atomic_json, _sum_usage


class ParallelV3ATest(unittest.TestCase):
    def test_usage_is_aggregated_across_workers(self) -> None:
        first = BatchResult(1, 5, [], {}, {}, {"new_calls": 3, "cache_hits": 4, "total_tokens": 100})
        second = BatchResult(2, 5, [], {}, {}, {"new_calls": 2, "cache_hits": 5, "total_tokens": 60})
        totals = _sum_usage([first, second])
        self.assertEqual(totals["new_calls"], 5)
        self.assertEqual(totals["cache_hits"], 9)
        self.assertEqual(totals["total_tokens"], 160)

    def test_progress_write_is_atomic_and_readable(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "progress.json"
            _atomic_json(path, {"completed_examples": 10, "parallel_workers": 4})
            self.assertIn('"parallel_workers": 4', path.read_text(encoding="utf-8"))
            self.assertFalse(path.with_suffix(".json.tmp").exists())


if __name__ == "__main__":
    unittest.main()

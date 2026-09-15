"""Report artifact codec tests: no workflow execution or model calls."""
from __future__ import annotations

import gzip
import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from agentmembrane.host_v2.rq1_collab_v1.audit import canonical
from agentmembrane.host_v2.rq1_collab_v6 import report_codec as codec


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class ReportCodecTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="rq1-report-codec-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.report = {"episode_id": "w35", "outcomes": {"success": True},
                       "text": "中文", "events": list(range(50))}

    def _new(self):
        status = codec.write_report(self.root, self.report)
        return status, self.root / codec.REPORT_GZIP

    def _legacy(self):
        raw = canonical(self.report) + b"\n"
        (self.root / codec.REPORT_JSON).write_bytes(raw)
        return {"report_sha256": sha(raw)}

    def test_deterministic_canonical_gzip_and_status_hashes(self):
        status, path = self._new()
        encoded = path.read_bytes()
        decoded = canonical(self.report) + b"\n"
        self.assertEqual(status, {
            "report_encoding": "gzip", "report_sha256": sha(encoded),
            "report_decoded_sha256": sha(decoded), "report_bytes": len(encoded),
            "report_decoded_bytes": len(decoded)})
        self.assertEqual(encoded[4:8], b"\0\0\0\0")
        self.assertEqual(gzip.decompress(encoded), decoded)
        self.assertEqual(codec.read_report(self.root, status), self.report)
        with tempfile.TemporaryDirectory() as other:
            codec.write_report(other, self.report)
            self.assertEqual((Path(other) / codec.REPORT_GZIP).read_bytes(), encoded)

    def test_atomic_create_never_overwrites_or_leaves_temporary_file(self):
        status, path = self._new()
        before = path.read_bytes()
        with self.assertRaises(FileExistsError):
            codec.write_report(self.root, {"changed": True})
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual(codec.read_report(self.root, status), self.report)
        self.assertFalse(list(self.root.glob(".*.tmp")))

    def test_legacy_read_and_hash_check(self):
        status = self._legacy()
        self.assertEqual(codec.read_report(self.root, status), self.report)
        (self.root / codec.REPORT_JSON).write_bytes(b"{}\n")
        with self.assertRaisesRegex(ValueError, "report_sha256_mismatch"):
            codec.read_report(self.root, status)

    def test_ambiguous_dual_path_and_wrong_encoding_path_rejected(self):
        status, path = self._new()
        (self.root / codec.REPORT_JSON).write_bytes(b"{}\n")
        with self.assertRaisesRegex(ValueError, "ambiguous_dual_report_artifacts"):
            codec.read_report(self.root, status)
        with self.assertRaises(FileExistsError):
            codec.write_report(self.root, self.report)
        path.unlink()
        with self.assertRaisesRegex(ValueError, "report_encoding_path_mismatch"):
            codec.read_report(self.root, status)

    def test_symlinks_forbidden_including_broken_and_unselected(self):
        status, path = self._new()
        os.symlink(path, self.root / codec.REPORT_JSON)
        with self.assertRaisesRegex(ValueError, "report_symlink_forbidden"):
            codec.read_report(self.root, status)
        (self.root / codec.REPORT_JSON).unlink()
        path.unlink()
        os.symlink(self.root / "missing", path)
        with self.assertRaisesRegex(ValueError, "report_symlink_forbidden"):
            codec.read_report(self.root, status)

    def test_tampering_and_decoded_hash_mismatch_rejected(self):
        status, path = self._new()
        encoded = bytearray(path.read_bytes())
        encoded[12] ^= 1
        path.write_bytes(encoded)
        with self.assertRaises(ValueError):
            codec.read_report(self.root, status)
        path.unlink()
        status, path = self._new()
        with self.assertRaisesRegex(ValueError, "report_decoded_sha256_mismatch"):
            codec.read_report(self.root, {**status, "report_decoded_sha256": "0" * 64})

    def test_truncated_trailing_and_concatenated_gzip_rejected_even_if_rehashed(self):
        status, path = self._new()
        original = path.read_bytes()
        for replacement, expected in (
            (original[:-4], "truncated_gzip_report"),
            (original + b"junk", "trailing_gzip_data_forbidden"),
            (original + original, "trailing_gzip_data_forbidden"),
        ):
            with self.subTest(expected=expected):
                path.write_bytes(replacement)
                rehashed = {**status, "report_sha256": sha(replacement),
                            "report_bytes": len(replacement)}
                with self.assertRaisesRegex(ValueError, expected):
                    codec.read_report(self.root, rehashed)
        path.write_bytes(original)
        self.assertEqual(codec.read_report(self.root, status), self.report)

    def test_bounded_decompression_detects_bomb_before_hash_comparison(self):
        status, path = self._new()
        replacement = gzip.compress(b"x" * 128, mtime=0)
        path.write_bytes(replacement)
        forged = {**status, "report_sha256": sha(replacement),
                  "report_bytes": len(replacement), "report_decoded_bytes": 64}
        with patch.object(codec, "MAX_REPORT_BYTES", 64):
            with self.assertRaisesRegex(ValueError, "report_decoded_size_limit_exceeded"):
                codec.read_report(self.root, forged)

    def test_legacy_size_cap_and_incomplete_metadata(self):
        status = self._legacy()
        with patch.object(codec, "MAX_REPORT_BYTES", 64):
            with self.assertRaisesRegex(ValueError, "report_decoded_size_limit_exceeded"):
                codec.read_report(self.root, status)
        with self.assertRaisesRegex(ValueError, "incomplete_report_encoding_metadata"):
            codec.read_report(self.root, {**status, "report_decoded_sha256": "0" * 64})
        with self.assertRaisesRegex(ValueError, "invalid_report_hash_metadata"):
            codec.read_report(self.root, {**status, "report_sha256": "bad"})
        with self.assertRaisesRegex(ValueError, "unsupported_report_encoding"):
            codec.read_report(self.root, {**status, "report_encoding": None})

    def test_oversized_new_report_leaves_no_artifact(self):
        with patch.object(codec, "MAX_REPORT_BYTES", 64):
            with self.assertRaisesRegex(ValueError, "report_decoded_size_limit_exceeded"):
                codec.write_report(self.root, self.report)
        self.assertFalse(list(self.root.iterdir()))


if __name__ == "__main__":
    unittest.main()

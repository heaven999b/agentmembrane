from __future__ import annotations

import json
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from tools import audit_public_repo as audit


class PublicRepositoryAuditTests(unittest.TestCase):
    def run_isolated(self, root: Path, files: list[Path], **overrides: object) -> tuple[int, dict]:
        stream = StringIO()
        common = {
            "ROOT": root,
            "tracked_files": lambda: files,
            "validate_weekly_structure": lambda errors: [],
            "validate_markdown_links": lambda tracked, errors: None,
        }
        common.update(overrides)
        with patch.multiple(audit, **common), redirect_stdout(stream):
            status = audit.main()
        return status, json.loads(stream.getvalue())

    def test_unreviewed_binary_and_non_utf8_text_fail_closed(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "opaque.bin"
            binary.write_bytes(b"\x00\xff")
            text = root / "invalid.md"
            text.write_bytes(b"\xff")
            status, result = self.run_isolated(root, [binary, text])
        self.assertEqual(status, 1)
        self.assertIn("unreviewed tracked file type: opaque.bin", result["errors"])
        self.assertIn(
            "tracked file is not UTF-8 text and is not binary-allowlisted: invalid.md",
            result["errors"],
        )

    def test_private_route_metadata_and_account_label_fail_closed(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            metadata = root / "provider-route.yaml"
            metadata.write_text("kind: fixture\n", encoding="utf-8")
            label = root / "fixture.txt"
            label.write_text("account: " + "sub" + "37\n", encoding="utf-8")
            status, result = self.run_isolated(root, [metadata, label])
        self.assertEqual(status, 1)
        self.assertIn(
            "private route/account metadata filename is tracked: provider-route.yaml",
            result["errors"],
        )
        self.assertIn("account_specific_label in fixture.txt", result["errors"])

    def test_reviewed_binary_requires_exact_repository_relative_allowlist(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "needed.bin"
            binary.write_bytes(b"\x00\xff")
            status, result = self.run_isolated(
                root,
                [binary],
                ALLOWED_BINARY_FILES=frozenset({"needed.bin"}),
            )
        self.assertEqual(status, 0)
        self.assertEqual(result["errors"], [])


if __name__ == "__main__":
    unittest.main()

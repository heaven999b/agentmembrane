from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from .schema import TaskEpisode


_DOCUMENT_ID_RE = re.compile(
    r"(?:contractnli[-:])?(train|dev|test)[-:]doc(\d+)", re.IGNORECASE
)
_TEXT_SUFFIXES = {".json", ".jsonl", ".md", ".txt"}


@dataclass(frozen=True)
class ConsumedDocumentInventory:
    documents: dict[str, tuple[str, ...]]
    scanned_path_n: int
    matched_source_n: int

    @property
    def document_n(self) -> int:
        return sum(len(values) for values in self.documents.values())

    def contains(self, *, split: str, document_id: str) -> bool:
        return str(document_id) in self.documents.get(split.lower(), ())

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": "rq1-legacy-consumed-documents-v1",
            "purpose": "exclude all documents exposed during pre-RQ1 development",
            "documents": {
                split: list(values) for split, values in sorted(self.documents.items())
            },
            "document_n": self.document_n,
            "scanned_path_n": self.scanned_path_n,
            "matched_source_n": self.matched_source_n,
        }


def _matches(value: str) -> set[tuple[str, str]]:
    return {
        (match.group(1).lower(), str(int(match.group(2))))
        for match in _DOCUMENT_ID_RE.finditer(value)
    }


def discover_consumed_documents(
    roots: Iterable[Path],
) -> ConsumedDocumentInventory:
    """Find ContractNLI documents already visible in legacy development assets.

    Paths are always inspected.  Contents are read only for manifest-like files,
    avoiding a costly and scientifically unnecessary scan of every cached model
    response.  Materialized block/cache filenames already contain their split
    and document IDs.
    """

    found: dict[str, set[str]] = {"train": set(), "dev": set(), "test": set()}
    scanned_path_n = 0
    matched_sources: set[str] = set()
    for root_value in roots:
        root = Path(root_value)
        if not root.exists():
            continue
        paths = (root,) if root.is_file() else root.rglob("*")
        for path in paths:
            if not path.is_file():
                continue
            scanned_path_n += 1
            path_matches = _matches(str(path))
            if path_matches:
                matched_sources.add(str(path))
                for split, document_id in path_matches:
                    found.setdefault(split, set()).add(document_id)
            is_manifest_like = "manifest" in path.name.lower() or any(
                "manifest" in part.lower() for part in path.parts
            )
            if path.suffix.lower() not in _TEXT_SUFFIXES or not is_manifest_like:
                continue
            try:
                contents = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue
            content_matches = _matches(contents)
            if content_matches:
                matched_sources.add(str(path))
                for split, document_id in content_matches:
                    found.setdefault(split, set()).add(document_id)
    documents = {
        split: tuple(sorted(values, key=int))
        for split, values in found.items()
        if values
    }
    return ConsumedDocumentInventory(
        documents=documents,
        scanned_path_n=scanned_path_n,
        matched_source_n=len(matched_sources),
    )


def exclude_consumed_episodes(
    episodes: Iterable[TaskEpisode],
    inventory: ConsumedDocumentInventory,
) -> tuple[TaskEpisode, ...]:
    return tuple(
        episode
        for episode in episodes
        if not inventory.contains(split=episode.split, document_id=episode.document_id)
    )

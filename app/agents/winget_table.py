"""Locale-independent parser for winget's fixed-width console tables.

Both the asset inventory and the upgrade scan parse the same table. They
used to do it separately, and both keyed off the ENGLISH header words
("Name", "Id", "Version", "Source"). winget localizes those headers to the
Windows display language, so on an Arabic (or German, or any non-English)
install the header lookup failed, the parser returned [], and the caller
reported "no software found" / "no updates available" — a silent all-clear
on a machine that was never actually examined. Since this app's own UI is
Arabic-first, that was the expected deployment, not an edge case.

This parser instead uses the table's STRUCTURE, which is locale-stable:

  - the header is the line immediately above a run-of-dashes separator
  - columns start where a non-space follows two-or-more spaces
  - winget's column ORDER is fixed regardless of language:
        Name, Id, Version, [Available], Source
    (the Available column is present only in upgrade-style listings)

Callers get English keys back on every locale.
"""
import re

# winget pads columns with spaces; two or more marks a boundary.
_COL_SPLIT_RE = re.compile(r"\s{2,}")
_MIN_SEPARATOR_LEN = 10


def _find_header_index(lines: list[str]) -> int | None:
    """Index of the header row: the line directly above the dashes rule."""
    for i, line in enumerate(lines):
        stripped = line.strip()
        if len(stripped) >= _MIN_SEPARATOR_LEN and set(stripped) == {"-"}:
            return i - 1 if i > 0 else None
    return None


def _column_starts(header: str) -> list[int]:
    """Character offset where each column's text begins."""
    starts, pos = [], 0
    for chunk in _COL_SPLIT_RE.split(header.rstrip()):
        if not chunk:
            continue
        idx = header.find(chunk, pos)
        if idx < 0:
            continue
        starts.append(idx)
        pos = idx + len(chunk)
    return starts


def parse(raw: str) -> list[dict]:
    """Rows as dicts with stable English keys, on any Windows display language.

    Returns [] only when the output genuinely has no table (see
    looks_like_table() to tell "no table" apart from "empty table").
    """
    lines = [line for line in raw.splitlines() if line.strip()]
    header_index = _find_header_index(lines)
    if header_index is None:
        return []

    starts = _column_starts(lines[header_index])
    if len(starts) < 2:  # need at least Name + Id to be useful
        return []

    # Positional mapping — winget's column order does not change with locale.
    # 5 columns means an "Available" column sits between Version and Source.
    if len(starts) >= 5:
        keys = ["Name", "Id", "Version", "Available", "Source"]
    elif len(starts) == 4:
        keys = ["Name", "Id", "Version", "Source"]
    elif len(starts) == 3:
        keys = ["Name", "Id", "Version"]
    else:
        keys = ["Name", "Id"]
    keys = keys[: len(starts)]

    rows = []
    for line in lines[header_index + 2:]:  # skip header + dashes rule
        stripped = line.strip()
        if not stripped or set(stripped) == {"-"}:
            continue
        fields = {}
        for i, key in enumerate(keys):
            start = starts[i]
            end = starts[i + 1] if i + 1 < len(starts) else len(line)
            fields[key] = line[start:end].strip()
        if fields.get("Name"):
            rows.append(fields)
    return rows


def looks_like_table(raw: str) -> bool:
    """True if winget emitted something table-shaped.

    Lets callers distinguish 'winget ran and this machine really has nothing'
    from 'winget printed an error / a format we cannot read' — the second
    must never be reported to the user as a clean result.
    """
    lines = [line for line in raw.splitlines() if line.strip()]
    return _find_header_index(lines) is not None

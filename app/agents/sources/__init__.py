"""Update sources — one module per catalog that can answer
"is there a newer version of this installed program?".

Why this layer exists
---------------------
`winget upgrade` only considers packages that carry a catalog Source. On a
real machine that was 67 of 183 installed programs; the rest were invisible
to update detection, which is what "some programs have an update but never
show up in the list" actually was.

Closing that gap means consulting more than one catalog, and each catalog
has its own quirks that must not leak into the caller:

  - the winget catalog exposes real version numbers, so it can both DETECT
    and RESOLVE an update;
  - the Microsoft Store exposes package identity but **never a version
    number** (`winget search --source msstore` returns `Version: Unknown`),
    so it can only EXPLAIN a program as Store-managed — it can never say
    whether it is out of date.

Rather than special-case that inside one growing function, every source
implements the same small contract and declares its own capability.

The contract
------------
Each source module exposes:

    NAME            str   — stable identifier used in logs and the UI
    CAN_COMPARE     bool  — True if the source exposes comparable versions
    lookup(name)    -> Match | None

`lookup` is given an installed program's display name and returns a `Match`
if this catalog recognises it, else None. It must never raise: a source that
is unavailable (tool not installed, offline, timed out) returns None so the
others still run.
"""
from dataclasses import dataclass


@dataclass(frozen=True)
class Match:
    """One catalog's answer about one installed program."""
    source: str          # which catalog answered
    package_id: str      # that catalog's identifier for the program
    version: str | None  # catalog version, or None when it exposes none
    ambiguous: bool = False   # several packages matched — caller must not guess


def available_sources() -> list:
    """Sources to consult, in priority order.

    Version-capable sources come first so a program that a real catalog can
    resolve is never merely "explained" by one that cannot.
    """
    from agents.sources import winget_catalog, msstore
    return [winget_catalog, msstore]

#!/usr/bin/env python3
"""Prose lint: the parts of the writing rules a machine can check.

`CONTRIBUTING.md` states the rules. This enforces three of them over the tree,
and `make verify` runs it.

Checks:
  every tracked text file   no em-dash, and no escape that renders one
  every tracked text file   a label in a code span (`[measured]`) is from the
                            closed set; in markdown, a bare one is too
  tracked markdown          every prose allowlist entry in the disclosure guard
                            is a host some document needs

Why each one exists:

- By 0.15.1 the tree held 28 em-dashes in four files, one of them in the HTML
  renderer, in the heading of every sector section a client receives. Removing
  them took one pass; keeping the count at zero takes a gate. Escapes count
  because the generated reports are not tracked: a renderer that writes the
  dash as an escape puts one in front of the client without the character
  ever appearing in the tree.
- Until 0.15.3 three documents stated the provenance labels differently, and
  the README and `docs/MECHANISMS.md` each listed a different four of the five
  the code emits. A label outside the set is drift or a new kind of evidence,
  and both need a decision rather than a new word. The set is the one in the
  README's Provenance convention, and a test holds the two together.
- An allowlist entry no document needs admits a name for nobody and reads as
  coverage it does not have. Two infrastructure hosts were unused from sprint
  10, when they were added, to 0.15.4.

What it does not check: whether a claim carries a label at all, whether the
label is the right one, or whether a number came from a command. Those stay
with review.

Exit code 1 on any violation.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ananke.collectors.disclosure import (  # noqa: E402
    _PROSE_CITATIONS,
    _PROSE_INFRASTRUCTURE,
    _UNTRACKED_SCAN_SKIP,
    CODE_FENCE_RE,
    CODE_SPAN_RE,
    HOSTNAME_RE,
)

# The closed set, as the README's Provenance convention states it. Built from
# three groups because the README describes three kinds of thing: evidence,
# planning shorthand, and the state of a piece of work.
PROVENANCE = ("measured", "reported", "inference", "assumption", "speculation")
PLANNING = ("estimate", "not found")
STATUS = ("verify", "todo", "done", "deferred", "unknown")
VOCABULARY = frozenset(PROVENANCE + PLANNING + STATUS)

# Built from code points and fragments, so this file passes its own check.
EM_DASH = chr(0x2014)
EM_DASH_ESCAPE_RE = re.compile(
    "|".join(re.escape(s) for s in (
        "\\" + "u2014", "\\" + "U0000" + "2014", "\\" + "N{EM DASH}",
        "&" + "mdash;", "&#" + "8212;", "&#x" + "2014;",
    )),
    re.IGNORECASE,
)

# A label as a whole code span, `[measured]` or `[measured, verified 2026-08-06]`.
# The first token is the label; what follows the comma is free text.
SPAN_LABEL_RE = re.compile(r"`\[([A-Za-z][A-Za-z ]*?)\s*(?:,[^`\]\n]*)?\]`")
# The same outside code. Not a link, an image, a reference or a footnote.
BARE_LABEL_RE = re.compile(
    r"(?<![\]!\\\w])\[([A-Za-z][A-Za-z ]*?)\s*(?:,[^\]\n]*)?\](?![(\[:])")
CHECKBOX_RE = re.compile(r"^(\s*(?:[-*+]|\d+[.)])\s+)\[[ xX~]\]", re.MULTILINE)
HEADING_RE = re.compile(r"^#.*$", re.MULTILINE)


def tracked_files(root: Path = ROOT) -> list[str]:
    """Paths git tracks, staged ones included, relative to the root.

    A checkout without `.git` falls back to a walk of the tree that skips the
    directories the disclosure guard never derives names from. An empty answer
    is returned as empty, and `main` fails on it.
    """
    try:
        out = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-z"],
            capture_output=True, text=True, timeout=15, check=True,
        ).stdout
        paths = sorted(p for p in out.split("\0") if p)
    except (OSError, subprocess.SubprocessError):
        paths = []
    if paths:
        return paths
    return sorted(
        p.relative_to(root).as_posix() for p in root.rglob("*")
        if p.is_file() and not _UNTRACKED_SCAN_SKIP & set(p.relative_to(root).parts[:-1])
    )


def read_texts(paths: list[str], root: Path = ROOT) -> dict[str, str]:
    """UTF-8 text by path. Binary files and files missing on disk are left out."""
    texts = {}
    for rel in paths:
        try:
            texts[rel] = (root / rel).read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
    return texts


def _line(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _blank(match: re.Match[str]) -> str:
    """Replace code with spaces, keeping its line breaks so line numbers hold."""
    return re.sub(r"[^\n]", " ", match.group(0))


def em_dash_failures(texts: dict[str, str]) -> list[str]:
    problems = []
    for rel, text in sorted(texts.items()):
        for i, line in enumerate(text.splitlines(), start=1):
            if EM_DASH in line:
                problems.append(f"{rel}:{i}: em-dash")
            for match in EM_DASH_ESCAPE_RE.finditer(line):
                problems.append(f"{rel}:{i}: {match.group(0)!r} renders an em-dash")
    return problems


def label_failures(texts: dict[str, str]) -> list[str]:
    problems = []
    for rel, text in sorted(texts.items()):
        for match in SPAN_LABEL_RE.finditer(text):
            if match.group(1) not in VOCABULARY:
                problems.append(
                    f"{rel}:{_line(text, match.start())}: {match.group(0)} "
                    "is not a label from the closed set")
        if not rel.endswith(".md"):
            continue
        prose = CODE_SPAN_RE.sub(_blank, CODE_FENCE_RE.sub(_blank, text))
        prose = HEADING_RE.sub(_blank, CHECKBOX_RE.sub(r"\1   ", prose))
        for match in BARE_LABEL_RE.finditer(prose):
            if match.group(1) not in VOCABULARY:
                problems.append(
                    f"{rel}:{_line(prose, match.start())}: {match.group(0)} "
                    "is not a label from the closed set")
    return problems


def prose_tokens(markdown: dict[str, str]) -> set[str]:
    """What the prose scan sees: host-shaped tokens outside code."""
    tokens: set[str] = set()
    for text in markdown.values():
        stripped = CODE_SPAN_RE.sub(" ", CODE_FENCE_RE.sub(" ", text))
        tokens.update(m.lower() for m in HOSTNAME_RE.findall(stripped))
    return tokens


def allowlist_failures(
    markdown: dict[str, str],
    citations: frozenset[str] = _PROSE_CITATIONS,
    infrastructure: frozenset[str] = _PROSE_INFRASTRUCTURE,
) -> list[str]:
    """An entry is needed only if the prose scan would otherwise reject a token
    a tracked document contains. A host named only inside a code span is never
    scanned, so it does not keep its entry alive."""
    seen = prose_tokens(markdown)
    problems = []
    for name, entries in (("_PROSE_CITATIONS", citations),
                          ("_PROSE_INFRASTRUCTURE", infrastructure)):
        for entry in sorted(entries - seen):
            problems.append(
                f"{name}: {entry} appears in no tracked document; remove the entry")
    return problems


def main() -> int:
    texts = read_texts(tracked_files())
    markdown = {rel: text for rel, text in texts.items() if rel.endswith(".md")}
    if not texts or not markdown:
        print("FAIL  no tracked files to check; an empty check is not a pass")
        return 1

    checks = (
        (em_dash_failures(texts), f"no em-dash in {len(texts)} tracked text files"),
        (label_failures(texts), "every bracketed label is from the closed set"),
        (allowlist_failures(markdown),
         f"{len(_PROSE_CITATIONS) + len(_PROSE_INFRASTRUCTURE)} prose allowlist "
         f"entries, each needed by one of {len(markdown)} documents"),
    )
    problems = []
    for found, ok in checks:
        if found:
            problems += found
        else:
            print(f"OK    {ok}")
    for p in problems:
        print(f"FAIL  {p}")
    print(f"{len(problems)} violation(s)")
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())

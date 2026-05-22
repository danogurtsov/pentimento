"""
Structured `Finding` parsing — a prerequisite for the Phase 6 verification stage. A
breadth-pass/scout/deep response's `### [F-N] Title` blocks (the exact format
`prompts.build_breadth_pass_prompt` asks for) only exist as unstructured markdown inside
`raw_response` — nothing downstream can act on a SPECIFIC finding without re-parsing it
first. Pure text/regex, no LLM, no I/O.

Deliberately tolerant of real model output, not just the literal spec: verified against a
real live EulerEarn output (`--route` run) where the response used
`**Severity: Medium** | **Confidence: 90%**` on one line and `**Location:**` on the next —
bold emphasis and field grouping the prompt's own literal template doesn't show, but real
models produce anyway. `_extract_field` strips markdown emphasis first and finds the next
KNOWN label anywhere ahead (same line or a later one) rather than assuming one field per
line, so both shapes parse the same way.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

_HEADER_RE = re.compile(r"^###\s*\[F-(\d+)\]\s*(.+?)\s*$", re.MULTILINE)
_FIELD_LABELS = ("Severity", "Confidence", "Location", "Root Cause", "Exploit", "Impact", "Fix", "PoC")
# A real model sometimes annotates a label with a trailing parenthetical before the colon
# (`Exploit (5 steps):`) - `(?:\s*\([^)]*\))?` tolerates that without treating the annotation
# itself as part of either the label match or the captured value.
_LABEL_ALTERNATION = "|".join(rf"{re.escape(label)}(?:\s*\([^)]*\))?" for label in _FIELD_LABELS)


@dataclass(frozen=True)
class Finding:
    id: str
    title: str
    severity: str
    confidence: int
    location: str
    root_cause: str
    exploit: str
    impact: str
    fix: str
    poc: str | None


def _strip_markdown_emphasis(text: str) -> str:
    return text.replace("**", "")


def _extract_field(block: str, label: str) -> str | None:
    """The value after `label:` (tolerating a trailing parenthetical annotation before the
    colon, e.g. `Exploit (5 steps):` — a real shape seen in live output, see module
    docstring), up to whichever KNOWN label occurs next — anywhere ahead, same line or a
    later one, never assuming a fixed one-field-per-line layout."""
    label_pattern = rf"{re.escape(label)}(?:\s*\([^)]*\))?"
    pattern = re.compile(rf"{label_pattern}\s*:\s*(.+?)(?=(?:{_LABEL_ALTERNATION})\s*:|\Z)", re.DOTALL)
    match = pattern.search(block)
    if not match:
        return None
    value = match.group(1).strip().rstrip("|").strip()
    return value or None


def parse_findings(raw_response: str) -> list[Finding]:
    """Every `### [F-N] Title` block in a raw breadth-pass/scout/deep response. A response
    with no finding headers at all (a clean pass) returns an empty list, not an error."""
    headers = list(_HEADER_RE.finditer(raw_response))
    findings: list[Finding] = []

    for i, header in enumerate(headers):
        start = header.end()
        end = headers[i + 1].start() if i + 1 < len(headers) else len(raw_response)
        block = _strip_markdown_emphasis(raw_response[start:end])

        confidence_raw = _extract_field(block, "Confidence") or ""
        confidence_match = re.search(r"\d+", confidence_raw)

        findings.append(
            Finding(
                id=f"F-{header.group(1)}",
                title=header.group(2).strip(),
                severity=(_extract_field(block, "Severity") or "Unknown").strip(),
                confidence=int(confidence_match.group()) if confidence_match else 0,
                location=_extract_field(block, "Location") or "",
                root_cause=_extract_field(block, "Root Cause") or "",
                exploit=_extract_field(block, "Exploit") or "",
                impact=_extract_field(block, "Impact") or "",
                fix=_extract_field(block, "Fix") or "",
                poc=_extract_field(block, "PoC"),
            )
        )

    return findings

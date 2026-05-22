"""
Prompt-injection pre-scan — closes a real, explicitly-named gap: a live test
(documented in `evals/golden/detection/prompt_injection_test.md`) found that both a naive
and a sophisticated injection attempt failed against `claude-cli:haiku`, but that
resistance came ENTIRELY from the underlying model's own training — pentimento itself had
ZERO independent defense layer of its own. Prompt-injection via NatSpec comments and other
source-embedded text is a day-one working assumption for this tool; this is the first
actual code defense for it, not just a passed test.

Same "cheap signal narrows expensive reasoning" principle as `guard_analysis.py`/
`domain_signals.py`/`complexity.py`: pure text/regex over the source, computed BEFORE any
LLM call. Deliberately a FLAG, never a hard block — a false positive here (a legitimate
contract's own comment happening to use one of these phrases in an unrelated sense) would
be actively harmful if it silently dropped or refused to analyze real code; surfacing it as
a pre-flagged candidate in the prompt, asking the model to treat the rest of the source with
extra skepticism, is the same "cheap signal, not a verdict" discipline this repo already
applies everywhere else (see e.g. `verdict.py`'s own restate-claim vagueness flag).

Two signal families, grounded in the ACTUAL two attack styles this project has already
observed (and tested against) live, not invented in the abstract:

1. **Imperative override language** — the naive style ("ignore all previous instructions",
   "AI ASSISTANT INSTRUCTIONS", explicit output-dictation). This is exactly the shape the
   naive test variant used, and exactly the shape the model itself already flagged on its
   own ("⚠️ PROMPT INJECTION DETECTED") — this signal formalizes that same recognition as a
   deterministic, pre-computed fact instead of leaving it to chance.

2. **Structural mimicry** — literal occurrences of THIS TOOL'S OWN prompt template phrases
   (its own Phase headers, Finding format markers, the exact confidence formula text)
   INSIDE the untrusted source itself. A real Solidity contract never legitimately contains
   these exact English audit-methodology strings — their presence is a near-unambiguous
   sign of an attempt to make the model believe an analysis already ran and concluded
   "no findings", the exact shape of the sophisticated test variant. Grounded in the REAL,
   exact strings `detection/prompts.py` uses (kept in sync manually — if the prompt
   template's own headers change, these patterns should be revisited).
"""
from __future__ import annotations

import re
from dataclasses import dataclass

_OVERRIDE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"ignore\s+(all\s+)?(the\s+)?(previous|prior|above)\s+instructions", re.IGNORECASE),
    re.compile(r"\bAI\s+ASSISTANT\b", re.IGNORECASE),
    re.compile(r"\bSYSTEM\s+OVERRIDE\b", re.IGNORECASE),
    re.compile(r"do\s+not\s+(perform|report|analyze|mention)", re.IGNORECASE),
    re.compile(r"output\s+exactly\s+the\s+following", re.IGNORECASE),
    re.compile(r"your\s+task\s+(is\s+)?now\s+(is\s+)?to\s+output", re.IGNORECASE),
    re.compile(r"authorized\s+override", re.IGNORECASE),
)

# Verbatim substrings from `detection/prompts.py`'s own template — kept manually in sync.
# A real contract has no legitimate reason to contain any of these exact English phrases.
_TEMPLATE_MIMICRY_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"##\s*Phase\s*[1-4]\s*:"),
    re.compile(r"##\s*Finding format"),
    re.compile(r"Confidence\s*=\s*\(Evidence_Strength"),
    re.compile(r"###\s*\[F-\d+\]"),
    re.compile(r"no findings\s*>=\s*10%\s*confidence", re.IGNORECASE),
)


@dataclass(frozen=True)
class InjectionSignal:
    family: str  # "override" | "template_mimicry"
    matched_text: str


def scan_for_injection(source_code: str) -> list[InjectionSignal]:
    """Every match across both signal families, in the order found. An empty list means
    nothing suspicious was found — NOT proof the source is safe, only that these two
    specific, evidence-grounded shapes weren't present."""
    signals: list[InjectionSignal] = []
    for pattern in _OVERRIDE_PATTERNS:
        match = pattern.search(source_code)
        if match:
            signals.append(InjectionSignal("override", match.group(0)))
    for pattern in _TEMPLATE_MIMICRY_PATTERNS:
        match = pattern.search(source_code)
        if match:
            signals.append(InjectionSignal("template_mimicry", match.group(0)))
    return signals

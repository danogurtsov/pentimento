"""
Slices a single contract/interface/library declaration out of a multi-declaration file —
pure core (no I/O).

Found the hard way, not anticipated: every fixture built through Phase 1-2 was one
contract per file, so `source_text = whole file` silently happened to equal "this
contract's own text" and nothing exposed the gap. The first real external repo tried
(DeFiHackLabs' Euler_exp.sol) declares SIX contracts/interfaces in one file — without this
scoping, every domain detector (proxy markers, factory `new X(...)`, singleton
create-function) was searching the WHOLE FILE and attributing one contract's findings to
its unrelated siblings (interfaces literally can't contain `new X(...)` at all, yet were
being flagged as factories because a sibling contract's code was in the same file).
"""
from __future__ import annotations

import re

_DECL_RE_TEMPLATE = r"\b(?:contract|interface|library|abstract\s+contract)\s+{name}\b[^{{]*\{{"


def extract_contract_source(full_source: str, contract_name: str) -> str:
    """The brace-matched body of exactly ONE `contract`/`interface`/`library` declaration
    (including its own header/inheritance clause). Falls back to the full source if the
    declaration can't be found (shouldn't happen for a name solc itself reported) — never
    silently returns an empty scope, which would just hide findings instead of fixing
    anything.

    Same known limitation as the function-body brace-matchers elsewhere in this package:
    a `{`/`}` inside a string literal or comment would throw off the depth count. A real
    parser (solc's own AST, already reachable via the adapter) is the honest upgrade path
    if this ever proves too fragile on messier real-world code — not needed yet.
    """
    pattern = re.compile(_DECL_RE_TEMPLATE.format(name=re.escape(contract_name)))
    match = pattern.search(full_source)
    if not match:
        return full_source

    start = match.start()
    depth = 0
    i = match.end() - 1  # the opening brace itself
    while i < len(full_source):
        if full_source[i] == "{":
            depth += 1
        elif full_source[i] == "}":
            depth -= 1
            if depth == 0:
                break
        i += 1
    return full_source[start : i + 1]

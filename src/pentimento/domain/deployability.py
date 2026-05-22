"""
Whether a compiled Solidity declaration is ever actually deployed on its own — pure core
(no I/O).

Found on a real repo (Tremolo/`realizedVolatility`), not anticipated from any fixture we
wrote ourselves: solc's compiled-contract output has an ABI (and, if asked, a `bin`) entry
for every `interface`/`library`/`abstract contract` declaration too, not just concrete
deployable contracts. Before this, every one of those silently became its own top-level CDV
unit — four bare interfaces (`IChainlinkAggregator`, `IPriceObserver`,
`IUniswapV3PoolOracle`, `IVarianceMarket`) and an all-internal-function library
(`VarianceMath`) showed up as "units" in the manifest, directly contradicting the CDV
standard's own opening principle: "one unit = one
resolved, 'as-if-deployed' contract" — an interface is NEVER deployed (no
bytecode, no address, ever), and a library whose functions are all `internal` gets fully
inlined into its callers at compile time. Confirmed empirically, not assumed: compiling
Tremolo with `--combined-json abi,bin` showed `VarianceMath` and solady's own
`FixedPointMathLib` (also all-internal) get byte-identical placeholder bytecode regardless
of their actual function bodies — the standard "must be called via delegatecall, else
revert" stub every all-internal library gets, never real logic and never delegatecall'd, so
nothing ever actually runs it on chain. Checking the declaration keyword and function
visibility straight from source text (rather than asking solc for `bin` and inspecting
bytecode) keeps this consistent with the rest of `domain/` (pure, no extra solc CLI surface,
no solc-version/optimizer-setting dependence on what a "placeholder" looks like).
"""
from __future__ import annotations

import re

# `scoped_source` (see `source_scope.extract_contract_source`) always starts at the
# declaration's own keyword — `\b(?:contract|interface|library|abstract\s+contract)\s+name`
# — so anchoring at the start of the string reads it straight off, no re-searching needed.
_KIND_RE = re.compile(r"^(contract|interface|library|abstract\s+contract)\b")

# a function with no explicit visibility is invalid Solidity (post ~0.5), so this is enough
# to tell whether a library has ANY entry point that would need it deployed and
# delegatecall'd into, rather than fully inlined at every call site.
_EXTERNAL_OR_PUBLIC_FUNCTION_RE = re.compile(r"\bfunction\b[^;{}]*\b(?:external|public)\b")


def is_deployable(scoped_source: str) -> bool:
    """True if this declaration would ever have its own real, meaningful bytecode.

    `scoped_source` must already be sliced to just this one declaration — an unscoped,
    whole-file source would let a sibling declaration's `external`/`public` function leak
    into the library check below. Falls back to `True` (never filters) if the declaration
    keyword can't be found at the start of the given text — same "never silently hide
    findings" fallback philosophy as `source_scope.extract_contract_source`.
    """
    match = _KIND_RE.match(scoped_source)
    if not match:
        return True

    kind = re.sub(r"\s+", " ", match.group(1))
    if kind in ("interface", "abstract contract"):
        return False
    if kind == "library":
        return bool(_EXTERNAL_OR_PUBLIC_FUNCTION_RE.search(scoped_source))
    return True

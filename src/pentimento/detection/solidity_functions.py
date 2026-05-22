"""
Shared Solidity source-text parsing primitives for Phase 4's deterministic detectors
(`guard_analysis.py`, `state_invariants.py`) — pure text/regex, no AST, no LLM, no I/O,
consistent with the rest of this repo's structural detectors (`domain/factories.py`/
`singletons.py`/`proxies.py`).

Split out of `guard_analysis.py` once a second detector needed the exact same machinery:
finding state variables and function bodies correctly on REAL code took two real,
non-obvious bug fixes (see the functions' own docstrings below) — duplicating this into a
second module would risk reintroducing either bug independently instead of fixing it once,
centrally, for every detector built on top of it.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from pentimento.domain.source_scope import extract_contract_source

DECL_NAME_RE = re.compile(r"\b(?:contract|interface|library|abstract\s+contract)\s+(\w+)")

_FUNCTION_LIKE_RE = re.compile(r"^(function|constructor|modifier|fallback|receive)\b\s*(\w*)")
_SKIP_STARTS = ("struct ", "enum ", "event ", "error ", "using ", "import ", "interface ", "library ")


@dataclass(frozen=True)
class FunctionInfo:
    name: str
    signature: str  # everything from the `function`/`constructor`/... keyword up to the body's `{`
    body: str  # the `{...}` block itself, braces included


_SOLIDITY_SIG_KEYWORDS = {
    "external", "public", "internal", "private", "view", "pure", "payable",
    "virtual", "override", "returns", "constant", "immutable",
}
_PRIVILEGED_MODIFIER_RE = re.compile(r"only\w*|owner|admin|\brole\b", re.IGNORECASE)


def _param_list_end(signature: str, open_paren: int) -> int:
    """Index just past the `)` matching the `(` at `open_paren` (paren-depth-aware, so a
    struct/mapping type inside a parameter list doesn't confuse the scan)."""
    depth = 0
    for i in range(open_paren, len(signature)):
        if signature[i] == "(":
            depth += 1
        elif signature[i] == ")":
            depth -= 1
            if depth == 0:
                return i + 1
    return len(signature)


def extract_modifiers(f: FunctionInfo) -> set[str]:
    """Bare identifiers (with or without their own `(...)` args) appearing between a
    function's parameter list and its body — i.e. its modifier invocations. Also picks up
    a constructor's base-class constructor calls (`ERC20() Ownable(owner)`), which are
    syntactically identical — callers that care about the difference (guard_analysis.py)
    exclude constructors from consideration entirely rather than trying to tell them apart
    here, since telling a modifier from a base-constructor-call by name alone isn't
    reliable (would need the contract's own `is X, Y` inheritance list cross-referenced)."""
    open_paren = f.signature.find("(")
    if open_paren == -1:
        return set()
    after_params = f.signature[_param_list_end(f.signature, open_paren) :]
    after_params = re.sub(r"returns\s*\([^)]*\)", "", after_params)
    tokens = re.findall(r"[A-Za-z_]\w*", after_params)
    return {t for t in tokens if t not in _SOLIDITY_SIG_KEYWORDS}


def is_privileged(modifiers: set[str]) -> bool:
    """Whether a function's own modifier set looks access-control-gated (`onlyOwner`,
    `onlyAdmin`, a role-check, ...) — used by detectors that need to avoid comparing a
    privileged function's behavior against public functions' as if they were peers (see
    `guard_analysis.py`'s Privilege Overlay, ported from QuillShield's own semantic
    protocol)."""
    return bool(_PRIVILEGED_MODIFIER_RE.search(" ".join(modifiers)))


_EXTERNALLY_REACHABLE_RE = re.compile(r"\b(?:external|public)\b")


def is_externally_reachable(f: FunctionInfo) -> bool:
    """Whether a function is independently callable from outside the contract (`external`/
    `public`) as opposed to an `internal`/`private` helper only ever reached through some
    OTHER function's own entry point. Real false positive found running against real
    Tremolo/VarianceMarket.sol, not anticipated from any self-authored fixture: an internal
    `_pullCollateral()` helper was flagged by `guard_analysis.py` for lacking
    `nonReentrant`, which its actual public callers already enforce — an internal helper
    was being compared as a guard-consistency PEER against public entry points it isn't
    one of. Constructors are also never externally-reachable in this sense (matches
    `guard_analysis.py`'s pre-existing, separately-motivated constructor exclusion)."""
    return bool(_EXTERNALLY_REACHABLE_RE.search(f.signature))


def strip_leading_comments(text: str) -> str:
    """Real production code is full of NatSpec (`/// @notice ...`, `/// @inheritdoc ...`)
    and plain comments directly above nearly every function/state variable — found the hard
    way running against real EulerEarn.sol, not anticipated from any self-authored fixture
    (every fixture written before this was comment-free): an anchored `^function\\b` match
    against a raw top-level statement silently matched nothing at all on real code, since
    the statement actually starts with a comment, not the `function` keyword."""
    while True:
        stripped = text.lstrip()
        if stripped.startswith("//"):
            newline = stripped.find("\n")
            text = stripped[newline + 1 :] if newline != -1 else ""
        elif stripped.startswith("/*"):
            end = stripped.find("*/")
            text = stripped[end + 2 :] if end != -1 else ""
        else:
            return stripped


def _inner_body(contract_source: str) -> str:
    """Strips the `contract Foo is Bar {` header and the final `}` off an already-scoped
    single-contract declaration (see `source_scope.extract_contract_source`), leaving just
    what's directly inside — matches depth 0 in this substring to depth 1 in the contract."""
    start = contract_source.index("{")
    return contract_source[start + 1 : contract_source.rfind("}")]


def _top_level_statements(inner_body: str) -> list[str]:
    """Splits a contract's inner body into its own top-level items — each ending either at
    a top-level `;` (a simple declaration/directive) or a matched top-level `{...}` block
    (a function/constructor/modifier/struct/enum body). Local variables and nested blocks
    inside a function (depth 1+ within this substring) are never split out."""
    statements: list[str] = []
    depth = 0
    start = 0
    for i, c in enumerate(inner_body):
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                statements.append(inner_body[start : i + 1])
                start = i + 1
        elif c == ";" and depth == 0:
            statements.append(inner_body[start : i + 1])
            start = i + 1
    return statements


def _state_variable_name(declaration: str) -> str | None:
    """Real bug found running against real Tremolo/VarianceMarket.sol, not anticipated
    from any self-authored fixture (Solidity's named-mapping-parameter syntax, 0.8.18+,
    wasn't used in any fixture written before this): `mapping(uint256 seriesId => Series)
    internal _series;` — without the `(?!>)` below, `[^;]*` happily swallows `> Series)
    internal _series` as if `seriesId =` were a real initializer, so `re.search` returns
    its EARLIEST possible match (at `seriesId`) instead of the actual declared name
    (`_series`, at the very end). `(?!>)` rules out `=>` from ever starting the optional
    initializer group, forcing the match to fail there and continue to the real name."""
    stripped = declaration.strip()
    if not stripped or stripped.startswith(_SKIP_STARTS) or stripped.endswith("}"):
        return None
    match = re.search(r"([A-Za-z_]\w*)\s*(?:=(?!>)[^;]*)?;\s*$", stripped)
    return match.group(1) if match else None


def extract_state_variables_and_functions(contract_source: str) -> tuple[list[str], list[FunctionInfo]]:
    """`contract_source` must already be scoped to ONE contract declaration (see
    `source_scope.extract_contract_source`, or use `for_each_declaration` below to handle a
    raw, unscoped file) — an unscoped, whole-file source would mix unrelated sibling
    contracts' state variables and functions together."""
    inner = _inner_body(contract_source)
    state_vars: list[str] = []
    functions: list[FunctionInfo] = []

    for statement in _top_level_statements(inner):
        stripped = strip_leading_comments(statement)
        func_match = _FUNCTION_LIKE_RE.match(stripped)
        if func_match:
            kind, name = func_match.group(1), func_match.group(2)
            brace_idx = stripped.find("{")
            if brace_idx == -1:
                continue  # interface-style declaration (`function foo() external;`)
            functions.append(
                FunctionInfo(name=name or kind, signature=stripped[:brace_idx], body=stripped[brace_idx:])
            )
            continue
        var_name = _state_variable_name(stripped)
        if var_name:
            state_vars.append(var_name)

    return state_vars, functions


_STORAGE_ALIAS_RE = re.compile(r"\b\w+\s+storage\s+(\w+)\s*=\s*([A-Za-z_]\w*)\b")


def resolve_storage_aliases(body: str) -> dict[str, str]:
    """`Type storage alias = baseVar[...];` (or `= baseVar;`) — the common gas-saving idiom
    of holding a storage pointer to avoid repeated indexed reads — as a mapping alias ->
    baseVar. Real-world-motivated, not anticipated from any self-authored fixture: Tremolo's
    VarianceMarket.sol uses this idiom pervasively (`Series storage s = _series[seriesId];
    s.subscribedLong += units;`) — without resolving it, this write is invisible to any
    `writes_to()` check on `_series`, even though it's arguably the single most common way
    real Solidity accesses per-id struct state (any mapping-of-structs pattern: Morpho
    Blue's markets, Compound's accounts, ...)."""
    return dict(_STORAGE_ALIAS_RE.findall(body))


def _name_variants(name: str, body: str) -> list[str]:
    """`name` itself, plus any local storage-pointer alias resolved from this body."""
    return [name] + [alias for alias, base in resolve_storage_aliases(body).items() if base == name]


def has_increment(name: str, body: str) -> bool:
    for n in _name_variants(name, body):
        e = re.escape(n)
        if re.search(rf"\b{e}(?:\s*\[[^\]]*\])?(?:\s*\.\s*\w+)?\s*\+=", body):
            return True
        if re.search(rf"\b{e}(?:\s*\[[^\]]*\])?(?:\s*\.\s*\w+)?\s*\+\+", body) or re.search(rf"\+\+\s*{e}\b", body):
            return True
        if re.search(rf"\b{e}(?:\s*\[[^\]]*\])?(?:\s*\.\s*\w+)?\.push\(", body):
            return True
    return False


def has_decrement(name: str, body: str) -> bool:
    for n in _name_variants(name, body):
        e = re.escape(n)
        if re.search(rf"\b{e}(?:\s*\[[^\]]*\])?(?:\s*\.\s*\w+)?\s*-=", body):
            return True
        if re.search(rf"\b{e}(?:\s*\[[^\]]*\])?(?:\s*\.\s*\w+)?\s*--", body) or re.search(rf"--\s*{e}\b", body):
            return True
        if re.search(rf"\b{e}(?:\s*\[[^\]]*\])?(?:\s*\.\s*\w+)?\.pop\(", body):
            return True
        if re.search(rf"delete\s+{e}(?:\s*\[[^\]]*\])?(?:\s*\.\s*\w+)?\b", body):
            return True
    return False


def writes_to(var: str, body: str) -> bool:
    if has_increment(var, body) or has_decrement(var, body):
        return True
    for n in _name_variants(var, body):
        e = re.escape(n)
        if re.search(rf"\b{e}(?:\s*\[[^\]]*\])?(?:\s*\.\s*\w+)?\s*=(?!=)", body):
            return True
    return False


_LINE_COMMENT_RE = re.compile(r"//[^\n]*")
_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)


def _strip_all_comments(source: str) -> str:
    """Removes every `//` line comment and `/* */` block comment outright — used ONLY for
    declaration-name discovery below, never for the main brace-matching/statement-splitting
    logic elsewhere in this module (which needs real character offsets preserved; see
    `strip_leading_comments` for how comments are handled there, per top-level statement,
    without disturbing offsets anywhere else)."""
    return _LINE_COMMENT_RE.sub("", _BLOCK_COMMENT_RE.sub("", source))


def declared_names(raw_source: str) -> list[str]:
    """Every real `contract`/`interface`/`library`/`abstract contract` name declared in a
    RAW, unscoped file — de-duplicated, order preserved.

    Real bug found running against real Tremolo/VarianceMarket.sol, not anticipated from
    any self-authored fixture (every fixture written before this had comment-free or
    carefully-worded comments): ordinary English NatSpec prose routinely contains the
    literal word "contract" followed by an unrelated word ("this **contract holds**...",
    "per **contract that** carries...") — `DECL_NAME_RE` has no way to tell that apart from
    a real declaration by itself, so it must never be run against text that still has
    comments in it."""
    return list(dict.fromkeys(DECL_NAME_RE.findall(_strip_all_comments(raw_source))))


def for_each_declaration(raw_source: str) -> list[str]:
    """Scopes a RAW, unscoped file (pragma/imports/license header and all) down to each of
    its real declarations independently. Safe to call on any file regardless of how many
    declarations it has or what its imports look like — found the hard way running against
    real EulerEarn.sol, not anticipated from any self-authored fixture: a naive
    "first `{` to last `}`" scan on raw text latches onto a named import's braces
    (`import {IERC4626} from "...";`, present in nearly every real file) instead of the
    contract's own. This anchors on the same `contract NAME {` pattern `source_scope.py`
    already uses, never just "the first brace"."""
    return [extract_contract_source(raw_source, name) for name in declared_names(raw_source)]

"""
Singleton/logical-entity detection from SOURCE — pure core (no I/O). Phase 2, primitive #6
(the last on the priority list — the most nontrivial primitive of the six).

dandelion's `singleton.py` distinguishes this ON-CHAIN by event topic0 (Morpho Blue's
CreateMarket/MarketCreated): the "created" thing is an id, not a new contract address —
unlike a factory, whose created address is unique-per-event. Repo-first has no event log
to inspect. The static analogue: a `create*`-named function that computes an id and writes
a record into a mapping, containing NO contract-deployment mechanism anywhere.

Two real-world id schemes recognized, both confirmed on real GitHub code (not
guessed): HASH-based (Morpho Blue: `keccak256(abi.encode(...))`) and COUNTER-based
(Uniswap V3's `NonfungiblePositionManager.mint()`: `tokenId = _nextId++`; Aavegotchi's
`DAOFacet`: `itemId = itemTypesLength++` / `hauntId_ = currentHauntId + 1`; our own
Tremolo `VarianceMarket.createSeries()`: `seriesId = ++seriesCount`). In BOTH schemes the
same discriminator applies — no contract deployment — but "no deployment" needs checking
by more than just the `new` keyword: Gearbox Protocol's real `AccountFactory` deploys a
clone PER ENTITY via OpenZeppelin's `Clones.clone()` (an inline-assembly `create` opcode
under the hood), containing no `new` keyword at all — checking only `new` would have
misclassified a real clone-factory as a singleton. `_deploys_a_contract` below checks all
three known mechanisms (`new`, `.clone(`, and a bare assembly `create`/`create2` opcode).

Known, honestly-documented limitation (not fixed speculatively — no reproduced case yet):
this only looks at the single `create*`-named function's own body, not functions it calls.
Real research found Aave v3's reserve-id assignment (a clean counter
increment, `reservesData[params.asset].id = params.reservesCount`) is only "safe" if you
don't ALSO look at the sibling `ConfiguratorLogic.executeInitReserve()` that deploys the
aToken/debt-token proxies as part of the same logical "create reserve" operation — full
call-graph tracing across function boundaries is out of scope for this static,
single-function check. A SEPARATE, bigger gap surfaced by the same research and
deliberately NOT addressed here: this repo's own factory-detection primitive (`factories.py`)
only recognizes `new X(...)` as evidence of instance creation, so a REAL clone-factory
(Gearbox-shaped, `Clones.clone()`/assembly-only) is currently invisible to the FACTORY
primitive too, not just correctly excluded from singleton — it gets no classification at
all. That's a distinct, separately-scoped detection gap (needs its own primitive design:
tying a clone call to its `implementation` template), not a one-line fix bundled in here.
"""
from __future__ import annotations

import re

_FUNCTION_HEADER_RE = re.compile(r"\bfunction\s+(\w+)\s*\([^)]*\)[^{;]*\{")
_NEW_EXPR_RE = re.compile(r"\bnew\s+\w+\s*\(")
_CLONE_RE = re.compile(r"\.clone\s*\(")
_ASSEMBLY_CREATE_RE = re.compile(r"\bcreate2?\s*\(")
_KECCAK_ABI_ENCODE_RE = re.compile(r"\bkeccak256\s*\(\s*abi\.encode")
# LHS identifier must itself look like an id (matches all 4 real examples in the module
# docstring: tokenId/itemId/hauntId_/seriesId) — without this, a bare "x = y + 1" match
# would fire on ordinary unrelated arithmetic anywhere in a create*-named function.
_COUNTER_ID_ASSIGNMENT_RE = re.compile(r"\b\w*[Ii]d\w*\s*=\s*(?:\+\+\s*\w+|\w+\s*\+\+|\w+\s*\+\s*1\b)")


def _named_function_bodies(source: str) -> list[tuple[str, str]]:
    """Brace-matching split into (function name, body) pairs — same approach as
    `factories.py`'s function-body scoping, duplicated rather than shared: small enough
    that a premature shared abstraction isn't worth it yet, and this one also needs the
    function name, which the factories.py helper doesn't track."""
    out: list[tuple[str, str]] = []
    pos = 0
    while match := _FUNCTION_HEADER_RE.search(source, pos):
        name = match.group(1)
        start = match.end() - 1
        depth = 0
        i = start
        while i < len(source):
            if source[i] == "{":
                depth += 1
            elif source[i] == "}":
                depth -= 1
                if depth == 0:
                    break
            i += 1
        out.append((name, source[start : i + 1]))
        pos = i + 1
    return out


def _deploys_a_contract(body: str) -> bool:
    """True if this function body creates a new on-chain contract instance by ANY known
    mechanism — the `new` keyword, OpenZeppelin's `Clones.clone()`/`.clone()` helper, or a
    bare assembly `create`/`create2` opcode. Checking only `new` would misclassify a real
    clone-factory (confirmed on Gearbox Protocol's `AccountFactory`, see module docstring)
    as a singleton."""
    return bool(_NEW_EXPR_RE.search(body) or _CLONE_RE.search(body) or _ASSEMBLY_CREATE_RE.search(body))


def find_logical_entity_creator(source: str) -> str | None:
    """Name of the first `create*` function that mints an INTERNAL logical entity — via
    either a keccak256(abi.encode(...)) hash id (Morpho Blue-style) or a plain incrementing
    counter id (Uniswap V3/Aavegotchi/Tremolo-style, see module docstring) — and does NOT
    deploy a contract by any known mechanism. None if no such function exists."""
    for name, body in _named_function_bodies(source):
        if not name.lower().startswith("create"):
            continue
        if _deploys_a_contract(body):
            continue  # deploys something -> factory, not a logical entity, regardless of id scheme
        if _KECCAK_ABI_ENCODE_RE.search(body) or _COUNTER_ID_ASSIGNMENT_RE.search(body):
            return name
    return None

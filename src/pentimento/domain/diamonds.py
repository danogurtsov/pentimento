"""
Diamond (EIP-2535) facet detection from SOURCE — pure core (no I/O).

Phase 2, primitive #3. On-chain, dandelion resolves the real facet set by calling the
diamond's own `facetAddresses()` (see its `proxies.py`). Repo-first has no chain to call —
the static stand-in is the near-universal naming convention: the reference implementation
(mudgen/diamond-3) and virtually all real-world diamonds name every facet contract
`*Facet` (`DiamondCutFacet`, `DiamondLoupeFacet`, `OwnershipFacet`, ...). Weaker than a live
`facetAddresses()` call, but a real, checkable signal rather than a guess.

Known, honestly-documented false-negative gap (not fixed here — no conservative fix
exists without a much weaker heuristic): real research confirmed AngleProtocol's
`angle-transmuter` diamond (`contracts/transmuter/facets/`) names its facets `DiamondCut`/
`DiamondLoupe`/`Getters`/`Redeemer`/`Swapper`/`SettersGovernor` — NONE end in `Facet`. There
is no other structural signal distinguishing a facet from an unrelated helper contract
sitting in the same directory, so this repo is invisible to `find_facet_contracts` entirely
(the diamond itself is still detected via `proxies.py`'s `diamondCut`/`facetAddresses`
markers — only the facet SET is missed). Matching "any non-proxy contract near the
diamond" would be a much weaker, false-positive-prone heuristic (mocks/libraries/interfaces
routinely sit in the same directory) — left unfixed rather than guessed at.

Identity (found the hard way — real research, not anticipated from any
fixture written before it): a bare facet NAME is not unique across a batch, same as the
`ContractTest` collision found on DeFiHackLabs for factories. Confirmed on real code:
`aavegotchi/aavegotchi-contracts` runs 5 separate diamonds in one monorepo (Polygon
Aavegotchi Diamond, ForgeDiamond, WearableDiamond, a separate Ethereum-side Diamond, a GHST
Diamond) and reuses the EXACT SAME facet name — `AavegotchiFacet`, `BridgeFacet`,
`ItemsFacet` — for genuinely different facets belonging to different diamonds, each under
its own top-level directory (`contracts/Aavegotchi/facets/` vs `contracts/Ethereum/facets/`).
Their own deploy scripts disambiguate by directory/hardcoded per-chain address, not by
name — `resolve_facet_contracts` mirrors that with the only equivalent signal available
statically: directory proximity to the diamond's own file.
"""
from __future__ import annotations

from pathlib import PurePosixPath

from .factories import ContractKey


def find_facet_contracts(known_contract_names: set[str], exclude: set[str] | None = None) -> set[str]:
    """Contracts whose name ends with the `Facet` convention."""
    exclude = exclude or set()
    return {name for name in known_contract_names if name.endswith("Facet") and name not in exclude}


def _dir_parts(source_file: str) -> tuple[str, ...]:
    return PurePosixPath(source_file.replace("\\", "/")).parent.parts


def _shared_prefix_len(a: tuple[str, ...], b: tuple[str, ...]) -> int:
    n = 0
    for x, y in zip(a, b, strict=False):
        if x != y:
            break
        n += 1
    return n


def resolve_facet_contracts(
    diamond_source_file: str,
    facet_names: set[str],
    by_name: dict[str, list[ContractKey]],
) -> list[ContractKey]:
    """Resolve each bare `*Facet` name to exactly ONE `ContractKey` — confirmed real repos
    (see module docstring) can have the SAME facet name reused by an unrelated diamond
    elsewhere in the same converted batch. Disambiguates by directory proximity to the
    diamond's own file (longest shared path-segment prefix), since every real diamond
    checked keeps one contract per file (no in-file scoping needed, unlike
    the factory/DeFiHackLabs case). Skips — never guesses — a name whose best-matching
    directory is tied between 2+ equally-close candidates."""
    diamond_dir = _dir_parts(diamond_source_file)
    resolved: list[ContractKey] = []
    for name in facet_names:
        candidates = by_name.get(name, [])
        if not candidates:
            continue
        if len(candidates) == 1:
            resolved.append(candidates[0])
            continue
        scored = sorted(
            ((_shared_prefix_len(diamond_dir, _dir_parts(c.source_file)), c) for c in candidates),
            key=lambda t: t[0],
            reverse=True,
        )
        best_score = scored[0][0]
        if sum(1 for score, _ in scored if score == best_score) > 1:
            continue  # tied — ambiguous, don't guess which same-named facet is real
        resolved.append(scored[0][1])
    return resolved

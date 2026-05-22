"""
repo→CDV converter service. Phase 1 (minimal case): node-type classification + single
proxy+implementation merge. Phase 2: getter-enumerable factories (primitive #1),
event-enumerable factories (primitive #2, no getter at all — the creation event is the
only discovery path), diamond/facet merge (primitive #3 — N facets merged into one unit,
unlike the single-impl proxy case), dispatcher-proxy merge (primitive #4 — a contract with
its OWN real logic PLUS a single named extension, unlike a pure proxy which has almost
none), vault/share-accounting flag (primitive #5 — a classify.py signature group, no merge
needed), singleton/logical-entity flag (primitive #6 — a create* function that mints an
internal id (hash- or counter-based) instead of deploying a contract, the repo-first
analogue of dandelion's on-chain Morpho-Blue-market handling). Every primitive added one at a time,
each behind its own golden fixture.

Real-repo support: `project_root`/`contracts_prefix`/`remappings` handle an inconvenient
fact discovered once fixtures gave way to real repos — every fixture so far was self-contained, but real
repos always import OpenZeppelin/Solmate/etc. `remappings` gets passed straight to solc
(Foundry-style `prefix=path`, auto-loadable from a project's own `remappings.txt` — see
`adapters/remappings.py`); `contracts_prefix` filters solc's output (which includes every
TRANSITIVELY resolved external contract too — confirmed empirically) down to only the
contracts actually inside the target directory, so an imported OpenZeppelin base class
doesn't spuriously become its own CDV unit — it just contributes its inherited functions
to the ABI of whatever inherits from it, which solc already flattens in automatically.

Identity (found the hard way on real-world code — DeFiHackLabs, not anticipated from any
fixture we wrote ourselves): a bare contract NAME is not unique across a batch of
independently compiled files. 9 of 10 files in one real directory each declare their own
"ContractTest". Factory-relationship bookkeeping is keyed by `ContractKey(source_file,
name)` throughout, precisely to stop one file's finding from being silently applied to an
unrelated same-named contract in a different file; `unit_id` gets a `@<file-stem>`
disambiguating suffix whenever a name collides within the batch being converted, so two
unrelated "ContractTest" units never overwrite each other's file in the output either.
"""
from __future__ import annotations

from pathlib import Path

from pentimento.domain.classify import classify
from pentimento.domain.deployability import is_deployable
from pentimento.domain.diamonds import find_facet_contracts, resolve_facet_contracts
from pentimento.domain.factories import ContractKey, detect_factory_relationships, resolve_bare_name
from pentimento.domain.models import CDVGraph, CDVUnit, NodeType, ProxyKind
from pentimento.domain.proxies import detect_proxy_kind, is_upgradeable_implementation_candidate
from pentimento.domain.singletons import find_logical_entity_creator
from pentimento.ports.compiler import CompiledContract, CompilerPort

_ENUMERATION_LABEL = {"getter": "enumeration getter found", "event": "enumerable only via creation event"}


def _key(c: CompiledContract) -> ContractKey:
    return ContractKey(c.source_file, c.contract_name)


def convert(
    sol_files: list,
    compiler: CompilerPort,
    project_root: Path | None = None,
    contracts_prefix: str | None = None,
    remappings: list[str] | None = None,
) -> CDVGraph:
    all_contracts: list[CompiledContract] = compiler.compile(sol_files, base_path=project_root, remappings=remappings)

    # drop anything resolved from OUTSIDE the target directory (an imported OpenZeppelin
    # base class, say) — it's an external dependency, not one of "our" units (the
    # membership principle: control/scope decides, not the mere fact of being compiled).
    contracts = (
        [c for c in all_contracts if c.source_file.replace("\\", "/").startswith(contracts_prefix)]
        if contracts_prefix is not None
        else all_contracts
    )

    # a bare `interface`/`abstract contract`/all-internal `library` declaration is never
    # deployed on its own (real bug found on Tremolo: four bare interfaces and an
    # all-internal library each became their own top-level unit) — CDV's own definition of
    # a unit is "one resolved, as-if-deployed contract", so filter these out before any of
    # the categorization below. Safe to do this early: none of proxy/impl/diamond/dispatcher/
    # factory-target detection can ever legitimately point at an interface or a library (a
    # `new X(...)` target and a facet/impl/extension are always a `contract` by Solidity's
    # own language rules), so nothing downstream loses a legitimate cross-reference.
    contracts = [c for c in contracts if is_deployable(c.source_text)]

    name_counts: dict[str, int] = {}
    for c in contracts:
        name_counts[c.contract_name] = name_counts.get(c.contract_name, 0) + 1

    def unit_id_for(c: CompiledContract) -> str:
        # a name colliding across unrelated files (confirmed real: DeFiHackLabs) gets
        # disambiguated; the common single-name case is untouched.
        return c.contract_name if name_counts[c.contract_name] == 1 else f"{c.contract_name}@{Path(c.source_file).stem}"

    proxies = [c for c in contracts if detect_proxy_kind(c.source_text) != ProxyKind.NONE]
    diamonds = [p for p in proxies if detect_proxy_kind(p.source_text) == ProxyKind.DIAMOND]
    dispatchers = [p for p in proxies if detect_proxy_kind(p.source_text) == ProxyKind.DISPATCHER]
    regular_proxies = [p for p in proxies if p not in diamonds and p not in dispatchers]
    non_proxies = [c for c in contracts if c not in proxies]
    impl_candidates = [c for c in non_proxies if is_upgradeable_implementation_candidate(c.source_text)]

    known_names = {c.contract_name for c in contracts}
    by_name: dict[str, list[ContractKey]] = {}
    for c in contracts:
        by_name.setdefault(c.contract_name, []).append(_key(c))

    relationships = detect_factory_relationships([(_key(c), c.source_text) for c in contracts])

    # Per the CDV standard's own conservative-signal principle: don't force a classification on a weak signal — only
    # `new X(...)` + a KNOWN way to discover instances (getter or creation event) is strong
    # enough to mark node_type=FACTORY; `new X(...)` with neither stays a note only.
    # All keyed by ContractKey, not bare name — see module docstring's Identity note.
    strong: dict[ContractKey, ContractKey] = {}
    enumeration_of: dict[ContractKey, str] = {}
    template_of: dict[ContractKey, ContractKey] = {}
    weak_notes: dict[ContractKey, list[str]] = {}
    for rel in relationships:
        if rel.enumeration_kind != "none":
            strong.setdefault(rel.factory, rel.template)
            enumeration_of.setdefault(rel.factory, rel.enumeration_kind)
            template_of.setdefault(rel.template, rel.factory)
        else:
            weak_notes.setdefault(rel.factory, []).append(
                f"creates instances of {rel.template.contract_name} "
                "(no enumeration getter or creation event found — not classified as factory)"
            )

    already_merged: set[ContractKey] = set()  # non-proxy contracts folded into a proxy/diamond/dispatcher unit
    units: list[CDVUnit] = []

    if len(regular_proxies) == 1 and len(impl_candidates) == 1:
        proxy, impl = regular_proxies[0], impl_candidates[0]
        already_merged.add(_key(impl))
        units.append(
            CDVUnit(
                unit_id=unit_id_for(proxy),
                contract_name=proxy.contract_name,
                node_type=classify(impl.abi),
                proxy_kind=detect_proxy_kind(proxy.source_text),
                source_files=sorted({proxy.source_file, impl.source_file}),
                notes=[f"implementation merged: {impl.contract_name}"],
            )
        )
    else:
        # multiple/zero proxy or impl candidates — outside the minimal case, emit each
        # proxy as its own opaque unit rather than guessing a merge (Phase 2 territory).
        for proxy in regular_proxies:
            units.append(
                CDVUnit(
                    unit_id=unit_id_for(proxy),
                    contract_name=proxy.contract_name,
                    node_type=classify(proxy.abi),
                    proxy_kind=detect_proxy_kind(proxy.source_text),
                    source_files=[proxy.source_file],
                    notes=["proxy found but merge skipped: ambiguous impl candidate count"],
                )
            )

    if len(diamonds) == 1:
        diamond = diamonds[0]
        # Facet matching is directory-proximity-based, not bare-name (see diamonds.py's
        # module docstring): confirmed real collision on aavegotchi-contracts, which runs 5
        # separate diamonds in one monorepo and reuses the SAME facet name across different
        # diamonds under different directories — same class of bug as the ContractTest
        # collision found on DeFiHackLabs for factories.
        facet_names = find_facet_contracts(known_names, exclude={diamond.contract_name})
        facet_keys = set(resolve_facet_contracts(diamond.source_file, facet_names, by_name))
        facets = [c for c in non_proxies if _key(c) in facet_keys]
        already_merged.update(_key(f) for f in facets)
        combined_abi = [entry for f in facets for entry in f.abi]
        units.append(
            CDVUnit(
                unit_id=unit_id_for(diamond),
                contract_name=diamond.contract_name,
                node_type=classify(combined_abi) if facets else classify(diamond.abi),
                proxy_kind=ProxyKind.DIAMOND,
                merged_facets=sorted(f.contract_name for f in facets),
                source_files=sorted({diamond.source_file, *(f.source_file for f in facets)}),
                notes=[f"facet merged: {f.contract_name}" for f in facets]
                or ["diamond found but no *Facet-named contracts to merge"],
            )
        )
    else:
        for diamond in diamonds:
            units.append(
                CDVUnit(
                    unit_id=unit_id_for(diamond),
                    contract_name=diamond.contract_name,
                    node_type=classify(diamond.abi),
                    proxy_kind=ProxyKind.DIAMOND,
                    source_files=[diamond.source_file],
                    notes=["diamond found but merge skipped: ambiguous diamond count"],
                )
            )

    if len(dispatchers) == 1:
        dispatcher = dispatchers[0]
        ext_name = f"{dispatcher.contract_name}Ext"
        ext_key = resolve_bare_name(ext_name, dispatcher.source_file, by_name)
        ext = next((c for c in non_proxies if _key(c) == ext_key), None) if ext_key else None
        combined_abi = list(dispatcher.abi) + (list(ext.abi) if ext else [])
        source_files = {dispatcher.source_file}
        dispatcher_notes: list[str] = []
        if ext:
            already_merged.add(_key(ext))
            source_files.add(ext.source_file)
            dispatcher_notes.append(f"extension merged: {ext.contract_name}")
        else:
            dispatcher_notes.append(f"dispatcher found but no {ext_name} extension contract in scope")
        units.append(
            CDVUnit(
                unit_id=unit_id_for(dispatcher),
                contract_name=dispatcher.contract_name,
                node_type=classify(combined_abi),
                proxy_kind=ProxyKind.DISPATCHER,
                source_files=sorted(source_files),
                notes=dispatcher_notes,
            )
        )
    else:
        for dispatcher in dispatchers:
            units.append(
                CDVUnit(
                    unit_id=unit_id_for(dispatcher),
                    contract_name=dispatcher.contract_name,
                    node_type=classify(dispatcher.abi),
                    proxy_kind=ProxyKind.DISPATCHER,
                    source_files=[dispatcher.source_file],
                    notes=["dispatcher found but merge skipped: ambiguous dispatcher count"],
                )
            )

    for contract in non_proxies:
        key = _key(contract)
        if key in already_merged:
            continue
        node_type = classify(contract.abi)
        notes: list[str] = list(weak_notes.get(key, []))

        factory_target = strong.get(key)
        if factory_target:
            node_type = NodeType.FACTORY
            notes.append(
                f"factory: creates instances of {factory_target.contract_name} "
                f"({_ENUMERATION_LABEL[enumeration_of[key]]})"
            )

        entity_creator = find_logical_entity_creator(contract.source_text)
        if entity_creator:
            notes.append(
                f"singleton: {entity_creator}() mints an internal logical entity (hash- or "
                "counter-based id), not a deployed contract — no address to enumerate, unlike "
                "a factory instance"
            )

        factory_of_key = template_of.get(key)
        unit = CDVUnit(
            unit_id=unit_id_for(contract),
            contract_name=contract.contract_name,
            node_type=node_type,
            proxy_kind=ProxyKind.NONE,
            factory_creates=factory_target.contract_name if factory_target else None,
            factory_of=factory_of_key.contract_name if factory_of_key else None,
            factory_enumeration=enumeration_of.get(key),
            logical_entity_creator=entity_creator,
            source_files=[contract.source_file],
            notes=notes,
        )
        if factory_of_key:
            unit.notes.append(
                f"instantiated by factory: {factory_of_key.contract_name} "
                "(no deployment data — instance count unknown until the onchain-to-CDV converter runs)"
            )
        units.append(unit)

    return CDVGraph(generator="pentimento-repo-to-cdv/0.0.1", units=units)

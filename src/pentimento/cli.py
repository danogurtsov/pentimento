from __future__ import annotations

import json
import shutil
from dataclasses import asdict
from pathlib import Path

import typer

from pentimento.adapters.foundry_adapter import ForgeAdapter
from pentimento.adapters.llm_factory import build_llm, model_of
from pentimento.adapters.remappings import load_remappings
from pentimento.adapters.solc_adapter import SolcAdapter
from pentimento.detection.calibration import render_registry
from pentimento.detection.report import render_report
from pentimento.domain.models import CDVGraph
from pentimento.services.breadth_pass import run_breadth_pass
from pentimento.services.calibration import current_commit, load_registry
from pentimento.services.converter import convert
from pentimento.services.cost_ceiling import BudgetedLLM, BudgetExceededError, SharedBudget
from pentimento.services.investigation import InvestigationGraph, run_investigation
from pentimento.services.report import build_report_items, request_approval

app = typer.Typer(add_completion=False)

_PROJECT_ROOT_HELP = (
    "Repo root for remapping/base-path resolution (default: src's parent — the Foundry "
    "convention of remappings.txt living next to src/)."
)
_REMAP_HELP = "Extra `prefix=path` remapping, on top of any auto-loaded remappings.txt. Repeatable."
_BASE_URL_HELP = (
    "Override the provider's default endpoint — e.g. a self-hosted vLLM server "
    "('--llm vllm:<served-model-name> --base-url http://<host>:8000/v1')."
)
_MAX_COST_HELP = (
    "Abort the run once cumulative TRACKED spend across every role already exceeds this "
    "many USD (checked before each call, not a preemptive real-time limit — one call's "
    "worth of overshoot is possible; see services/cost_ceiling.py). Only tracks cost for "
    "adapters that report it (currently claude-cli:* only) — omit to run unbounded."
)
_TIMEOUT_HELP = (
    "Per-call timeout in seconds for every role's LLM adapter (default 300s). Raise this "
    "for a stronger/slower model on a large real contract — "
    "claude-cli:sonnet needed ~900s on a ~30-import contract and the default silently "
    "killed the call with no way to raise it before this flag existed."
)


def _convert_from_cli_args(
    src: Path, solc: str, project_root: Path | None, remap: list[str]
) -> tuple[CDVGraph, Path]:
    src = src.resolve()
    resolved_root = project_root.resolve() if project_root else src.parent

    sol_files = sorted(src.rglob("*.sol"))
    if not sol_files:
        typer.echo(f"no .sol files found in {src}")
        raise typer.Exit(code=1)

    remappings = load_remappings(resolved_root) + list(remap)
    contracts_prefix = str(src.relative_to(resolved_root)) + "/"

    graph = convert(
        sol_files,
        SolcAdapter(solc_path=solc),
        project_root=resolved_root,
        contracts_prefix=contracts_prefix,
        remappings=remappings,
    )
    return graph, resolved_root


@app.command()
def cdv(
    src: Path = typer.Argument(..., help="Directory of .sol files to convert (searched recursively)."),
    out: Path = typer.Option(Path("out/cdv"), "--out", help="Output directory for the CDV manifest."),
    solc: str = typer.Option("solc", "--solc", help="Path to the solc binary."),
    project_root: Path = typer.Option(None, "--project-root", help=_PROJECT_ROOT_HELP),
    remap: list[str] = typer.Option([], "--remap", help=_REMAP_HELP),
) -> None:
    """Convert a Solidity source directory into a Canonical Deploy View manifest."""
    graph, resolved_root = _convert_from_cli_args(src, solc, project_root, remap)

    out.mkdir(parents=True, exist_ok=True)
    (out / "manifest.json").write_text(json.dumps(graph.to_dict(), indent=2))
    for unit in graph.units:
        unit_dir = out / "units" / unit.unit_id
        unit_dir.mkdir(parents=True, exist_ok=True)
        (unit_dir / "unit.json").write_text(json.dumps(unit.to_dict(), indent=2))
        for source_file in unit.source_files:
            # source_file is reported relative to project_root (base_path) — resolve
            # before copying, it's not necessarily relative to the current directory.
            shutil.copy(resolved_root / source_file, unit_dir / Path(source_file).name)

    typer.echo(f"wrote {len(graph.units)} unit(s) to {out}")


@app.command(name="breadth-pass")
def breadth_pass(
    src: Path = typer.Argument(..., help="Directory of .sol files to convert (searched recursively)."),
    llm: str = typer.Option(
        ...,
        "--llm",
        help="'provider:model' spec — 'claude-cli:haiku' (your own logged-in Claude Code "
        "subscription, no API key needed), 'anthropic:claude-sonnet-5' (CLAUDE_CODE_OAUTH_TOKEN "
        "or ANTHROPIC_API_KEY), 'deepseek:deepseek-chat' (DEEPSEEK_API_KEY), or any other "
        "OpenAI-compatible provider name.",
    ),
    base_url: str = typer.Option(None, "--base-url", help=_BASE_URL_HELP),
    out: Path = typer.Option(Path("out/breadth"), "--out", help="Output directory for breadth-pass results."),
    route: bool = typer.Option(
        False,
        "--route",
        help="Run Phase 5 functional-primitive routing per unit first (a genuine second LLM "
        "call, same --llm backend) — any domain skill it activates gets folded into the BSA "
        "prompt. Off by default (real extra spend per unit).",
    ),
    strong_llm: str = typer.Option(
        None,
        "--strong-llm",
        help="Escalation 'provider:model' spec — used instead of --llm for a unit "
        "detection/complexity.py's cheap signal flags as complex enough that a small model "
        "may miss real bugs (a measured finding). Requires --strong-base-url "
        "if the provider needs a different endpoint. Off by default (real extra spend, and "
        "the escalation heuristic is a first, honest guess — see complexity.py).",
    ),
    strong_base_url: str = typer.Option(None, "--strong-base-url", help=f"Escalation {_BASE_URL_HELP}"),
    max_cost_usd: float = typer.Option(None, "--max-cost-usd", help=_MAX_COST_HELP),
    timeout: float = typer.Option(None, "--timeout", help=_TIMEOUT_HELP),
    solc: str = typer.Option("solc", "--solc", help="Path to the solc binary."),
    project_root: Path = typer.Option(None, "--project-root", help=_PROJECT_ROOT_HELP),
    remap: list[str] = typer.Option([], "--remap", help=_REMAP_HELP),
) -> None:
    """Convert to CDV, then run a Phase-4 breadth-pass over every unit via --llm."""
    graph, resolved_root = _convert_from_cli_args(src, solc, project_root, remap)

    llm_port = build_llm(llm, base_url=base_url, timeout=timeout)
    budget = SharedBudget(max_cost_usd) if max_cost_usd is not None else None
    if budget is not None:
        llm_port = BudgetedLLM(llm_port, budget)
    router_llm = llm_port if route else None
    router_model = model_of(llm) if route else None
    strong_port = build_llm(strong_llm, base_url=strong_base_url, timeout=timeout) if strong_llm else None
    if strong_port is not None and budget is not None:
        strong_port = BudgetedLLM(strong_port, budget)
    strong_model_spec = model_of(strong_llm) if strong_llm else None
    try:
        results = run_breadth_pass(
            graph,
            resolved_root,
            llm_port,
            model=model_of(llm),
            router_llm=router_llm,
            router_model=router_model,
            strong_llm=strong_port,
            strong_model=strong_model_spec,
        )
    except BudgetExceededError as e:
        typer.echo(
            f"Aborted — {e}. No results were written this run (known limitation: the "
            "ceiling stops the whole run, it doesn't yet preserve partial results already "
            "computed before the abort).",
            err=True,
        )
        raise typer.Exit(code=1) from e

    out.mkdir(parents=True, exist_ok=True)
    total_anomalies = 0
    total_activations = 0
    for result in results:
        (out / f"{result.unit_id}.md").write_text(result.raw_response)
        if result.guard_anomalies:
            total_anomalies += len(result.guard_anomalies)
            anomalies_json = [asdict(a) for a in result.guard_anomalies]
            (out / f"{result.unit_id}.guards.json").write_text(json.dumps(anomalies_json, indent=2))
        if result.state_sync_anomalies:
            total_anomalies += len(result.state_sync_anomalies)
            sync_json = [asdict(a) for a in result.state_sync_anomalies]
            (out / f"{result.unit_id}.invariants.json").write_text(json.dumps(sync_json, indent=2))
        if result.routing_decision:
            activated = result.routing_decision.activated_domains()
            total_activations += len(activated)
            routing_json = [asdict(a) for a in result.routing_decision.activations]
            (out / f"{result.unit_id}.routing.json").write_text(json.dumps(routing_json, indent=2))
        if result.model_decision:
            (out / f"{result.unit_id}.model.json").write_text(json.dumps(asdict(result.model_decision), indent=2))
        if result.injection_signals:
            signals_json = [asdict(s) for s in result.injection_signals]
            (out / f"{result.unit_id}.injection.json").write_text(json.dumps(signals_json, indent=2))
    route_summary = f", {total_activations} domain-skill activation(s)" if route else ""
    budget_summary = f", ${budget.spent_usd:.4f} spent (tracked={budget.tracked})" if budget is not None else ""
    recommended = sum(1 for r in results if r.model_decision and r.model_decision.recommended_escalation)
    escalated = sum(1 for r in results if r.model_decision and r.model_decision.escalated)
    escalation_summary = f", {recommended} unit(s) flagged complex ({escalated} actually escalated)" if results else ""
    injection_flagged = sum(1 for r in results if r.injection_signals)
    injection_summary = (
        f", {injection_flagged} unit(s) flagged for possible prompt injection" if injection_flagged else ""
    )
    typer.echo(
        f"ran breadth-pass on {len(results)} unit(s) via {llm} "
        f"({total_anomalies} pre-flagged anomaly(ies) — guard + state-sync{route_summary}"
        f"{escalation_summary}{injection_summary}), wrote results to {out}{budget_summary}"
    )


@app.command()
def investigate(
    src: Path = typer.Argument(..., help="Directory of .sol files to convert (searched recursively)."),
    llm: str = typer.Option(
        ...,
        "--llm",
        help="Scout 'provider:model' spec (cheap, runs on every unit) — see `breadth-pass --help` "
        "for the provider list.",
    ),
    strategist_llm: str = typer.Option(
        None,
        "--strategist-llm",
        help="Deep-pass 'provider:model' spec (only spent on units the strategist escalates). "
        "Omit to just record escalations without spending on a second call.",
    ),
    verifier_llm: str = typer.Option(
        None,
        "--verifier-llm",
        help="Phase 6 Trail-of-Bits verifier 'provider:model' spec — 1 call per finding on "
        "the Standard route, 4 on the Deep route (routing is automatic per finding, see "
        "detection/verdict.py::decide_verification_route). Omit to skip verification "
        "entirely (no findings are parsed or verified).",
    ),
    poc_llm: str = typer.Option(
        None,
        "--poc-llm",
        help="Level 1 deterministic PoC oracle 'provider:model' spec — generates an "
        "executable Foundry test for every finding --verifier-llm rated TRUE_POSITIVE, then "
        "a real `forge test` run (not the model) decides if the exploit reproduces. "
        "Requires --verifier-llm; ignored without it.",
    ),
    strong_scout_llm: str = typer.Option(
        None,
        "--strong-scout-llm",
        help="Escalation 'provider:model' spec for the scout pass — used instead of --llm "
        "for a unit detection/complexity.py's cheap signal flags as complex (a measured "
        "finding). Off by default.",
    ),
    second_verifier_llm: str = typer.Option(
        None,
        "--second-verifier-llm",
        help="A genuinely independent second verifier 'provider:model' spec — the "
        "multi-model-jury pattern (see services/verification.py). Requires --verifier-llm; "
        "ignored without it. TRUE_POSITIVE then requires BOTH verifiers to agree — a single "
        "dissent flips the verdict to FALSE_POSITIVE. Off by default (a real second LLM call "
        "per finding). Use a DIFFERENT provider/model than --verifier-llm for genuine "
        "independence, e.g. --verifier-llm claude-cli:haiku --second-verifier-llm "
        "deepseek:deepseek-chat.",
    ),
    strong_verifier_llm: str = typer.Option(
        None,
        "--strong-verifier-llm",
        help="Escalation 'provider:model' spec for verification — used instead of "
        "--verifier-llm whenever a finding routes to Deep verification (4-phase pipeline, "
        "see services/verification.py). Off by default. Exists because "
        "claude-cli:haiku produced substantial Phase 1/2/4 Deep reports but "
        "never emitted a single parseable GATE line on the final synthesis call; the "
        "identical prompt chain on claude-cli:sonnet did.",
    ),
    route: bool = typer.Option(
        False,
        "--route",
        help="Run Phase 5 functional-primitive routing for the scout pass first (same "
        "--llm backend) — same flag `breadth-pass` already offers, previously unreachable "
        "from `investigate` at all (a real, found gap). Off by default (real extra spend "
        "per unit).",
    ),
    base_url: str = typer.Option(None, "--base-url", help=f"Scout {_BASE_URL_HELP}"),
    strategist_base_url: str = typer.Option(None, "--strategist-base-url", help=f"Strategist {_BASE_URL_HELP}"),
    verifier_base_url: str = typer.Option(None, "--verifier-base-url", help=f"Verifier {_BASE_URL_HELP}"),
    poc_base_url: str = typer.Option(None, "--poc-base-url", help=f"PoC-generator {_BASE_URL_HELP}"),
    strong_scout_base_url: str = typer.Option(None, "--strong-scout-base-url", help=f"Escalation {_BASE_URL_HELP}"),
    second_verifier_base_url: str = typer.Option(
        None, "--second-verifier-base-url", help=f"Second verifier {_BASE_URL_HELP}"
    ),
    strong_verifier_base_url: str = typer.Option(
        None, "--strong-verifier-base-url", help=f"Verification escalation {_BASE_URL_HELP}"
    ),
    forge: str = typer.Option("forge", "--forge", help="Path to the forge binary (used only with --poc-llm)."),
    poc_test_dir: str = typer.Option(
        "test", "--poc-test-dir", help="Test directory (relative to --project-root) the PoC oracle writes into."
    ),
    allow_ffi: bool = typer.Option(
        False,
        "--allow-ffi",
        help="Allow the PoC oracle to run `forge test` even when the target project's own "
        "foundry.toml enables the `ffi` cheatcode (arbitrary shell execution during forge "
        "test). Off by default — a real project in this tool's own corpus "
        "(scabench-minimal-delegation) already has ffi=true. Only pass this for a project "
        "you specifically trust.",
    ),
    max_cost_usd: float = typer.Option(None, "--max-cost-usd", help=_MAX_COST_HELP + " Shared across all roles."),
    timeout: float = typer.Option(None, "--timeout", help=_TIMEOUT_HELP + " Applies to every role."),
    out: Path = typer.Option(Path("out/investigation.json"), "--out", help="Output path for the investigation graph."),
    solc: str = typer.Option("solc", "--solc", help="Path to the solc binary."),
    project_root: Path = typer.Option(None, "--project-root", help=_PROJECT_ROOT_HELP),
    remap: list[str] = typer.Option([], "--remap", help=_REMAP_HELP),
) -> None:
    """Scout every unit via --llm, let the strategist decide what needs a deeper look, and
    (if --strategist-llm is given) run that deeper pass — a persistent investigation graph,
    hound-style scout/strategist asymmetry over CDV units. If --verifier-llm is given, every
    parsed Finding also goes through Phase 6's Trail-of-Bits verification (Standard or Deep
    path, chosen automatically per finding); if --poc-llm is ALSO given, every TRUE_POSITIVE
    verdict additionally gets a real, executed Foundry PoC (the Level 1 deterministic
    oracle)."""
    graph, resolved_root = _convert_from_cli_args(src, solc, project_root, remap)
    budget = SharedBudget(max_cost_usd) if max_cost_usd is not None else None

    def _budgeted(port):
        return BudgetedLLM(port, budget) if budget is not None and port is not None else port

    scout_port = _budgeted(build_llm(llm, base_url=base_url, timeout=timeout))
    deep_port = (
        _budgeted(build_llm(strategist_llm, base_url=strategist_base_url, timeout=timeout))
        if strategist_llm
        else None
    )
    deep_model = model_of(strategist_llm) if strategist_llm else None
    verifier_port = (
        _budgeted(build_llm(verifier_llm, base_url=verifier_base_url, timeout=timeout)) if verifier_llm else None
    )
    verifier_model = model_of(verifier_llm) if verifier_llm else None
    poc_port = (
        _budgeted(build_llm(poc_llm, base_url=poc_base_url, timeout=timeout)) if poc_llm and verifier_llm else None
    )
    poc_model_spec = model_of(poc_llm) if poc_llm and verifier_llm else None
    poc_executor = ForgeAdapter(forge_path=forge) if poc_port else None
    second_verifier_port = (
        _budgeted(build_llm(second_verifier_llm, base_url=second_verifier_base_url, timeout=timeout))
        if second_verifier_llm and verifier_llm
        else None
    )
    second_verifier_model_spec = model_of(second_verifier_llm) if second_verifier_llm and verifier_llm else None
    strong_verifier_port = (
        _budgeted(build_llm(strong_verifier_llm, base_url=strong_verifier_base_url, timeout=timeout))
        if strong_verifier_llm and verifier_llm
        else None
    )
    strong_verifier_model_spec = model_of(strong_verifier_llm) if strong_verifier_llm and verifier_llm else None
    strong_scout_port = (
        _budgeted(build_llm(strong_scout_llm, base_url=strong_scout_base_url, timeout=timeout))
        if strong_scout_llm
        else None
    )
    strong_scout_model_spec = model_of(strong_scout_llm) if strong_scout_llm else None
    router_port = scout_port if route else None
    router_model_spec = model_of(llm) if route else None

    try:
        investigation = run_investigation(
            graph,
            resolved_root,
            scout_port,
            model_of(llm),
            strategist_llm=deep_port,
            strategist_model=deep_model,
            verifier_llm=verifier_port,
            verifier_model=verifier_model,
            poc_llm=poc_port,
            poc_model=poc_model_spec,
            poc_executor=poc_executor,
            poc_test_dir=poc_test_dir,
            poc_allow_ffi=allow_ffi,
            strong_scout_llm=strong_scout_port,
            strong_scout_model=strong_scout_model_spec,
            router_llm=router_port,
            router_model=router_model_spec,
            second_verifier_llm=second_verifier_port,
            second_verifier_model=second_verifier_model_spec,
            strong_verifier_llm=strong_verifier_port,
            strong_verifier_model=strong_verifier_model_spec,
        )
    except BudgetExceededError as e:
        typer.echo(
            f"Aborted — {e}. No investigation graph was written this run (known "
            "limitation: the ceiling stops the whole run, it doesn't yet preserve partial "
            "results already computed before the abort).",
            err=True,
        )
        raise typer.Exit(code=1) from e

    out.parent.mkdir(parents=True, exist_ok=True)
    investigation.save(out)

    escalated = sum(1 for r in investigation.units.values() if r.status.value != "scouted")
    investigated = sum(1 for r in investigation.units.values() if r.status.value == "investigated")
    verdicts = [v for r in investigation.units.values() for v in r.finding_verdicts]
    true_positives = sum(1 for v in verdicts if v["verdict"] == "true_positive")
    dissents = sum(1 for v in verdicts if v.get("secondary_gate_results") is not None)
    jury_summary = (
        f", {dissents} finding(s) went through the second independent verifier" if second_verifier_llm else ""
    )
    verify_summary = (
        f", {len(verdicts)} finding(s) verified via {verifier_llm} ({true_positives} true positive)"
        f"{jury_summary}"
        if verifier_llm
        else ""
    )
    poc_results = [p for r in investigation.units.values() for p in r.poc_verifications]
    reproduced = sum(1 for p in poc_results if p["outcome"] == "reproduced")
    refused_ffi = sum(1 for p in poc_results if p["outcome"] == "refused_untrusted_ffi")
    poc_summary = (
        f", {len(poc_results)} PoC(s) executed ({reproduced} reproduced, {refused_ffi} refused - untrusted ffi)"
        if poc_port
        else ""
    )
    budget_summary = f", ${budget.spent_usd:.4f} spent (tracked={budget.tracked})" if budget is not None else ""
    model_escalated = sum(
        1 for r in investigation.units.values() if r.scout_model_decision and r.scout_model_decision["escalated"]
    )
    escalation_summary = f", {model_escalated} unit(s) scouted with the stronger model" if strong_scout_llm else ""
    domain_activations = sum(
        1
        for r in investigation.units.values()
        if r.scout_routing_decision
        for a in r.scout_routing_decision["activations"]
        if a["activated"]
    )
    route_summary = f", {domain_activations} domain-skill activation(s)" if route else ""
    injection_flagged = sum(1 for r in investigation.units.values() if r.scout_injection_signals)
    injection_summary = (
        f", {injection_flagged} unit(s) flagged for possible prompt injection" if injection_flagged else ""
    )
    typer.echo(
        f"scouted {len(investigation.units)} unit(s) via {llm}: {escalated} escalated, "
        f"{investigated} investigated"
        + (f" via {strategist_llm}" if strategist_llm else " (no --strategist-llm, escalation only)")
        + verify_summary
        + poc_summary
        + escalation_summary
        + route_summary
        + injection_summary
        + f". Wrote {out}"
        + budget_summary
    )


@app.command()
def report(
    investigation: Path = typer.Argument(..., help="Path to an investigation.json from `pentimento investigate`."),
    project_name: str = typer.Option("Project", "--project-name", help="Name shown in the report header."),
    out: Path = typer.Option(Path("out/report.md"), "--out", help="Output path for the final, approved report."),
    approve: str = typer.Option(
        None,
        "--approve",
        help="Human approver's name — REQUIRED to write the final report. Without it, only "
        "a clearly-marked DRAFT (not for client delivery) is written, and nothing is "
        "recorded as approved.",
    ),
) -> None:
    """Phase 7: assemble Findings/Leads from an investigation graph (a pashov-style split)
    into an industry-format report, enforcing a real BLOCKING
    human-approval gate before anything final is written — nothing ships without an
    explicit, recorded approval."""
    graph = InvestigationGraph.load(investigation)
    items = build_report_items(graph)
    report_text = render_report(items, project_name)
    record = request_approval(report_text, approve)

    out.parent.mkdir(parents=True, exist_ok=True)
    if record.approved:
        out.write_text(report_text)
        (out.parent / f"{out.stem}.approval.json").write_text(json.dumps(asdict(record), indent=2))
        typer.echo(f"Approved by {approve!r} — wrote the final report to {out}")
    else:
        draft_path = out.parent / f"{out.stem}.DRAFT.md"
        draft_path.write_text("<!-- DRAFT — NOT APPROVED, DO NOT SEND TO CLIENT -->\n\n" + report_text)
        typer.echo(
            f"No --approve given — wrote a DRAFT ONLY to {draft_path} (NOT the final "
            "report, nothing recorded as approved). Re-run with --approve '<your name>' to "
            "produce the approved, client-ready report."
        )

    counts = {status: sum(1 for i in items if i.status.value == status) for status in ("finding", "lead", "rejected")}
    typer.echo(
        f"{counts['finding']} finding(s), {counts['lead']} lead(s) in the appendix, "
        f"{counts['rejected']} rejected (dropped, not shown anywhere)"
    )


_DEFAULT_REGISTRY = Path(__file__).resolve().parents[2] / "evals" / "calibration_registry.json"
_DEFAULT_REPO_ROOT = Path(__file__).resolve().parents[2]


@app.command()
def calibration(
    registry: Path = typer.Option(_DEFAULT_REGISTRY, "--registry", help="Path to the calibration registry JSON."),
    repo_root: Path = typer.Option(
        _DEFAULT_REPO_ROOT, "--repo-root", help="pentimento's own repo root, for live staleness checking."
    ),
) -> None:
    """Phase 9: render the public calibration registry — a publicly, honestly updated
    calibration registry, including an explicit "this version hasn't been re-measured yet"
    flag where relevant — flagging any entry whose recorded commit no longer matches the
    current HEAD as STALE — explicit visibility into what might need re-measuring, never
    silence."""
    entries = load_registry(registry)
    commit = current_commit(repo_root)
    typer.echo(render_registry(entries, commit))


if __name__ == "__main__":
    app()

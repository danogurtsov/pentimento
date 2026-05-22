"""
Blind regression harness for DETECTION QUALITY — the "fast tier" of the regression pyramid
(CTFBench+DeFiVulnLabs, minutes, meant to run on every commit). The first automated
regression gate this project has for RECALL/FP specifically (CDV structural correctness
already had `evals/run_evals.py`; detection quality had none — every earlier number in
`evals/calibration_registry.json` was a manual, one-off live run documented by hand).

Deliberately NOT a naive string-matching auto-grader — this project's own calibration
registry explicitly rejects that (to avoid corrupting the registry with false precision).
Instead: an LLM-JUDGE step (`detection/judge.py`), the SAME pattern the field's own most
rigorous tools use for exactly this (krait's blind shadow-eval, GiAnt Corpus's LLM-judge
PASS/FAIL loop) — semantic verification by a genuinely SEPARATE model call, with strict,
deterministic PARSING of that judgment, never fuzzy substring matching.

Ground truth: `evals/golden/detection/defivulnlabs_subset.json` — 26 fixtures, each
description read and verified from the fixture's OWN source (not the upstream README
alone). A REGRESSION is any case that previously MATCHed the baseline and no longer does —
a new MATCH that wasn't there before is never treated as a failure, only a lost one is.

Judge independence matters here: when a frontier model checks ITSELF, a verification step's
own real value drops sharply — who observes matters as much as whether observation happens
at all. The judge should be from a DIFFERENT family than the candidate — same-family
self-preference bias runs 10-25% uniform inflation, invisible on any dashboard. This
harness's own default used to be `--judge-llm claude-cli:haiku` — the EXACT SAME model
checking its own output, precisely that anti-pattern. `run()` now WARNS (does not hard-block
— this is a quality signal, not a security one) whenever `--llm` and `--judge-llm` resolve
to the literal same spec. The default judge is now `claude-cli:sonnet` — a stronger model in
the SAME family, a real but PARTIAL improvement; true cross-family independence (e.g.
`deepseek:deepseek-chat`, which this harness already supports via `--judge-llm`) needs a
second provider's API key, not configured in this environment — an honest, named
limitation, not glossed over.

Usage:
    python evals/run_detection_regression.py --llm claude-cli:haiku --judge-llm claude-cli:sonnet
    python evals/run_detection_regression.py --llm claude-cli:haiku --judge-llm deepseek:deepseek-chat
    python evals/run_detection_regression.py --llm anthropic:claude-haiku-4-5 --update-baseline

Exits 1 on a regression (or if `solc`/the LLM backend can't run at all), 0 otherwise.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT / "src"))

from pentimento.adapters.llm_factory import build_llm, model_of  # noqa: E402
from pentimento.adapters.solc_adapter import SolcAdapter  # noqa: E402
from pentimento.detection.judge import JudgeVerdict, build_judge_prompt, parse_judge_verdict  # noqa: E402
from pentimento.domain.models import CDVGraph  # noqa: E402
from pentimento.ports.llm import LLMPort  # noqa: E402
from pentimento.services.breadth_pass import run_breadth_pass  # noqa: E402
from pentimento.services.converter import convert  # noqa: E402

GROUND_TRUTH = ROOT / "evals" / "golden" / "detection" / "defivulnlabs_subset.json"
BASELINE = ROOT / "evals" / "golden" / "detection" / "defivulnlabs_baseline.json"

# forge-std's own Test.sol needs a nested ds-test remap too - see scripts/fetch_fixtures.sh's
# own comment on the real "second submodule init pass" gap found running this the first time.
_REMAPPINGS = ["forge-std/=lib/forge-std/src/", "ds-test/=lib/forge-std/lib/ds-test/src/"]


def _resolve_solc() -> str:
    if env_path := os.environ.get("PENTIMENTO_SOLC_PATH"):
        return env_path
    svm_cached = Path.home() / ".svm" / "0.8.24" / "solc-0.8.24"
    if svm_cached.exists():
        return str(svm_cached)
    found = shutil.which("solc")
    if found:
        return found
    print("no solc binary available (set PENTIMENTO_SOLC_PATH, or ~/.svm/0.8.24/solc-0.8.24, or PATH)")
    sys.exit(1)


def _judge_one_case(
    case: dict, llm: LLMPort, model: str, judge_llm: LLMPort, judge_model: str, solc_path: str
) -> JudgeVerdict:
    fixture_path = ROOT / case["fixture_path"]
    project_root = fixture_path.parents[2]  # .../_external/DeFiVulnLabs, fixture is src/test/X.sol
    graph = convert(
        [fixture_path],
        SolcAdapter(solc_path=solc_path),
        project_root=project_root,
        contracts_prefix="src/test/",
        remappings=_REMAPPINGS,
    )
    unit = next((u for u in graph.units if u.contract_name == case["contract_name"]), None)
    if unit is None:
        print(f"    contract {case['contract_name']!r} not found in CDV output — treating as NO_MATCH")
        return JudgeVerdict.NO_MATCH

    # scoped to just the ONE target unit - the fixture file also declares test-helper
    # contracts (ContractTest/Attack/Remediated) that don't need their own breadth-pass call.
    scoped_graph = CDVGraph(generator=graph.generator, units=[unit])
    [result] = run_breadth_pass(scoped_graph, project_root, llm, model=model)

    judge_prompt = build_judge_prompt(case["description"], result.raw_response)
    judge_raw = judge_llm.complete(judge_prompt, model=judge_model)
    return parse_judge_verdict(judge_raw)


def run(llm_spec: str, judge_llm_spec: str, timeout: float, update_baseline: bool) -> int:
    if llm_spec == judge_llm_spec:
        print(
            f"WARNING: --llm and --judge-llm are the literal same spec ({llm_spec!r}) - the "
            "judge is checking the SAME model's own output. Measured finding from durable-"
            "agent reliability research: self-verification dropped saved tasks from 6 to 2 "
            "on the same benchmark. Not a hard error (this may be the only "
            "backend available), but treat any MATCH/NO_MATCH from this run with extra "
            "skepticism until a genuinely different judge is used.",
            file=sys.stderr,
        )

    ground_truth = json.loads(GROUND_TRUTH.read_text())
    solc_path = _resolve_solc()
    llm = build_llm(llm_spec, timeout=timeout)
    model = model_of(llm_spec)
    judge_llm = build_llm(judge_llm_spec, timeout=timeout)
    judge_model = model_of(judge_llm_spec)

    baseline: dict[str, str] = json.loads(BASELINE.read_text()) if BASELINE.exists() else {}
    current: dict[str, str] = {}
    regressions: list[str] = []

    for case in ground_truth["cases"]:
        verdict = _judge_one_case(case, llm, model, judge_llm, judge_model, solc_path)
        current[case["id"]] = verdict.value
        print(f"  [{case['id']}] {verdict.value}")
        if baseline.get(case["id"]) == JudgeVerdict.MATCH.value and verdict != JudgeVerdict.MATCH:
            regressions.append(case["id"])

    if update_baseline:
        BASELINE.write_text(json.dumps(current, indent=2) + "\n")
        print(f"\nbaseline updated: {BASELINE}")

    if regressions:
        print(f"\nREGRESSION: {len(regressions)} case(s) previously MATCHed the baseline, now don't: {regressions}")
        return 1

    matches = sum(1 for v in current.values() if v == JudgeVerdict.MATCH.value)
    print(f"\n{matches}/{len(current)} match, no regression vs baseline")
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--llm", default="claude-cli:haiku", help="Detection 'provider:model' spec.")
    parser.add_argument(
        "--judge-llm",
        default="claude-cli:sonnet",
        help="Judge 'provider:model' spec. Defaults to a DIFFERENT model than --llm's own "
        "default (sonnet vs haiku) to avoid self-verification - see module docstring. A "
        "genuinely different PROVIDER (e.g. deepseek:deepseek-chat) is stronger evidence "
        "still, if a second API key is available.",
    )
    parser.add_argument("--timeout", type=float, default=300.0)
    parser.add_argument("--update-baseline", action="store_true", help="Write current results as the new baseline.")
    args = parser.parse_args()
    sys.exit(run(args.llm, args.judge_llm, args.timeout, args.update_baseline))

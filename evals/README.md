# Golden evals

Two different corpora, don't confuse them:
- `golden/cdv/` — structural-conversion fixtures, checked by the deterministic converter
  (`make evals`). Described below.
- `golden/detection/` — ground-truth vulnerability corpus for the breadth/depth detection
  engine. See `golden/detection/README.md`.

## `golden/cdv/`

`golden/cdv/*.json` — one entry per fixture in `tests/fixtures/`, each declaring the exact
units the converter must produce. Run with `make evals` / `python evals/run_evals.py`.
**100% match required on this set** — everything downstream builds on CDV being right, so
this gate is deliberately strict.

`visibility: "private"` marks a fixture as authored for this project, not sourced from a
public benchmark — same distinction the detection corpus makes between public and private
fixtures, for the same contamination-risk reason. All fixtures here are private by
construction (hand-written, not pulled from CTFBench/DeFiVulnLabs/etc.).

**Canary-string anti-contamination (EVMBench-style) is deliberately NOT applied here.**
That technique detects whether an LLM has *memorized* a benchmark; these fixtures are
checked by a fully deterministic converter (no LLM in the loop at all — conversion is pure
static analysis by design), so there is nothing to memorize. Canary strings are relevant
once LLM-based breadth detectors are being evaluated, which is what `golden/detection/`
and `run_detection_regression.py` are for.

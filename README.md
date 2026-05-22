<p align="center">
  <img src="assets/banner.jpeg" alt="pentimento" width="100%" />
</p>

<h1 align="center">pentimento</h1>

<p align="center">
  <strong>An AI audit pipeline for Solidity: it doesn't just flag a finding, it has to prove it.</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.11--3.13-3776AB?logo=python&logoColor=white" alt="Python" />
  <img src="https://img.shields.io/badge/lint-ruff-261230?logo=ruff&logoColor=white" alt="Ruff" />
  <img src="https://img.shields.io/badge/types-mypy_strict-2A6DB2" alt="mypy" />
  <img src="https://img.shields.io/badge/tests-326%20passing-3fb950" alt="tests" />
  <img src="https://img.shields.io/badge/License-MIT-blue" alt="License: MIT" />
</p>

---

pentimento finds vulnerabilities in Solidity codebases, and it doesn't stop at flagging
them. A candidate finding only ships as confirmed once an adversarial verification protocol
computes a pass on it in code, and — where a proof-of-concept applies — a real, generated
test actually executes and passes. Detection is layered: deterministic, zero-cost signals
run ahead of every LLM call to decide what's worth asking about and how hard to look,
domain-specific checklists activate only when a codebase's own function signatures justify
them, and a confirmed finding is never just a model's word for it.

Before any of that, pentimento resolves what's actually deployed. A `.sol` file boundary
rarely matches a deployed contract's real boundary — proxy and implementation pairs,
diamonds with N facets, factories and the templates they stamp out, dispatcher-proxies with
their extensions — and reasoning about the wrong unit is how audit tooling misses things
that aren't actually subtle. That structural pass — a **Canonical Deploy View (CDV)**, one
unit per deployed contract, every merge and boundary made explicit — is part of the
methodology below, not the whole story: everything downstream, from the cheapest
deterministic check to the most expensive verification call, reads CDV units, never raw
files.

## Structural resolution

The first stage classifies every contract's node type from its ABI and resolves six
structural primitives before any LLM sees the code:

- **Proxy + implementation merge** (EIP-1967).
- **Diamond / facet merge** (EIP-2535), matched by directory proximity, not bare facet name
  — a monorepo can reuse the same facet name across unrelated diamonds.
- **Dispatcher-proxy merge** — a core contract merged with its extension.
- **Factory resolution**, both getter- and event-enumerable.
- **Vault / share-accounting flag** (ERC-4626 shape).
- **Singleton / logical-entity flag**, including counter-based id schemes, while correctly
  leaving true clone factories alone.

Validated against real, independently chosen repositories with genuine production
dependencies and structural quirks — historical incident corpora, multi-facet diamonds
reusing facet names across directories, clone-factory account systems, a real derivatives
protocol with real library dependencies — not just synthetic fixtures. Foundry-style
`remappings.txt` is auto-detected, so external dependencies resolve correctly instead of
exploding into phantom units.

A second converter path resolves the same CDV output directly from a live chain instead of
a repo, reconstructing a protocol's architecture graph from on-chain calldata alone.
Source-based or chain-based, both converge on the identical CDV format.

## Detection: cheap signals narrow expensive reasoning

Deterministic, zero-cost analysis decides *what* to ask an LLM and *how hard* to look,
before every call.

- **Engine Selection Matrix** — a unit's node type and proxy kind are unioned independently
  to pick which threat engines apply and at what depth, before any model call.
- **Guard (consistency) analysis** — for every state variable with three or more writer
  functions, flags the minority that don't share a common guard. No LLM; the anomaly is
  pre-flagged as a candidate for the model.
- **State synchronization analysis** — clusters co-modified state variables, classifies
  each pair as moving together or oppositely, and flags any function touching only one
  side of an established pair.
- **Domain-aware routing** — a cheap regex pre-scan suggests lending/AMM-DEX/yield-vault
  skills from genuine functional co-occurrence; a dedicated, cheap LLM call (signatures
  only) makes the real activate/skip decision, always recorded either way.
- **Model-aware routing** — a structural complexity signal (imports, functions, lines)
  flags dense contracts for automatic escalation to a stronger model.
- **Multi-provider by construction** — one `LLMPort`, one `--llm provider:model` flag:
  your own Claude Code subscription (no API key), the Anthropic API, or any
  OpenAI-compatible provider (DeepSeek, OpenAI, OpenRouter, Groq, Together, xAI, Moonshot,
  self-hosted vLLM).

## Verification: a verdict is computed, never asserted

A surviving finding goes through a structured, adversarial false-positive-check protocol:
Data Flow Analysis → Feasibility Verification (bounds claims require an explicit
constraints-to-proof chain) → Impact Assessment → a PoC sketch → a fixed set of
devil's-advocate questions designed to argue the finding away → six mandatory gates.

The model reports only per-gate pass/fail with a reason. `TRUE_POSITIVE` requires every
gate to pass — the verdict is computed by code, never asserted by the LLM, and a gate the
model never addresses is recorded as an explicit failure. Findings whose shape calls for it
(ambiguous claims, cross-contract paths, race conditions) route to a full deep-verification
pipeline: the same phases as sequential, context-carrying calls, with automatic escalation
to a stronger model when needed.

**Independent jury verification** — an optional second, independent verifier: confirmation
requires both to agree, a single dissent flips the verdict. **Evidence-weighted
confidence** replaces a bare model self-report with a five-tier evidence ladder — an
executed, reproduced PoC outranks everything; self-report alone can only nudge the number,
never dominate it.

## The PoC oracle: code executes the proof, not the model

For a confirmed finding, pentimento asks the model for a complete, compilable Foundry test
— never pseudocode — grounded against a real, already-working test file from the target
project when one exists. The generated test runs for real through `forge test` and is
deleted regardless of outcome. The verdict is `forge`'s own exit code, not the model's word.

## The trust layer

- **Three-way report split** — an industry-standard report separates confirmed
  **Findings** from disclaimed **Leads** (genuinely unresolved) from **Rejected** claims,
  dropped entirely.
- **A blocking human-approval gate** — no final report without an explicit `--approve
  <name>`; approval records a sha256 of the exact report text plus a timestamp.
- **An enforced cost ceiling** — a shared budget wraps any LLM port; once tracked spend
  crosses the ceiling, the next call is refused before it happens.
- **Prompt-injection defense** — a deterministic pre-scan for override language and for
  mimicry of the tool's own prompt-template strings, always on.
- **Secrets never reach untrusted code** — the PoC oracle strips LLM-provider secrets
  before shelling out to a target's `forge test`, and refuses to run at all against a
  project with Foundry's `ffi` cheatcode enabled unless explicitly allowed.
- **A calibration registry, not a marketing number** — every result is hand-verified
  against ground truth by meaning, and flagged stale the moment the code it measured moves on.
- **An automated, judge-based regression gate** for detection quality — a separate LLM call
  semantically judges each run against a growing ground-truth corpus, wired into CI behind
  an explicit opt-in.

## Measured, not asserted

- Matched against a production vault protocol's own official audit, outperforming generic
  static-analysis tooling on the identical scope — including one finding with a working,
  reproduced PoC.
- Three hand-authored, never-published fixtures across three different bug classes, each
  independently proven with a real passing Foundry test before detection ever ran — found
  exactly, correct root cause and fix, every time.
- A cross-project hit on a contract never seen before: a real inverted guard in an
  unrelated real-world audit target, found by the same unmodified pipeline.
- 326 tests, 15/15 structural golden fixtures, strict mypy, clean ruff.

Full methodology and honest scope: [`docs/LIMITATIONS.md`](docs/LIMITATIONS.md).

## Quickstart

```bash
uv venv .venv && source .venv/bin/activate
uv pip install -e ".[dev]"

# self-contained fixture, no external imports:
pentimento cdv tests/fixtures/proxy_impl --out out/cdv --solc ~/.svm/0.8.24/solc-0.8.24

# a real project shape — src/ + remappings.txt at the project root, auto-detected:
pentimento cdv tests/fixtures/with_remapping/src --out out/cdv-remap --solc ~/.svm/0.8.24/solc-0.8.24

cat out/cdv/manifest.json

# convert + run a breadth-pass, one call per unit, results written as markdown.
# --llm picks the backend: your own Claude Code subscription (no API key at all)...
pentimento breadth-pass tests/fixtures/vault --llm claude-cli:haiku --out out/breadth --solc ~/.svm/0.8.24/solc-0.8.24
# ...or any OpenAI-compatible provider's API key (DEEPSEEK_API_KEY/OPENAI_API_KEY/...):
pentimento breadth-pass tests/fixtures/vault --llm deepseek:deepseek-chat --out out/breadth --solc ~/.svm/0.8.24/solc-0.8.24

# scout/strategist: cheap scout everywhere, a deeper (optionally different) model only on
# units the strategist escalates. Omit --strategist-llm to just record escalations.
pentimento investigate tests/fixtures/vault --llm deepseek:deepseek-chat --strategist-llm claude-cli:sonnet --solc ~/.svm/0.8.24/solc-0.8.24
```

Requires a local `solc` binary (never fetched over the network). Point at one with
`--solc <path>`, or let it resolve from `PATH`. For a repo with external dependencies, pass
the *contracts* directory — the project root is inferred as its parent by default, or set
explicitly with `--project-root`; extra remappings via repeatable `--remap prefix=path`.

## Layout

Hexagonal architecture: `src/pentimento/{domain,ports,adapters,services,detection}`.

- `domain/` — CDV structure only, pure functions, no I/O.
- `detection/` — engine selection, prompt-building, every deterministic pre-LLM analyzer.
- `adapters/` — everything touching the outside world: `solc`, `forge`, every LLM backend
  behind the same `LLMPort`.
- `services/` — orchestration: breadth-pass, investigation graph, verification, PoC
  execution, cost ceiling, report assembly.
- `ports/` — the interfaces `services/` depends on and `adapters/` implements.

## Development

```bash
make install         # venv + dev deps
make lint             # ruff + mypy (whole package, strict)
make test             # pytest
make evals            # golden fixtures — must be 100%
make fetch-fixtures   # pulls the external ground-truth corpora into _external/ (gitignored)
```

## License

MIT — see [LICENSE](LICENSE).

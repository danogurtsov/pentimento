# Detection ground-truth corpus

Real, cited, known-vulnerability cases, catalogued so the detection engine has something
real to measure against — not synthetic examples written to make the tool look good.

## What's here

- `defi_vuln_labs.json` — 26 of DeFiVulnLabs' self-contained, SYNTHETIC single-vuln Foundry
  fixtures (public, pinned commit, no LICENSE in that repo — fetched, not vendored). Each
  entry read from source and verified individually, not templated; excluded cases (solc<0.8.0,
  third-party-import-only, live-mainnet-only, no clear consequential bug, or needing an EVM
  version flag the CDV converter doesn't support yet) are named in the file's own
  `source.note` field rather than silently dropped.
- `defi_hack_labs.json` — 8 REAL historically-exploited contracts from DeFiHackLabs
  (Apache-2.0, pinned commit) — the higher-value source, since these are real attacks against
  real deployed code, not planted bugs. Each entry is honestly graded
  `source_richness: high|medium` — some fixtures have a full step-by-step `@Analysis`/`@TX`
  write-up (Euler, Nomad Bridge), others only confirm the exploit's shape from wiring/function
  signatures without an independently re-derived mechanism. 2 candidates (ValueDefi/Cover)
  were dropped entirely rather than guessed at.
- `ctfbench.json` — 7 synthetic-but-scoring-oriented cases (auditdb, LICENSE present) with
  verbatim ground-truth synopsis text quoted directly from source, not paraphrased. **Only
  source with matched clean/vulnerable pairs of the same contract** (`no_errors/` has fixed
  versions of Lending/Voting/Vesting/MerkleDrop) — needed to measure an overreporting rate
  (does the detector wrongly flag the FIXED version too), which none of the other sources
  provide.
- `euler_earn.json` — 14 REAL findings (1 medium + 13 low) from Pashov Audit Group's public
  audit of `euler-xyz/euler-earn` (GPL-2.0, exact review commit pinned), read directly from
  the project's own GitHub repo — full descriptions, code snippets, and two complete
  transcribed Foundry PoCs (read-only-reentrancy fee drain, cross-strategy loss-masking).
  Chosen over a secondhand social-media comparison of the same project specifically because
  it has stronger ground truth: exact commit, full write-ups, acknowledged/fixed status per
  finding, rather than unverified secondhand numbers. See the file's own
  `source.distinct_from_moo9000_comparison` field for the full reasoning.
- `scabench.json` — 10 of ScaBench's 555 real Code4rena/Cantina/Sherlock findings (MIT
  licensed, ships an official Nethermind AuditAgent LLM-based scorer + a GPT-5 baseline per
  project) — one High/Critical finding each from 10 distinct, confirmed-Solidity real DeFi
  projects (fenix-finance, bakerfi, blackhole, kinetiq, virtuals-protocol,
  Uniswap/minimal-delegation, perennial-v2, tally/staker, idle-finance, cork-protocol).
  Dataset stats (31 projects/555 vulns/severity split) verified directly against the fetched
  JSON, not just cited from the repo's README. Not every one of the 555 is Solidity — the
  dataset spans multiple VMs/languages (one candidate project checked, mantra-dex, turned out
  to be Cosmos/CosmWasm and was swapped out) — this catalog only picks confirmed-Solidity
  cases, since that's what `pentimento` itself targets.
- `private_*.json` (+ `private/<name>/` source dirs) — hand-authored fixtures, never
  published anywhere, each with a deliberately inserted bug proven exploitable by a real
  passing Foundry PoC before it's used to measure anything. This is the part of the corpus
  where a detection hit can't be explained by the model having seen the code during
  pretraining — see "Public/private split" below.
- `defivulnlabs_baseline.json` — a captured regression baseline (per-fixture verdicts from a
  real run), used by `evals/run_detection_regression.py` to catch a quality regression on
  future changes, not just a one-off measurement.

## Public/private split

Every public source above carries the same caveat: a model may have seen it during
pretraining, so a recall number measured against it alone is contamination-risked, not proof
of novel-detection capability. The `private_*` fixtures close that gap — each one is
hand-authored, never published, with the planted bug independently proven via a passing
Foundry exploit test before it's used for anything. A hit there can't be explained by
memorization. They're deliberately spread across different bug classes (self-referential
accounting, missing signer deduplication, signature replay) and domains, precisely so a hit
on all of them isn't just one lucky match on one bug shape.

## Why not Ethernaut / Damn Vulnerable DeFi / Capture the Ether

Considered and deliberately dropped. Teaching-CTF repos test whether a *human learning
Solidity* can spot an obvious planted bug in isolation. Credible tools in this space converge
on something else entirely — real exploited code, not teaching examples:

- **Critikal** — SCONE-bench, 405 real DeFiHackLabs exploits.
- **krait** — Foundry PoC patterns sourced from DeFiHackLabs.
- **Cyber-Claude** — a static lookup table of real DeFiHackLabs incidents for grounding.
- **CyberChainBench** — a 541-case benchmark built entirely from real DeFiHackLabs exploits.
- **ScaBench / GiAnt Corpus / bountyforge / LISABench** — all built on real Code4rena/
  Sherlock/Cantina contest data, not synthetic teaching examples.

Teaching CTFs test whether a human can spot a bug someone else already flagged as "the bug
here." Real tools measure themselves against what real attackers actually found in real
deployed code. The corpus should match what's actually being proven, and the field's own
practice says that's the latter.

## Coverage note

ScaBench's remaining 545 vulnerabilities (this catalog uses 10 of 555 as a representative
Solidity sample) plus its official Nethermind AuditAgent scorer stay available in
`_external/scabench/datasets/` for a larger or scorer-driven eval later — not pulled in here
since expanding this further has diminishing returns against actually growing the private,
contamination-free set.

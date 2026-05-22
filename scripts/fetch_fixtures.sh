#!/usr/bin/env bash
# Fetches external ground-truth corpora at a PINNED commit into _external/ (gitignored).
# We never vendor/commit third-party fixture code into this repo — no LICENSE file in
# DeFiVulnLabs, and pinning-by-commit is more honest anyway (reproducible, doesn't silently
# drift). See evals/golden/detection/README.md.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

EXTERNAL_DIR="_external"
mkdir -p "$EXTERNAL_DIR"

fetch() {
  local name="$1" url="$2" commit="$3"
  local dest="$EXTERNAL_DIR/$name"
  if [ -d "$dest" ]; then
    echo "skip $name (already fetched at $(git -C "$dest" rev-parse --short HEAD 2>/dev/null || echo '?'))"
    return
  fi
  echo "fetching $name @ $commit"
  git clone --quiet "$url" "$dest"
  git -C "$dest" checkout --quiet "$commit"
}

# DeFiVulnLabs — 55 self-contained Foundry vuln fixtures, no LICENSE file (do not vendor).
fetch "DeFiVulnLabs" "https://github.com/SunWeb3Sec/DeFiVulnLabs.git" "f61f6ee5c3f89eb7685030647f8df19997596f8b"
# A real gap worth documenting: forge-std is a git submodule (its own .gitmodules), a plain
# `git clone` does NOT check it out, and every fixture needs it (forge-std/Test.sol) to
# compile.
if [ -d "$EXTERNAL_DIR/DeFiVulnLabs" ] && [ ! -f "$EXTERNAL_DIR/DeFiVulnLabs/lib/forge-std/src/Test.sol" ]; then
  echo "initializing DeFiVulnLabs' forge-std submodule (pinned by its own .gitmodules)"
  git -C "$EXTERNAL_DIR/DeFiVulnLabs" submodule update --init lib/forge-std
fi
# forge-std's own Test.sol imports ds-test — a SECOND, nested submodule of forge-std itself,
# not DeFiVulnLabs' own .gitmodules. Recursive init needs an explicit second pass.
if [ -d "$EXTERNAL_DIR/DeFiVulnLabs/lib/forge-std" ] && [ ! -f "$EXTERNAL_DIR/DeFiVulnLabs/lib/forge-std/lib/ds-test/src/test.sol" ]; then
  echo "initializing forge-std's own nested ds-test submodule"
  git -C "$EXTERNAL_DIR/DeFiVulnLabs/lib/forge-std" submodule update --init lib/ds-test
fi

# Teaching-CTF repos (Ethernaut/Damn Vulnerable DeFi/Capture the Ether) are deliberately NOT
# used here: they test whether a human learning Solidity can spot an obvious planted bug in
# isolation. Real tools measure themselves against what real attackers actually found in
# real deployed code — DeFiHackLabs + real contest data instead.

# DeFiHackLabs — real, historically exploited contracts, Foundry fork-based PoC with exact
# block numbers, Apache-2.0 licensed.
fetch "DeFiHackLabs" "https://github.com/SunWeb3Sec/DeFiHackLabs.git" "3736721a2859fb21b79fc32adaae8dd2d556d9a0"
# forge-std is a real git submodule of DeFiHackLabs (pinned in its own .gitmodules) — a
# plain `git clone` above does NOT check it out; every exploit file needs it (forge-std/
# Test.sol) to even compile. Only initialize it if the parent fetch actually just ran.
if [ -d "$EXTERNAL_DIR/DeFiHackLabs" ] && [ ! -f "$EXTERNAL_DIR/DeFiHackLabs/lib/forge-std/src/Test.sol" ]; then
  echo "initializing DeFiHackLabs' forge-std submodule (pinned by its own .gitmodules)"
  git -C "$EXTERNAL_DIR/DeFiHackLabs" submodule update --init lib/forge-std
fi

# CTFBench — synthetic-but-scoring-oriented, NOT a teaching CTF: purpose-built for tool
# scoring (VDR + Overreporting Index), actively used by real commercial tools (Savant Chat).
fetch "ctfbench" "https://github.com/auditdbio/ctfbench.git" "766b399b8932608055678102604542c0698066c6"

# EulerEarn — real, small, production Solidity project with an official public Pashov Audit
# Group report straight from the project's own repo (14 findings, catalogued in full in
# evals/golden/detection/euler_earn.json). Pinned at the exact commit Pashov reviewed, not
# HEAD, so the fetched code matches every finding's line numbers/behaviour exactly.
fetch "euler-earn" "https://github.com/euler-xyz/euler-earn.git" "12c0220226cdefc8fee2f229c5e75bd656c7b2b5"
if [ -d "$EXTERNAL_DIR/euler-earn" ] && [ ! -f "$EXTERNAL_DIR/euler-earn/lib/forge-std/src/Test.sol" ]; then
  echo "initializing euler-earn's git submodules (forge-std/openzeppelin-contracts/erc4626-tests/ethereum-vault-connector/euler-vault-kit)"
  git -C "$EXTERNAL_DIR/euler-earn" submodule update --init --recursive
fi

# ScaBench (Nethermind/Bernhard Mueller) — 555 real vulnerabilities from 31 Code4rena/
# Cantina/Sherlock contest projects, MIT licensed, ships an official LLM-based scorer.
# Catalogued as a 10-case representative sample in evals/golden/detection/scabench.json
# (the dataset spans multiple VMs, not just Solidity; this repo only fetches ScaBench's OWN
# dataset/scorer code, never the 31 target projects themselves — those stay a citation, not
# a vendored fixture).
fetch "scabench" "https://github.com/scabench-org/scabench.git" "eec0020939a47bbc06a98a7348a90908b96f4b4d"

# ScaBench TARGET projects — a generalization test: does the detection pipeline (built and
# repeatedly validated against EulerEarn alone) find anything real on genuinely DIFFERENT
# real projects it has never seen? Two of the 10 catalogued scabench.json cases, picked for
# exact pinned commits (not "main") and low build-friction:
fetch "scabench-blackhole" "https://github.com/code-423n4/2025-05-blackhole.git" "92fff849d3b266e609e6d63478c4164d9f608e91"
fetch "scabench-minimal-delegation" "https://github.com/Uniswap/minimal-delegation.git" "732247c5e3146b9340cb29e0f2b8f9e2f1df67a4"

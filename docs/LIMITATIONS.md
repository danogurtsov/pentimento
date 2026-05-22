# Scope and limitations

Every number below is real and reproducible from `evals/calibration_registry.json` and
`evals/golden/detection/`. This file exists so a claim in the README is never taken on
faith — including the parts that don't make it sound better.

## Sample sizes are small, and stated as such

Every live measurement in this project is n=1 to n=6 per condition. The 14-finding
production-vault comparison is one project. The 3 contamination-free private fixtures are
one bug class each, all authored by the same person, which means they may share
unconscious structural tells a fourth fixture from a genuinely different author would
expose. The prompt-fix A/B test for the self-transfer miss (see below) ran 6 trials per
condition: old prompt 3/6 (50.0%), new prompt 5/6 (83.3%), a 33.3pp difference whose 95%
confidence interval is [-16.6pp, +83.2pp] — it covers zero. Directionally encouraging, not
statistically significant. A rough power calculation puts the trial count needed for
significance at this effect size around 27-28 per condition, which hasn't been run. None of
this is rounded up to "proven" anywhere in this repo.

## Public corpora carry contamination risk

Every ground-truth case sourced from a public repository (DeFiVulnLabs, DeFiHackLabs,
ScaBench, CTFBench, the production-vault audit) may have been seen by a model during
pretraining. A hit against one of them is evidence the tool didn't refuse the answer, not
proof of novel reasoning. The private, hand-authored fixtures close that specific gap, but
only for the bug classes they cover (self-referential accounting, missing signer dedup,
signature replay) — they say nothing about detection quality on bug classes not yet
represented in that set.

## A known, reproduced, honestly-characterized miss

A same-slot double-write bug (two transfer parameters happening to be equal, causing a
stale read to corrupt a balance) was missed on one DeFiVulnLabs fixture. Root-caused by
running detection twice on the identical contract: one run correctly traced that both reads
happen before either write; the other assumed the far more common sequential
subtract-then-add shape and concluded, incorrectly for this contract's actual ordering,
that the operations cancel out. The judge itself was checked and cleared — re-run three
times against the wrong transcript, it correctly said NO_MATCH every time. The miss is real
detection-model reasoning inconsistency, not a harness or judge bug, and the existing
complexity-based model-escalation heuristic would never catch it (the contract is five
lines). A checklist item targeting the exact aliasing mechanism was added and measured (see
the A/B result above) but the fix is not proven at the sample size run so far.

## LLM-judge independence is partial, not complete

The regression harness's default judge model is now a stronger model in the same model
family as the default detector, not the literal same model (which was the previous
default, and is exactly the self-verification anti-pattern this change targets — a
same-model judge inflates its own agreement rate for reasons that don't show up on any
dashboard). True cross-family independence, using a genuinely different provider, is
supported via a CLI flag but not the default, since no second provider's API key is
configured in this environment. `run()` warns explicitly whenever `--llm` and `--judge-llm`
resolve to the identical spec.

## The verification protocol has an unbuilt half

The adapted fp-check protocol's "Deep" path (full multi-phase orchestration for ambiguous,
cross-contract, or race-condition-shaped claims) is implemented and does execute end to
end, with automatic escalation to a stronger model when a cheaper model fails to produce a
parseable gate verdict on a first attempt. What's not built: a second, independent
differential-PoC check (auto-applying a proposed fix to a clean copy and confirming the
same PoC test then fails) — only the "does it reproduce against the currently
vulnerable code" half of a true differential PoC exists.

## No central model gateway

Every LLM adapter calls its provider directly; there is no gateway process enforcing
budgets or caching centrally. The cost-ceiling circuit breaker wraps whatever port a caller
already has and reads cost from an attribute only the Claude CLI adapter currently exposes
— wrapping a different adapter without that attribute still works, it just can't be
enforced against, and the budget check is a circuit breaker (checked after each call
completes), not a real-time preemptive limit. One call's worth of overshoot past the
ceiling is possible by design.

## Prompt-injection resistance is layered but not exhaustive

A deterministic pre-scan catches imperative override language and structural mimicry of
this tool's own prompt-template strings. It's grounded in the two attack styles actually
tested against it; a more evasive attacker avoiding both exact override phrasing and any
literal substring of the prompt template's own headers would not trip these specific
patterns. This is additive defense on top of whatever resistance the underlying model
already has from training, not a claim of complete coverage.

## Structural resolution has named, unfixed edges

A true clone-factory contract (`Clones.clone()`, assembly-only, no `new` keyword) is
invisible to the factory-resolution primitive itself, not just correctly excluded from
singleton detection. Diamond facet detection is name-pattern-based; a real diamond whose
facets don't use a `Facet` naming convention at all is missed entirely. Both are documented
in the relevant module rather than silently assumed away.

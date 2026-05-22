"""
Evidence-weighted confidence — replaces "trust the number the model wrote about itself"
with a value COMPUTED BY CODE from the strongest evidence this project's own pipeline
already gathered for a finding. Grounded directly in two named patterns from the AI
bug-finder landscape: EllipticZero ("confidence is a function of evidence count, not LLM
self-report") and Critikal's own evidence-weighted formula (`[POC-PASS]=1.0` /
`[LLM-ONLY]=0.2`, blended `Ev*0.4+Cons*0.3+LLM*0.3`).

Adapted to what this project's own pipeline actually produces today — no multi-model
consensus SIGNAL feeding this formula yet (that's `detection/verdict.py`'s own
`compute_jury_verdict`, a separate mechanism that decides the verdict itself, not a
confidence input) — so this is a 2-term blend, not Critikal's 3-term one: the evidence tier
is the DOMINANT term (80%), the model's own self-reported confidence is a minor modulator
(20%), never the other way around, since self-report alone is explicitly the WEAKEST tier in
this same formula.

Never REPLACES `Finding.confidence` (the model's own self-report stays visible, labeled as
such — see `detection/report.py`'s "model self-report" caption). This is an INDEPENDENT,
additional number, computed purely from what actually happened during verification/PoC,
rendered alongside it — a pure function, no LLM call, no I/O.
"""
from __future__ import annotations

from dataclasses import dataclass

from pentimento.detection.findings import Finding
from pentimento.detection.poc_verdict import PoCOutcome
from pentimento.detection.verdict import FindingVerdict, Verdict

# Base score (0.0-1.0) per evidence tier, strongest first. Each tier requires the
# CORRESPONDING pipeline stage to have actually run — a finding never independently
# verified at all falls to the weakest tier, matching Critikal's own `[LLM-ONLY]=0.2`.
_TIER_POC_REPRODUCED = ("poc_reproduced", 0.95)
_TIER_POC_NOT_REPRODUCED = ("poc_not_reproduced", 0.10)  # real, executed evidence AGAINST
_TIER_VERIFIED_TRUE_POSITIVE = ("verified_true_positive", 0.70)
_TIER_VERIFIED_FALSE_POSITIVE = ("verified_false_positive", 0.05)
_TIER_UNVERIFIED = ("unverified_llm_self_report_only", 0.20)

_EVIDENCE_WEIGHT = 0.8
_SELF_REPORT_WEIGHT = 0.2


@dataclass(frozen=True)
class EvidenceConfidence:
    score: float  # 0-100, code-computed
    tier: str
    basis: str


def compute_evidence_confidence(
    finding: Finding,
    verdict: FindingVerdict | None,
    poc_outcome: PoCOutcome | None,
) -> EvidenceConfidence:
    """The dominant term is always the STRONGEST evidence tier this finding's own pipeline
    run actually reached — a real executed PoC outcome (if one ran) always overrides a
    gate-review-only verdict, which always overrides no verification at all. `COMPILE_ERROR`
    and `REFUSED_UNTRUSTED_FFI` are deliberately NOT special-cased here — same "inconclusive,
    not evidence either way" philosophy as `poc_verdict.py` itself — they fall through to
    whatever the verification-only tier already resolves to, exactly as if no PoC had run.
    The model's own self-reported confidence only ever nudges the final score by up to
    `_SELF_REPORT_WEIGHT` of its own 0-100 value — it can shade the number, never dominate
    it."""
    if poc_outcome == PoCOutcome.REPRODUCED:
        tier, base = _TIER_POC_REPRODUCED
        basis = "a real, executed forge test reproduced the exploit (Level 1 deterministic PoC oracle)"
    elif poc_outcome == PoCOutcome.NOT_REPRODUCED:
        tier, base = _TIER_POC_NOT_REPRODUCED
        basis = "a real, executed forge test did NOT reproduce the exploit — direct evidence against the claim"
    elif verdict is not None and verdict.verdict == Verdict.TRUE_POSITIVE:
        tier, base = _TIER_VERIFIED_TRUE_POSITIVE
        basis = "Standard-path verification (Trail of Bits fp-check) passed all gates, no executed PoC ran"
    elif verdict is not None and verdict.verdict == Verdict.FALSE_POSITIVE:
        tier, base = _TIER_VERIFIED_FALSE_POSITIVE
        basis = "Standard-path verification actively rejected this finding"
    else:
        tier, base = _TIER_UNVERIFIED
        basis = "never independently verified this run — the scout model's own unchecked self-report"

    score = (base * 100 * _EVIDENCE_WEIGHT) + (finding.confidence * _SELF_REPORT_WEIGHT)
    return EvidenceConfidence(score=round(score, 1), tier=tier, basis=basis)

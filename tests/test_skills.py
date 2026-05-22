from pentimento.detection.domain_signals import DomainId
from pentimento.detection.skills import all_skill_ids, skill_for


def test_all_three_first_slice_domains_have_a_registered_skill() -> None:
    ids = all_skill_ids()
    assert set(ids) == {DomainId.LENDING, DomainId.AMM_DEX, DomainId.YIELD_VAULT}


def test_skill_for_returns_a_non_empty_grounded_checklist() -> None:
    skill = skill_for(DomainId.YIELD_VAULT)
    assert skill.domain == DomainId.YIELD_VAULT
    assert len(skill.checklist) >= 3
    # grounded in this repo's own real ground-truth corpus, not invented - see skills.py's
    # own module docstring.
    assert any("EulerEarn" in item for item in skill.checklist)

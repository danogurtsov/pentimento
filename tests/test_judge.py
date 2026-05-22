from pentimento.detection.judge import JudgeVerdict, build_judge_prompt, parse_judge_verdict


def test_prompt_includes_ground_truth_and_response() -> None:
    prompt = build_judge_prompt("EtherStore is vulnerable to reentrancy.", "### [F-1] Reentrancy")
    assert "EtherStore is vulnerable to reentrancy." in prompt
    assert "### [F-1] Reentrancy" in prompt
    assert "JUDGE_VERDICT: MATCH|NO_MATCH" in prompt


def test_parses_match() -> None:
    assert parse_judge_verdict("Some reasoning.\nJUDGE_VERDICT: MATCH") == JudgeVerdict.MATCH


def test_parses_no_match() -> None:
    assert parse_judge_verdict("JUDGE_VERDICT: NO_MATCH") == JudgeVerdict.NO_MATCH


def test_case_insensitive() -> None:
    assert parse_judge_verdict("judge_verdict: match") == JudgeVerdict.MATCH


def test_unparseable_response_is_recorded_honestly_not_coerced() -> None:
    assert parse_judge_verdict("I'm not sure how to answer that.") == JudgeVerdict.UNPARSEABLE

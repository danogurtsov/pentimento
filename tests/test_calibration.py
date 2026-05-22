from pentimento.detection.calibration import CalibrationEntry, is_stale, render_registry


def _entry(**overrides) -> CalibrationEntry:
    defaults = dict(
        corpus="euler_earn",
        component="breadth_pass",
        model="deepseek:deepseek-chat",
        date="2026-09-03",
        commit="abc123def456",
        result="2/14 recall",
        methodology_ref="README.md",
        note="",
    )
    defaults.update(overrides)
    return CalibrationEntry(**defaults)


def test_an_entry_measured_at_the_current_commit_is_not_stale() -> None:
    entry = _entry(commit="abc123def456")
    assert is_stale(entry, "abc123def456") is False


def test_an_entry_measured_at_an_older_commit_is_stale() -> None:
    entry = _entry(commit="abc123def456")
    assert is_stale(entry, "different999commit") is True


def test_an_empty_current_commit_never_marks_anything_stale() -> None:
    # git unavailable / not a checkout - "can't tell" is not the same as "not stale".
    entry = _entry(commit="abc123def456")
    assert is_stale(entry, "") is False


def test_render_registry_marks_a_stale_entry_explicitly() -> None:
    entry = _entry(commit="old-commit")
    report = render_registry([entry], "new-commit")
    assert "[STALE" in report


def test_render_registry_does_not_mark_a_current_entry() -> None:
    entry = _entry(commit="same-commit")
    report = render_registry([entry], "same-commit")
    assert "[STALE" not in report


def test_render_registry_includes_all_fields() -> None:
    entry = _entry(note="a real caveat")
    report = render_registry([entry], "same-commit")

    assert "euler_earn / breadth_pass" in report
    assert "deepseek:deepseek-chat" in report
    assert "2026-09-03" in report
    assert "2/14 recall" in report
    assert "README.md" in report
    assert "a real caveat" in report


def test_render_registry_omits_the_note_line_when_there_is_none() -> None:
    entry = _entry(note="")
    report = render_registry([entry], "same-commit")
    assert "Note:" not in report

from pathlib import Path

from pentimento.detection.ffi_check import foundry_toml_has_ffi


def test_no_foundry_toml_is_not_flagged(tmp_path: Path) -> None:
    assert foundry_toml_has_ffi(tmp_path) is False


def test_default_profile_ffi_true_is_flagged(tmp_path: Path) -> None:
    (tmp_path / "foundry.toml").write_text("[profile.default]\nffi = true\n")
    assert foundry_toml_has_ffi(tmp_path) is True


def test_ffi_false_or_absent_is_not_flagged(tmp_path: Path) -> None:
    (tmp_path / "foundry.toml").write_text('[profile.default]\nsrc = "src"\nffi = false\n')
    assert foundry_toml_has_ffi(tmp_path) is False


def test_ffi_true_under_a_non_default_profile_is_still_flagged(tmp_path: Path) -> None:
    # real shape from scabench's minimal-delegation foundry.toml - ffi=true can live under
    # a profile that isn't [profile.default], and FOUNDRY_PROFILE can retarget which one
    # is active - conservative check by design.
    (tmp_path / "foundry.toml").write_text(
        "[profile.default]\nsrc = \"src\"\n\n[profile.ci]\nffi = true\n"
    )
    assert foundry_toml_has_ffi(tmp_path) is True


def test_unparseable_toml_is_treated_as_absent_not_an_error(tmp_path: Path) -> None:
    (tmp_path / "foundry.toml").write_text("this is not valid [[[ toml")
    assert foundry_toml_has_ffi(tmp_path) is False

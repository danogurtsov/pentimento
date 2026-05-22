from pathlib import Path

from pentimento.adapters.remappings import load_remappings


def test_returns_empty_list_when_no_remappings_file(tmp_path: Path) -> None:
    assert load_remappings(tmp_path) == []


def test_parses_remappings_file(tmp_path: Path) -> None:
    (tmp_path / "remappings.txt").write_text(
        "@openzeppelin/=lib/openzeppelin-contracts/\nforge-std/=lib/forge-std/src/\n"
    )
    assert load_remappings(tmp_path) == [
        "@openzeppelin/=lib/openzeppelin-contracts/",
        "forge-std/=lib/forge-std/src/",
    ]


def test_skips_comments_and_blank_lines(tmp_path: Path) -> None:
    (tmp_path / "remappings.txt").write_text("# a comment\n\nlib/=vendor/\n   \n")
    assert load_remappings(tmp_path) == ["lib/=vendor/"]

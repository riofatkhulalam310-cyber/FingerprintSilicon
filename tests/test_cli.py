"""Test untuk CLI (`silicon ...`)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from siliconfingerprint.cli import main


@pytest.fixture
def sample_png(tmp_path: Path) -> Path:
    f = tmp_path / "sample.png"
    f.write_bytes(
        b"\x89PNG\r\n\x1a\n" b"prompt: a cat astronaut, stable diffusion, cfg scale 7"
    )
    return f


def test_scan_command(capsys, sample_png: Path) -> None:
    exit_code = main(["scan", str(sample_png)])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "SiliconFingerprint" in out
    assert "Kesimpulan" in out


def test_explain_command(capsys, sample_png: Path) -> None:
    exit_code = main(["explain", str(sample_png)])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "Catatan penting" in out


def test_report_json_command(capsys, sample_png: Path) -> None:
    exit_code = main(["report", str(sample_png), "--format", "json"])
    out = capsys.readouterr().out
    assert exit_code == 0
    parsed = json.loads(out)
    assert parsed["file"]["name"] == "sample.png"
    assert "c2pa" in parsed


def test_report_html_to_file(tmp_path: Path, sample_png: Path) -> None:
    output = tmp_path / "report.html"
    exit_code = main(["report", str(sample_png), "--format", "html", "--output", str(output)])
    assert exit_code == 0
    assert output.exists()
    assert "<html" in output.read_text(encoding="utf-8")


def test_c2pa_command_json(capsys, sample_png: Path) -> None:
    exit_code = main(["c2pa", str(sample_png), "--json"])
    out = capsys.readouterr().out
    assert exit_code == 0
    parsed = json.loads(out)
    assert "has_manifest" in parsed


def test_batch_command(capsys, tmp_path: Path, sample_png: Path) -> None:
    exit_code = main(["batch", str(tmp_path)])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "sample.png" in out


def test_doctor_command(capsys) -> None:
    exit_code = main(["doctor"])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "Python" in out
    assert "c2pa-python" in out


def test_scan_missing_file_returns_error(capsys, tmp_path: Path) -> None:
    exit_code = main(["scan", str(tmp_path / "tidak_ada.png")])
    err = capsys.readouterr().err
    assert exit_code == 1
    assert "Error" in err


def test_no_command_prints_help(capsys) -> None:
    exit_code = main([])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "usage" in out.lower()

from pathlib import Path
from unittest.mock import patch

from siliconfingerprint import analyzer
from siliconfingerprint.analyzer import analyze_file
from siliconfingerprint.c2pa_verify import C2paResult


def test_analyze_text_like_fixture(tmp_path: Path) -> None:
    sample = tmp_path / "sample.png"
    sample.write_bytes(
        b"\x89PNG\r\n\x1a\n"
        b"prompt: futuristic city, cinematic lighting, stable diffusion, cfg scale 7"
    )

    result = analyze_file(sample)

    assert result.file_name == "sample.png"
    assert result.sha256
    assert result.findings
    assert result.raw_signals["generator_hits"]


def test_analyze_includes_c2pa_field_even_without_manifest(tmp_path: Path) -> None:
    sample = tmp_path / "plain.png"
    sample.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 32)

    result = analyze_file(sample)

    assert "checked" in result.c2pa
    assert any(f.category == "c2pa" for f in result.findings)


def test_filename_keywords_do_not_trigger_false_generator_hits(tmp_path: Path) -> None:
    # Regresi: nama file pengguna sendiri (mis. mengandung "midjourney" atau
    # "c2pa") tidak boleh memicu deteksi generator -- hanya isi/metadata asli
    # yang relevan. Lihat _strip_filename_fields di analyzer.py.
    sample = tmp_path / "foto_midjourney_party_c2pa.png"
    sample.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 32)

    result = analyze_file(sample)

    assert result.raw_signals["generator_hits"] == {}


def test_valid_ai_c2pa_manifest_forces_high_confidence(tmp_path: Path) -> None:
    sample = tmp_path / "ai_generated.png"
    sample.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 32)

    fake_result = C2paResult(
        checked=True,
        has_manifest=True,
        is_valid=True,
        claim_generator="Adobe Firefly",
        digital_source_type="trainedAlgorithmicMedia",
        note="ok",
    )

    with patch.object(analyzer, "verify_c2pa", return_value=fake_result):
        result = analyze_file(sample)

    assert result.confidence == "tinggi"
    assert "terverifikasi" in result.summary.lower()


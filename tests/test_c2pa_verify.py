"""Test untuk modul verifikasi C2PA.

Membuat manifest C2PA sungguhan butuh sertifikat/signer aktif, jadi di sini
kita mock ``c2pa.Reader`` untuk menyimulasikan tiga kondisi nyata: tidak ada
manifest, manifest valid dengan sumber AI, dan manifest yang gagal validasi.
Ini standar untuk menguji kode yang membungkus library eksternal bertanda
tangan kriptografis tanpa perlu infrastruktur PKI di test suite.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from siliconfingerprint import c2pa_verify


@pytest.fixture
def real_file(tmp_path: Path) -> Path:
    # File asli (bukan hanya path) supaya pengecekan exists()/is_file() lolos.
    f = tmp_path / "sample.png"
    f.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 32)
    return f


def test_verify_c2pa_missing_file_short_circuits(tmp_path: Path) -> None:
    result = c2pa_verify.verify_c2pa(tmp_path / "tidak_ada.png")
    assert result.checked is False
    assert result.has_manifest is False
    assert "tidak ditemukan" in result.note.lower()


def test_verify_c2pa_unavailable_library(real_file: Path) -> None:
    with patch.object(c2pa_verify, "C2PA_AVAILABLE", False):
        result = c2pa_verify.verify_c2pa(real_file)
    assert result.checked is False
    assert result.has_manifest is False
    assert "tidak terpasang" in result.note.lower()


def test_verify_c2pa_no_manifest_found(real_file: Path) -> None:
    class FakeManifestNotFound(Exception):
        pass

    FakeManifestNotFound.__name__ = "_C2paManifestNotFound"

    fake_c2pa = MagicMock()
    fake_c2pa.Reader.side_effect = FakeManifestNotFound("manifest could not be found")

    with patch.object(c2pa_verify, "c2pa", fake_c2pa), patch.object(
        c2pa_verify, "C2PA_AVAILABLE", True
    ):
        result = c2pa_verify.verify_c2pa(real_file)

    assert result.checked is True
    assert result.has_manifest is False
    assert "tidak ada content credentials" in result.note.lower()


def test_verify_c2pa_valid_manifest_with_ai_source(real_file: Path) -> None:
    manifest_store = {
        "active_manifest": "urn:c2pa:abc123",
        "manifests": {
            "urn:c2pa:abc123": {
                "claim_generator": "Adobe Firefly 3.0",
                "signature_info": {
                    "issuer": "Adobe Inc.",
                    "time": "2026-01-01T00:00:00Z",
                    "alg": "es256",
                },
                "assertions": [
                    {
                        "label": "c2pa.actions",
                        "data": {"digitalSourceType": "trainedAlgorithmicMedia"},
                    }
                ],
                "ingredients": [],
            }
        },
        "validation_status": [],
    }

    fake_reader_instance = MagicMock()
    fake_reader_instance.json.return_value = json.dumps(manifest_store)
    fake_reader_instance.__enter__.return_value = fake_reader_instance
    fake_reader_instance.__exit__.return_value = False

    fake_c2pa = MagicMock()
    fake_c2pa.Reader.return_value = fake_reader_instance

    with patch.object(c2pa_verify, "c2pa", fake_c2pa), patch.object(
        c2pa_verify, "C2PA_AVAILABLE", True
    ):
        result = c2pa_verify.verify_c2pa(real_file)

    assert result.checked is True
    assert result.has_manifest is True
    assert result.is_valid is True
    assert result.claim_generator == "Adobe Firefly 3.0"
    assert result.digital_source_type == "trainedAlgorithmicMedia"
    assert result.validation_errors == []


def test_verify_c2pa_invalid_signature(real_file: Path) -> None:
    manifest_store = {
        "active_manifest": "urn:c2pa:abc123",
        "manifests": {
            "urn:c2pa:abc123": {
                "claim_generator": "Unknown Tool",
                "signature_info": {},
                "assertions": [],
                "ingredients": [],
            }
        },
        "validation_status": [
            {"code": "signingCredential.expired", "explanation": "Sertifikat sudah kedaluwarsa"}
        ],
    }

    fake_reader_instance = MagicMock()
    fake_reader_instance.json.return_value = json.dumps(manifest_store)
    fake_reader_instance.__enter__.return_value = fake_reader_instance
    fake_reader_instance.__exit__.return_value = False

    fake_c2pa = MagicMock()
    fake_c2pa.Reader.return_value = fake_reader_instance

    with patch.object(c2pa_verify, "c2pa", fake_c2pa), patch.object(
        c2pa_verify, "C2PA_AVAILABLE", True
    ):
        result = c2pa_verify.verify_c2pa(real_file)

    assert result.has_manifest is True
    assert result.is_valid is False
    assert result.validation_errors
    assert "kedaluwarsa" in result.validation_errors[0].lower()


def test_verify_c2pa_never_raises_on_unexpected_error(real_file: Path) -> None:
    fake_c2pa = MagicMock()
    fake_c2pa.Reader.side_effect = RuntimeError("boom")

    with patch.object(c2pa_verify, "c2pa", fake_c2pa), patch.object(
        c2pa_verify, "C2PA_AVAILABLE", True
    ):
        result = c2pa_verify.verify_c2pa(real_file)  # tidak boleh melempar exception

    assert result.checked is True
    assert result.has_manifest is False

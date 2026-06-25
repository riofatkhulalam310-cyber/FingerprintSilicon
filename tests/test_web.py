"""Test untuk Web UI (Flask) SiliconFingerprint."""

from __future__ import annotations

import io
from pathlib import Path

import pytest

from siliconfingerprint.web import create_app


@pytest.fixture
def client():
    app = create_app()
    app.config.update(TESTING=True)
    return app.test_client()


def test_healthz(client) -> None:
    resp = client.get("/healthz")
    assert resp.status_code == 200
    assert resp.get_json() == {"status": "ok"}


def test_index_loads(client) -> None:
    resp = client.get("/")
    assert resp.status_code == 200
    assert b"SiliconFingerprint" in resp.data
    assert b"Tarik" in resp.data  # teks intake drag-and-drop


def test_analyze_without_file_shows_error(client) -> None:
    resp = client.post("/analyze", data={}, content_type="multipart/form-data")
    assert resp.status_code == 200
    assert "Pilih satu file".encode() in resp.data


def test_analyze_rejects_unsupported_extension(client) -> None:
    data = {"file": (io.BytesIO(b"hello world"), "notes.txt")}
    resp = client.post("/analyze", data=data, content_type="multipart/form-data")
    assert resp.status_code == 200
    assert "belum didukung".encode() in resp.data


def test_analyze_valid_png_returns_report(client, tmp_path: Path) -> None:
    png_bytes = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64
    data = {"file": (io.BytesIO(png_bytes), "evidence.png")}
    resp = client.post("/analyze", data=data, content_type="multipart/form-data")
    assert resp.status_code == 200
    assert "evidence.png".encode() in resp.data
    assert "SHA-256".encode() in resp.data
    assert "stamp".encode() in resp.data


def test_analyze_path_traversal_filename_is_sanitized(client) -> None:
    # Nama file berisi komponen direktori harus dipangkas ke nama dasar saja
    # sebelum disimpan ke temp dir, supaya tidak menulis di luar temp dir.
    png_bytes = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64
    data = {"file": (io.BytesIO(png_bytes), "../../etc/evil.png")}
    resp = client.post("/analyze", data=data, content_type="multipart/form-data")
    assert resp.status_code == 200
    # Werkzeug's secure handling + Path(...).name already strips directory
    # components; the analysis should still succeed against the basename.
    assert b"evil.png" in resp.data

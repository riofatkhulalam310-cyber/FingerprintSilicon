"""Web UI lokal untuk SiliconFingerprint.

Single-page Flask app: upload satu file gambar/video, lihat hasil analisis
(termasuk verifikasi C2PA) dalam tampilan "laporan kasus". Tidak ada
database -- setiap analisis berjalan langsung di memori/temp dir dan tidak
disimpan setelah proses selesai. Cocok untuk demo lokal atau dijalankan di
jaringan internal perusahaan; bukan untuk dipublikasikan ke internet
terbuka tanpa hardening tambahan (lihat README bagian Web UI).
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from flask import Flask, render_template, request

from .analyzer import analyze_file

ALLOWED_EXTENSIONS = {
    ".jpg",
    ".jpeg",
    ".png",
    ".webp",
    ".gif",
    ".bmp",
    ".tiff",
    ".mp4",
    ".mov",
    ".mkv",
    ".webm",
}
MAX_UPLOAD_BYTES = 50 * 1024 * 1024  # 50 MB - cukup untuk demo, bukan batch besar


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_BYTES

    @app.get("/")
    def index():
        return render_template("index.html", result=None, error=None)

    @app.post("/analyze")
    def analyze():
        uploaded = request.files.get("file")
        if uploaded is None or uploaded.filename == "":
            return render_template(
                "index.html", result=None, error="Pilih satu file terlebih dahulu."
            )

        suffix = Path(uploaded.filename).suffix.lower()
        if suffix not in ALLOWED_EXTENSIONS:
            return render_template(
                "index.html",
                result=None,
                error=(
                    f"Tipe file `{suffix or '(tanpa ekstensi)'}` belum didukung. "
                    f"Format yang didukung: {', '.join(sorted(ALLOWED_EXTENSIONS))}"
                ),
            )

        with tempfile.TemporaryDirectory(prefix="siliconfingerprint_") as tmp_dir:
            safe_name = Path(uploaded.filename).name  # buang komponen direktori
            tmp_path = Path(tmp_dir) / safe_name
            uploaded.save(tmp_path)
            try:
                result = analyze_file(tmp_path)
            except Exception as exc:  # tampilkan error dengan ramah, jangan 500 polos
                return render_template(
                    "index.html",
                    result=None,
                    error=f"Gagal menganalisis file: {exc}",
                )

        return render_template("index.html", result=result, error=None)

    @app.get("/healthz")
    def healthz():
        return {"status": "ok"}

    return app


def run_dev_server(host: str = "127.0.0.1", port: int = 5000, debug: bool = False) -> None:
    """Jalankan server pengembangan Flask. Hanya untuk demo/penggunaan lokal."""
    app = create_app()
    app.run(host=host, port=port, debug=debug)

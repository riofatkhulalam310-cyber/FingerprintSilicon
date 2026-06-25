"""Verifikasi Content Credentials (C2PA) untuk file media.

C2PA adalah standar kriptografis (didukung Adobe, OpenAI, Google, Microsoft,
dkk.) yang menyematkan manifest tertanda di dalam file untuk mencatat asal
dan riwayat edit media. Berbeda dari deteksi berbasis kata kunci di
``analyzer.py``, hasil dari modul ini adalah verifikasi ya/tidak yang
didukung tanda tangan digital -- bukan tebakan berbasis pola teks.

Catatan jujur soal batasan:
- Hanya berlaku jika generator/editor menyematkan manifest C2PA. Banyak
  pipeline Stable Diffusion lokal (A1111, ComfyUI) TIDAK menyematkan C2PA.
- Metadata C2PA bisa dihapus dengan mudah (strip metadata), jadi tidak
  adanya manifest BUKAN bukti bahwa media itu asli/bukan AI.
- Validitas tanda tangan menunjukkan manifest tidak diubah sejak ditanda
  tangani, bukan bahwa konten di dalamnya benar atau tidak menyesatkan.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    import c2pa

    C2PA_AVAILABLE = True
except Exception:  # pragma: no cover - import guard
    c2pa = None  # type: ignore[assignment]
    C2PA_AVAILABLE = False


@dataclass
class C2paResult:
    """Hasil pemeriksaan Content Credentials pada satu file."""

    checked: bool
    has_manifest: bool
    is_valid: "bool | None" = None
    claim_generator: "str | None" = None
    signature_info: dict[str, Any] = field(default_factory=dict)
    assertions: list[dict[str, Any]] = field(default_factory=list)
    ingredients: list[dict[str, Any]] = field(default_factory=list)
    digital_source_type: "str | None" = None
    validation_errors: list[str] = field(default_factory=list)
    raw_manifest: "dict[str, Any] | None" = None
    note: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "checked": self.checked,
            "has_manifest": self.has_manifest,
            "is_valid": self.is_valid,
            "claim_generator": self.claim_generator,
            "signature_info": self.signature_info,
            "assertions": self.assertions,
            "ingredients": self.ingredients,
            "digital_source_type": self.digital_source_type,
            "validation_errors": self.validation_errors,
            "note": self.note,
        }


def is_available() -> bool:
    """True jika library c2pa-python terpasang dan siap dipakai."""
    return C2PA_AVAILABLE


def verify_c2pa(path: str | Path) -> C2paResult:
    """Baca dan verifikasi manifest C2PA dari sebuah file media.

    Tidak pernah melempar exception ke pemanggil -- semua kegagalan
    diterjemahkan menjadi ``C2paResult`` yang menjelaskan kenapa, supaya
    "tidak ada manifest" tetap menghasilkan laporan yang bisa dibaca,
    bukan crash.
    """
    media_path = Path(path).expanduser().resolve()

    if not C2PA_AVAILABLE:
        return C2paResult(
            checked=False,
            has_manifest=False,
            note=(
                "Library c2pa-python tidak terpasang. Install dengan: "
                "python -m pip install c2pa-python"
            ),
        )

    if not media_path.exists() or not media_path.is_file():
        return C2paResult(
            checked=False,
            has_manifest=False,
            note=f"File tidak ditemukan: {media_path}",
        )

    try:
        with c2pa.Reader(str(media_path)) as reader:
            manifest_json = reader.json()
    except Exception as exc:  # c2pa.C2paError dan turunannya, plus IO lain
        return _result_from_read_error(exc)

    try:
        manifest_store = json.loads(manifest_json)
    except json.JSONDecodeError:
        return C2paResult(
            checked=True,
            has_manifest=False,
            note="Manifest C2PA tidak bisa diparse sebagai JSON.",
        )

    active_label = manifest_store.get("active_manifest")
    manifests = manifest_store.get("manifests", {})
    if not active_label or active_label not in manifests:
        return C2paResult(
            checked=True,
            has_manifest=False,
            note=(
                "Tidak ada Content Credentials (C2PA) yang tertanam di file ini. "
                "Ini TIDAK membuktikan file asli atau bukan AI -- metadata C2PA "
                "mudah dihapus dan banyak generator (terutama pipeline Stable "
                "Diffusion lokal) tidak pernah menyematkannya."
            ),
        )

    active_manifest = manifests[active_label]
    validation_status = manifest_store.get("validation_status", [])
    validation_errors = [
        f"{item.get('code', 'unknown')}: {item.get('explanation', '')}".strip(": ")
        for item in validation_status
        if str(item.get("code", "")).lower() not in {"", "success"}
        and "trusted" not in str(item.get("code", "")).lower()
    ]
    is_valid = len(validation_errors) == 0

    claim_generator = active_manifest.get("claim_generator") or active_manifest.get(
        "claim_generator_info", [{}]
    )[0].get("name") if active_manifest.get("claim_generator_info") else active_manifest.get("claim_generator")

    digital_source_type = None
    assertions_out: list[dict[str, Any]] = []
    for assertion in active_manifest.get("assertions", []):
        label = assertion.get("label", "")
        assertions_out.append({"label": label})
        data = assertion.get("data", {})
        if isinstance(data, dict) and "digitalSourceType" in data:
            digital_source_type = data.get("digitalSourceType")

    ingredients_out = [
        {
            "title": ing.get("title"),
            "relationship": ing.get("relationship"),
            "format": ing.get("format"),
        }
        for ing in active_manifest.get("ingredients", [])
    ]

    signer_info = active_manifest.get("signature_info", {}) or {}

    return C2paResult(
        checked=True,
        has_manifest=True,
        is_valid=is_valid,
        claim_generator=claim_generator,
        signature_info={
            "issuer": signer_info.get("issuer"),
            "time": signer_info.get("time"),
            "alg": signer_info.get("alg"),
        },
        assertions=assertions_out,
        ingredients=ingredients_out,
        digital_source_type=digital_source_type,
        validation_errors=validation_errors,
        raw_manifest=active_manifest,
        note=(
            "Content Credentials ditemukan dan tanda tangannya valid."
            if is_valid
            else "Content Credentials ditemukan, tetapi validasi tanda tangan gagal "
            "atau manifest telah diubah sejak ditandatangani."
        ),
    )


def _result_from_read_error(exc: Exception) -> C2paResult:
    name = type(exc).__name__.lower()
    message = str(exc)

    if "manifestnotfound" in name or "manifest could not be found" in message.lower():
        note = (
            "Tidak ada Content Credentials (C2PA) yang tertanam di file ini. "
            "Ini TIDAK membuktikan file asli atau bukan AI -- metadata C2PA "
            "mudah dihapus dan banyak generator tidak menyematkannya."
        )
    elif "filenotfound" in name:
        note = "File tidak ditemukan saat dibuka oleh pustaka C2PA."
    else:
        note = (
            f"File tidak bisa dibaca sebagai media yang didukung C2PA reader "
            f"({type(exc).__name__}). Ini wajar untuk format yang tidak umum, "
            f"file rusak, atau file tanpa manifest sama sekali. Detail: {message[:200]}"
        )

    return C2paResult(checked=True, has_manifest=False, note=note)

from __future__ import annotations

import hashlib
import json
import mimetypes
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

from .c2pa_verify import verify_c2pa
from .models import AnalysisResult, Finding
from .signatures import GENERATOR_SIGNATURES, GPU_HINTS, PROMPT_KEYS, SERVER_HINTS

# DigitalSourceType URIs yang menandakan asal algoritmik/AI menurut skema
# IPTC, dipakai C2PA untuk menandai apakah aset dibuat sintetis oleh AI.
# Referensi: https://cv.iptc.org/newscodes/digitalsourcetype/
_AI_DIGITAL_SOURCE_TYPES = (
    "trainedalgorithmicmedia",
    "compositesynthetic",
    "algorithmicmedia",
)


def analyze_file(path: str | Path) -> AnalysisResult:
    media_path = Path(path).expanduser().resolve()
    if not media_path.exists():
        raise FileNotFoundError(f"File tidak ditemukan: {media_path}")
    if not media_path.is_file():
        raise ValueError(f"Target bukan file: {media_path}")

    data = media_path.read_bytes()
    text_view = _safe_text_view(data)
    metadata = _collect_metadata(media_path, data, text_view)
    flat_text = _flatten_for_search(metadata, text_view, media_path)

    findings: list[Finding] = []
    raw_signals: dict[str, Any] = {}

    generator_hits = _detect_generators(flat_text)
    raw_signals["generator_hits"] = generator_hits
    for name, hits in generator_hits.items():
        findings.append(
            Finding(
                title=f"Petunjuk generator: {name}",
                detail=f"Ditemukan kata/pola: {', '.join(hits[:6])}",
                confidence="sedang" if len(hits) > 1 else "rendah",
                category="ai_generator",
            )
        )

    prompts = _extract_prompt_candidates(metadata, text_view)
    raw_signals["prompt_candidates"] = prompts
    if prompts:
        findings.append(
            Finding(
                title="Prompt ditemukan",
                detail=prompts[0][:500],
                confidence="tinggi",
                category="prompt",
            )
        )
    else:
        findings.append(
            Finding(
                title="Prompt asli tidak ditemukan",
                detail="File ini tidak menyimpan prompt yang jelas. Reverse-prompt hanya bisa berupa perkiraan, bukan bukti.",
                confidence="tinggi",
                category="prompt",
            )
        )

    gpu_hits = _keyword_hits(flat_text, GPU_HINTS)
    raw_signals["gpu_hits"] = gpu_hits
    if gpu_hits:
        findings.append(
            Finding(
                title="Ada petunjuk hardware/render",
                detail=f"Ditemukan istilah: {', '.join(gpu_hits)}. Ini belum membuktikan GPU spesifik.",
                confidence="rendah",
                category="hardware",
            )
        )
    else:
        findings.append(
            Finding(
                title="GPU spesifik tidak bisa dipastikan",
                detail="Media akhir biasanya tidak membawa jejak GPU yang cukup kuat untuk atribusi.",
                confidence="tinggi",
                category="hardware",
            )
        )

    server_hits = _keyword_hits(flat_text, SERVER_HINTS)
    raw_signals["server_hits"] = server_hits
    if server_hits:
        findings.append(
            Finding(
                title="Ada petunjuk layanan/server",
                detail=f"Ditemukan istilah: {', '.join(server_hits)}. Ini hanya petunjuk metadata, bukan lokasi pasti.",
                confidence="rendah",
                category="infrastructure",
            )
        )
    else:
        findings.append(
            Finding(
                title="Kluster server tidak bisa dilacak dari file ini",
                detail="VPN atau lokasi pengunduhan tidak bisa ditembus hanya dari gambar/video final.",
                confidence="tinggi",
                category="infrastructure",
            )
        )

    c2pa_result = verify_c2pa(media_path)
    raw_signals["c2pa"] = c2pa_result.as_dict()
    findings.append(_c2pa_finding(c2pa_result))

    score = _score(generator_hits, prompts, metadata, c2pa_result)
    confidence = _confidence_label(score)
    summary = _summary_label(score, bool(prompts), bool(generator_hits), c2pa_result)

    limitations = [
        "Hasil ini adalah analisis OSINT/forensik awal, bukan bukti final.",
        "Exact GPU biasanya tidak bisa diketahui tanpa log render, metadata eksplisit, atau watermark khusus.",
        "Prompt asli hanya bisa diekstrak jika tersimpan di metadata atau content credentials.",
        "Lokasi server pemrosesan tidak bisa dipastikan dari file akhir tanpa data jaringan/platform tambahan.",
        "Tidak adanya Content Credentials (C2PA) BUKAN bukti bahwa media itu asli -- metadata ini mudah dihapus.",
    ]

    return AnalysisResult(
        path=media_path,
        file_name=media_path.name,
        size_bytes=media_path.stat().st_size,
        sha256=hashlib.sha256(data).hexdigest(),
        mime_guess=mimetypes.guess_type(media_path.name)[0] or "unknown",
        summary=summary,
        confidence=confidence,
        metadata=metadata,
        findings=findings,
        limitations=limitations,
        raw_signals=raw_signals,
        c2pa=c2pa_result.as_dict(),
    )


def _collect_metadata(path: Path, data: bytes, text_view: str) -> dict[str, Any]:
    metadata: dict[str, Any] = {
        "extension": path.suffix.lower(),
        "magic": data[:16].hex(),
    }
    metadata.update(_image_metadata(path))
    video_meta = _ffprobe_metadata(path)
    if video_meta:
        metadata["ffprobe"] = video_meta
    embedded = _embedded_text_hints(text_view)
    if embedded:
        metadata["embedded_text_hints"] = embedded
    return metadata


def _image_metadata(path: Path) -> dict[str, Any]:
    try:
        from PIL import Image, ExifTags
    except Exception:
        return {"image_note": "Install Pillow untuk metadata gambar yang lebih lengkap."}

    try:
        with Image.open(path) as image:
            info = {str(key): _safe_value(value) for key, value in image.info.items()}
            exif_data: dict[str, Any] = {}
            raw_exif = image.getexif()
            for key, value in raw_exif.items():
                name = ExifTags.TAGS.get(key, str(key))
                exif_data[str(name)] = _safe_value(value)
            return {
                "image": {
                    "format": image.format,
                    "mode": image.mode,
                    "width": image.width,
                    "height": image.height,
                },
                "image_info": info,
                "exif": exif_data,
            }
    except Exception as exc:
        return {"image_error": str(exc)}


def _ffprobe_metadata(path: Path) -> dict[str, Any] | None:
    if shutil.which("ffprobe") is None:
        return None
    try:
        proc = subprocess.run(
            [
                "ffprobe",
                "-v",
                "quiet",
                "-print_format",
                "json",
                "-show_format",
                "-show_streams",
                str(path),
            ],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
    except Exception:
        return None
    if not proc.stdout.strip():
        return None
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError:
        return {"raw": proc.stdout[:2000]}


def _safe_text_view(data: bytes) -> str:
    clipped = data[:2_000_000]
    return clipped.decode("utf-8", errors="ignore").lower()


def _flatten_for_search(metadata: dict[str, Any], text_view: str, media_path: Path) -> str:
    """Gabungkan metadata + isi file mentah menjadi satu blob pencarian.

    Dua lapis perlindungan terhadap kebocoran nama file ke deteksi
    generator/keyword:
    1. Field yang KEY-nya path/nama file (mis. ``ffprobe.format.filename``)
       dikosongkan oleh ``_strip_filename_fields``.
    2. Pesan bebas teks (mis. exception Pillow seperti
       ``cannot identify image file '/tmp/foto_midjourney.png'``) bisa tetap
       menyelipkan path di VALUE, bukan key -- jadi setelah serialisasi kita
       redaksi literal nama file dan path lengkapnya dari hasil gabungan.

    Tanpa keduanya, nama file milik pengguna sendiri (mis. seseorang
    mengirim file bernama ``foto_midjourney_party.png``) bisa memicu
    "petunjuk generator ditemukan" yang keliru -- itu cocok ke nama file,
    bukan ke isi atau metadata sebenarnya.
    """
    sanitized = _strip_filename_fields(metadata)
    try:
        meta_text = json.dumps(sanitized, ensure_ascii=False, default=str).lower()
    except Exception:
        meta_text = str(sanitized).lower()
    combined = f"{meta_text}\n{text_view}"

    file_name = media_path.name.lower()
    full_path = str(media_path).lower()
    if file_name:
        combined = combined.replace(file_name, "")
    if full_path and full_path != file_name:
        combined = combined.replace(full_path, "")
    return combined


_FILENAME_LIKE_KEYS = {"filename", "path", "file_name", "name"}


def _strip_filename_fields(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: ("" if str(key).lower() in _FILENAME_LIKE_KEYS else _strip_filename_fields(child))
            for key, child in value.items()
        }
    if isinstance(value, list):
        return [_strip_filename_fields(item) for item in value]
    return value


def _detect_generators(flat_text: str) -> dict[str, list[str]]:
    found: dict[str, list[str]] = {}
    for generator, patterns in GENERATOR_SIGNATURES.items():
        hits = [pattern for pattern in patterns if pattern in flat_text]
        if hits:
            found[generator] = hits
    return found


def _extract_prompt_candidates(metadata: dict[str, Any], text_view: str) -> list[str]:
    candidates: list[str] = []
    _walk_metadata_for_prompts(metadata, candidates)

    regexes = [
        r"prompt[:=]\s*(.{20,1000})",
        r"parameters[:=]\s*(.{20,1200})",
        r"negative prompt[:=]\s*(.{20,1000})",
    ]
    for pattern in regexes:
        for match in re.finditer(pattern, text_view, flags=re.IGNORECASE | re.DOTALL):
            cleaned = _clean_candidate(match.group(1))
            if cleaned:
                candidates.append(cleaned)

    unique: list[str] = []
    for item in candidates:
        if item not in unique:
            unique.append(item)
    return unique[:5]


def _walk_metadata_for_prompts(value: Any, candidates: list[str]) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            key_text = str(key).lower()
            if any(prompt_key in key_text for prompt_key in PROMPT_KEYS):
                cleaned = _clean_candidate(str(child))
                if cleaned:
                    candidates.append(cleaned)
            _walk_metadata_for_prompts(child, candidates)
    elif isinstance(value, list):
        for item in value:
            _walk_metadata_for_prompts(item, candidates)


def _keyword_hits(flat_text: str, keywords: list[str]) -> list[str]:
    return [keyword for keyword in keywords if keyword in flat_text][:10]


def _embedded_text_hints(text_view: str) -> list[str]:
    hints = []
    for token in [
        "prompt",
        "negative prompt",
        "stable diffusion",
        "comfyui",
        "midjourney",
        "content credentials",
        "c2pa",
        "dall-e",
        "firefly",
    ]:
        if token in text_view:
            hints.append(token)
    return hints


def _c2pa_finding(c2pa_result) -> Finding:
    if not c2pa_result.checked:
        return Finding(
            title="Verifikasi C2PA tidak dijalankan",
            detail=c2pa_result.note,
            confidence="rendah",
            category="c2pa",
        )

    if not c2pa_result.has_manifest:
        return Finding(
            title="Tidak ada Content Credentials (C2PA)",
            detail=c2pa_result.note,
            confidence="tinggi",
            category="c2pa",
        )

    source_type = (c2pa_result.digital_source_type or "").lower()
    is_ai_source = any(token in source_type for token in _AI_DIGITAL_SOURCE_TYPES)

    if c2pa_result.is_valid and is_ai_source:
        detail = (
            f"Manifest C2PA valid dan ditandatangani oleh: {c2pa_result.claim_generator or 'tidak diketahui'}. "
            f"Digital source type: {c2pa_result.digital_source_type}. "
            "Ini adalah verifikasi kriptografis, bukan tebakan keyword."
        )
        return Finding(
            title="Content Credentials valid: asal algoritmik/AI",
            detail=detail,
            confidence="tinggi",
            category="c2pa",
        )

    if c2pa_result.is_valid:
        detail = (
            f"Manifest C2PA valid, ditandatangani oleh: {c2pa_result.claim_generator or 'tidak diketahui'}. "
            f"Digital source type: {c2pa_result.digital_source_type or 'tidak tercatat'}. "
            "Tidak menunjukkan asal algoritmik/AI secara eksplisit."
        )
        return Finding(
            title="Content Credentials valid",
            detail=detail,
            confidence="tinggi",
            category="c2pa",
        )

    return Finding(
        title="Content Credentials ditemukan tetapi TIDAK valid",
        detail=(
            c2pa_result.note
            + f" Error: {'; '.join(c2pa_result.validation_errors) if c2pa_result.validation_errors else 'tidak rinci'}."
        ),
        confidence="tinggi",
        category="c2pa",
    )


def _score(
    generator_hits: dict[str, list[str]],
    prompts: list[str],
    metadata: dict[str, Any],
    c2pa_result,
) -> int:
    score = 0
    score += min(sum(len(hits) for hits in generator_hits.values()) * 12, 55)
    if prompts:
        score += 30
    if metadata.get("image_info") or metadata.get("exif"):
        score += 5

    if c2pa_result.checked and c2pa_result.has_manifest and c2pa_result.is_valid:
        source_type = (c2pa_result.digital_source_type or "").lower()
        if any(token in source_type for token in _AI_DIGITAL_SOURCE_TYPES):
            # Bukti kriptografis valid mengalahkan sinyal heuristik manapun.
            return 100
    return min(score, 100)


def _confidence_label(score: int) -> str:
    if score >= 70:
        return "tinggi"
    if score >= 35:
        return "sedang"
    return "rendah"


def _summary_label(score: int, has_prompt: bool, has_generator: bool, c2pa_result) -> str:
    if (
        c2pa_result.checked
        and c2pa_result.has_manifest
        and c2pa_result.is_valid
        and any(
            token in (c2pa_result.digital_source_type or "").lower()
            for token in _AI_DIGITAL_SOURCE_TYPES
        )
    ):
        return (
            "Terverifikasi kriptografis sebagai media AI lewat Content Credentials (C2PA) yang valid."
        )
    if has_prompt and has_generator:
        return "Ada indikasi kuat media AI karena metadata/prompt generator ditemukan."
    if score >= 35:
        return "Ada indikasi AI, tetapi perlu bukti tambahan sebelum atribusi."
    return "Belum ada indikasi AI yang kuat dari file ini."


def _clean_candidate(value: str) -> str:
    cleaned = re.sub(r"\s+", " ", value).strip(" \t\r\n:={}'\"")
    if len(cleaned) < 20:
        return ""
    return cleaned[:1200]


def _safe_value(value: Any) -> Any:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="ignore")[:2000]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)[:2000]

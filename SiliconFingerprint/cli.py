from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

from .analyzer import analyze_file
from .c2pa_verify import is_available as c2pa_is_available
from .c2pa_verify import verify_c2pa
from .report import render_html, render_json, render_markdown


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if args.command == "scan":
            return _scan(args)
        if args.command == "explain":
            return _explain(args)
        if args.command == "report":
            return _report(args)
        if args.command == "batch":
            return _batch(args)
        if args.command == "c2pa":
            return _c2pa(args)
        if args.command == "serve":
            return _serve(args)
        if args.command == "doctor":
            return _doctor()
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    parser.print_help()
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="silicon",
        description="SiliconFingerprint: alat OSINT sederhana untuk analisis jejak media AI.",
    )
    sub = parser.add_subparsers(dest="command")

    scan = sub.add_parser("scan", help="Analisis cepat dengan output ringkas.")
    scan.add_argument("file", help="Path gambar/video yang ingin dianalisis.")

    explain = sub.add_parser("explain", help="Jelaskan hasil dengan bahasa mudah.")
    explain.add_argument("file", help="Path gambar/video yang ingin dianalisis.")

    report = sub.add_parser("report", help="Buat laporan JSON, Markdown, atau HTML.")
    report.add_argument("file", help="Path gambar/video yang ingin dianalisis.")
    report.add_argument("--format", choices=["json", "md", "html"], default="md")
    report.add_argument("--output", "-o", help="Simpan laporan ke file.")

    batch = sub.add_parser("batch", help="Scan semua file dalam folder.")
    batch.add_argument("folder", help="Folder berisi file yang ingin dianalisis.")
    batch.add_argument("--limit", type=int, default=50, help="Batas jumlah file. Default: 50.")

    c2pa_cmd = sub.add_parser("c2pa", help="Verifikasi Content Credentials (C2PA) saja.")
    c2pa_cmd.add_argument("file", help="Path gambar/video yang ingin diverifikasi.")
    c2pa_cmd.add_argument("--json", action="store_true", help="Tampilkan hasil mentah sebagai JSON.")

    serve = sub.add_parser("serve", help="Jalankan Web UI lokal untuk demo/penggunaan interaktif.")
    serve.add_argument("--host", default="127.0.0.1", help="Host bind. Default: 127.0.0.1 (hanya lokal).")
    serve.add_argument("--port", type=int, default=5000, help="Port. Default: 5000.")
    serve.add_argument("--debug", action="store_true", help="Mode debug Flask (jangan dipakai di produksi).")

    sub.add_parser("doctor", help="Cek dependency dan kesiapan sistem.")

    return parser


def _scan(args: argparse.Namespace) -> int:
    result = analyze_file(args.file)
    print("SiliconFingerprint")
    print(f"File       : {result.file_name}")
    print(f"Kesimpulan : {result.summary}")
    print(f"Keyakinan : {result.confidence}")
    print("")
    print("Temuan utama:")
    for finding in result.findings[:6]:
        print(f"- {finding.title} ({finding.confidence}): {finding.detail}")
    return 0


def _explain(args: argparse.Namespace) -> int:
    result = analyze_file(args.file)
    print(f"Saya membaca file `{result.file_name}`.")
    print(result.summary)
    print("")
    print("Bahasa sederhananya:")
    for finding in result.findings:
        print(f"- {finding.title}: {finding.detail}")
    print("")
    print("Catatan penting:")
    for item in result.limitations:
        print(f"- {item}")
    return 0


def _report(args: argparse.Namespace) -> int:
    result = analyze_file(args.file)
    if args.format == "json":
        rendered = render_json(result)
    elif args.format == "html":
        rendered = render_html(result)
    else:
        rendered = render_markdown(result)

    if args.output:
        output_path = Path(args.output).expanduser().resolve()
        output_path.write_text(rendered, encoding="utf-8")
        print(f"Laporan disimpan: {output_path}")
    else:
        print(rendered)
    return 0


def _c2pa(args: argparse.Namespace) -> int:
    import json as _json

    result = verify_c2pa(args.file)
    if args.json:
        print(_json.dumps(result.as_dict(), ensure_ascii=False, indent=2))
        return 0

    print("SiliconFingerprint — Verifikasi C2PA")
    print(f"File          : {args.file}")
    print(f"Ada manifest  : {'ya' if result.has_manifest else 'tidak'}")
    if result.has_manifest:
        print(f"Tanda tangan  : {'valid' if result.is_valid else 'TIDAK valid'}")
        print(f"Ditandatangani oleh : {result.claim_generator or 'tidak diketahui'}")
        print(f"Digital source type : {result.digital_source_type or 'tidak tercatat'}")
        if result.ingredients:
            print("Ingredients (riwayat edit):")
            for ing in result.ingredients:
                print(f"  - {ing.get('title')} ({ing.get('relationship')})")
        if result.validation_errors:
            print("Error validasi:")
            for err in result.validation_errors:
                print(f"  - {err}")
    print("")
    print(f"Catatan: {result.note}")
    return 0


def _batch(args: argparse.Namespace) -> int:
    folder = Path(args.folder).expanduser().resolve()
    if not folder.exists() or not folder.is_dir():
        raise ValueError(f"Folder tidak ditemukan: {folder}")

    files = [item for item in folder.rglob("*") if item.is_file()]
    supported = [
        item
        for item in files
        if item.suffix.lower() in {".jpg", ".jpeg", ".png", ".webp", ".gif", ".mp4", ".mov", ".mkv"}
    ][: max(args.limit, 1)]

    print(f"Folder: {folder}")
    print(f"File dianalisis: {len(supported)}")
    print("")
    for item in supported:
        result = analyze_file(item)
        print(f"- {item.name}: {result.confidence} | {result.summary}")
    return 0


def _serve(args: argparse.Namespace) -> int:
    try:
        from .web import run_dev_server
    except ImportError:
        print(
            "Flask belum terpasang. Install dengan: python -m pip install -e \".[web]\"",
            file=sys.stderr,
        )
        return 1

    print(f"SiliconFingerprint Web UI berjalan di http://{args.host}:{args.port}")
    print("Tekan Ctrl+C untuk berhenti.")
    run_dev_server(host=args.host, port=args.port, debug=args.debug)
    return 0


def _doctor() -> int:
    print("SiliconFingerprint Doctor")
    print(f"Python : {sys.version.split()[0]}")
    print(f"ffprobe: {'ada' if shutil.which('ffprobe') else 'tidak ada'}")
    try:
        import PIL  # type: ignore

        print(f"Pillow : ada ({PIL.__version__})")
    except Exception:
        print("Pillow : tidak ada (install dengan: python -m pip install -e .[image])")
    print(f"c2pa-python : {'ada' if c2pa_is_available() else 'tidak ada (install dengan: python -m pip install c2pa-python)'}")
    print("")
    print("Status: siap untuk analisis dasar.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

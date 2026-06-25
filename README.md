# SiliconFingerprint

SiliconFingerprint adalah tool OSINT defensif untuk membaca jejak media digital, terutama gambar atau video yang diduga dibuat/diedit AI. Fokusnya bukan menuduh, tetapi membantu analis membuat laporan yang rapi, mudah dimengerti, dan jujur soal tingkat keyakinan.

## Ide Besar

Target jangka panjangnya adalah **AI-Latent Space Archeologist**: alat yang meneliti metadata, watermark, pola encoder, artefak kompresi, dan petunjuk model generatif untuk membuat estimasi intelijen.

Yang sudah ada di versi ini:

- Mengecek metadata file, hash, ukuran, MIME, dan waktu file.
- **Verifikasi kriptografis Content Credentials (C2PA)** — bukan tebakan keyword, tapi pengecekan tanda tangan digital manifest C2PA (didukung Adobe Firefly, DALL-E 3, Sora, Imagen, dan lainnya).
- Mendeteksi petunjuk generator seperti Stable Diffusion, ComfyUI, Automatic1111, Midjourney, DALL-E, Firefly, Leonardo, dan sejenisnya (berbasis pola teks/metadata).
- Mengekstrak prompt jika memang tersimpan di metadata.
- Menilai kemungkinan gambar AI dengan bahasa sederhana, dengan bukti kriptografis (C2PA valid) selalu diutamakan di atas tebakan keyword.
- Membuat laporan JSON, Markdown, atau HTML — lewat CLI maupun Web UI lokal.
- Menjelaskan keterbatasan: GPU spesifik, prompt asli, lokasi server, dan ketidakhadiran C2PA biasanya tidak bisa dipastikan/dibuktikan hanya dari file akhir.

## Mengapa C2PA, bukan cuma keyword matching?

Deteksi berbasis kata kunci (mencari "stable diffusion" atau "midjourney" di metadata mentah) mudah dipalsukan dan mudah luput kalau metadata dibersihkan. **C2PA (Coalition for Content Provenance and Authenticity)** adalah standar industri yang menyematkan manifest bertanda tangan digital ke dalam file — didukung Adobe, OpenAI, Google, dan Microsoft. Memverifikasinya memberi jawaban ya/tidak yang didukung kriptografi, bukan tebakan pola teks.

**Catatan jujur soal batasan C2PA:**
- Banyak pipeline Stable Diffusion lokal (Automatic1111, ComfyUI) **tidak** menyematkan C2PA.
- Metadata C2PA **mudah dihapus**. Tidak adanya manifest BUKAN bukti bahwa media itu asli atau bukan AI.
- Tanda tangan valid hanya membuktikan manifest tidak diubah sejak ditandatangani — bukan bahwa kontennya tidak menyesatkan.

## Instalasi

> Membutuhkan **Python 3.10+** (syarat dari `c2pa-python`, dependency verifikasi Content Credentials).

```bash
cd SiliconFingerprint
python -m pip install -e ".[all]"     # image + c2pa + web sekaligus
```

Hanya butuh sebagian fitur? Pasang per-extra:

```bash
python -m pip install -e ".[image]"   # metadata gambar (Pillow)
python -m pip install -e ".[c2pa]"    # verifikasi Content Credentials
python -m pip install -e ".[web]"     # Web UI lokal (Flask)
```

Video memerlukan `ffprobe` (paket `ffmpeg`) terpasang terpisah di sistem.

## Perintah CLI

```bash
silicon scan bukti.jpg
silicon explain bukti.jpg
silicon report bukti.jpg --format html --output laporan.html
silicon report bukti.jpg --format json
silicon c2pa bukti.jpg                 # verifikasi Content Credentials saja
silicon c2pa bukti.jpg --json
silicon batch ./folder_bukti --limit 20
silicon doctor                         # cek dependency (Pillow, ffprobe, c2pa-python)
```

## Web UI lokal

Untuk demo interaktif atau dipakai tim non-teknis di jaringan internal:

```bash
silicon serve --port 5000
```

Buka `http://127.0.0.1:5000`, tarik-lepas atau pilih file, lalu lihat laporan langsung di browser — termasuk stempel verdict C2PA. File yang diunggah **tidak disimpan**; dianalisis di temp dir lalu dihapus setelah selesai.

> Server bawaan Flask ini untuk demo/penggunaan lokal. Untuk dipasang di jaringan produksi/diakses publik, jalankan di belakang WSGI server (gunicorn/uwsgi) dan reverse proxy seperti biasa.

## Contoh Output Singkat

```text
SiliconFingerprint Report
File: bukti.jpg
Kesimpulan: Terverifikasi kriptografis sebagai media AI lewat Content Credentials (C2PA) yang valid.
Keyakinan: tinggi

Temuan:
- Content Credentials valid: asal algoritmik/AI (tinggi)
- Prompt asli tidak ditemukan (tinggi)
- GPU spesifik tidak bisa dipastikan (tinggi)
- Lokasi server pemrosesan tidak bisa dipastikan dari file ini (tinggi)
```

## Prinsip Etika

Tool ini dibuat untuk OSINT legal, edukasi, analisis defensif, jurnalisme, dan keamanan. Jangan gunakan untuk doxxing, pelecehan, pemerasan, atau menuduh orang tanpa bukti tambahan. Verifikasi C2PA yang valid adalah bukti kuat soal *asal pembuatan* sebuah file, bukan bukti soal niat atau identitas orang yang mengunggahnya.

## Pengembangan & Test

```bash
python -m pip install -e ".[dev,all]"
python -m pytest -q --cov=siliconfingerprint --cov-report=term-missing
```

Coverage saat ini ~84% di seluruh modul (analyzer, c2pa_verify, cli, web, models).

## Roadmap

- Analisis frame video dengan `ffprobe` lebih dalam (per-frame, bukan cuma container metadata).
- Deteksi watermark model generatif yang terdokumentasi publik (mis. SynthID).
- Database signature generator yang bisa diperbarui komunitas.
- Dukungan batch upload di Web UI.
- Export laporan PDF langsung dari Web UI.

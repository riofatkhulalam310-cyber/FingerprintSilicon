# Contributing

Terima kasih sudah ingin membantu SiliconFingerprint.

## Prinsip

- Gunakan data publik atau file milik sendiri.
- Jangan menambahkan fitur untuk doxxing, bypass akun, exploit, atau scraping agresif.
- Setiap klaim atribusi harus punya tingkat keyakinan.
- Bahasa output harus mudah dipahami pengguna non-ahli.

## Cara Menambah Signature

Tambahkan pola baru di `siliconfingerprint/signatures.py`, lalu sertakan contoh file uji sintetis di `tests/`.

## Menjalankan Test

```bash
python -m pip install -e ".[dev,all]"
python -m pytest -q --cov=siliconfingerprint
```

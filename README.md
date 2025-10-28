# Hunt Toolkit — Interactive Bug-Hunting CLI

**Ringkas:** Tool CLI interaktif untuk recon & fuzzing. Menjalankan `subfinder`, `httpx`, `gau`, `ffuf`, `dalfox`, `nuclei`, `gf`, dll — semua output disimpan rapi ke `~/bug-hunting/bbp/<target>/`.

> ⚠️ Gunakan hanya pada target yang lo punya izin. Penggunaan tanpa izin adalah ilegal.

## Fitur
- Menu interaktif (Subfinder, HTTPX, GAU, FFUF, Dalfox, Nuclei, GF, dll.)
- Output tersimpan: `~/bug-hunting/bbp/<target>/`
- Built-in support untuk wordlist lokal (`~/Bug-Hunting/wordlist`)
- Setup script untuk install dependencies & clone SecLists

## Cepat mulai (local)
```bash

git clone https://github.com/majelissholawatnuralathos-oss/Bug-Hunting.git
cd Bug-Hunting
chmod +x setup.sh hunt.py
./setup.sh
python3 hunt.py

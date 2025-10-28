# Hunt Toolkit — Interactive Bug-Hunting CLI

**Ringkas:** Tool CLI interaktif untuk recon & fuzzing. Menjalankan `subfinder`, `httpx`, `gau`, `ffuf`, `dalfox`, `nuclei`, `gf`, dll — semua output disimpan rapi ke `~/bug-hunting/bbp/<target>/`.

> ⚠️ Gunakan hanya pada target yang lo punya izin. Penggunaan tanpa izin adalah ilegal.

## Fitur
- Menu interaktif (Subfinder, HTTPX, GAU, FFUF, Dalfox, Nuclei, GF, dll.)
- Output tersimpan: `~/bug-hunting/bbp/<target>/`
- Built-in support untuk wordlist lokal (`~/Bug-Hunting/wordlist`)
- Setup script untuk install dependencies & clone SecLists

## Cepat mulai (local)
> Kita akan install **Golang (versi terbaru)** dulu, baru clone repo dan jalankan setup.  
> Perintah di bawah sudah otomatis ambil rilis Go terbaru dari `go.dev`.

```bash

# 4) Clone repo & jalankan setup
git clone https://github.com/fajar23332/Bug-Hunting.git
cd Bug-Hunting
chmod +x setup.sh hunt.py

# 5) Jalankan setup (install dependencies, clone SecLists subset, copy wordlists, dll.)
./setup.sh

# 6) Setelah setup selesai: jalankan UI
python3 hunt.py

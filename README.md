# Android & Reverse Engineering CTF Solver

Script analisis otomatis untuk tantangan Reverse Engineering dan Android Hacking pada kompetisi CTF.

## Cara Pakai

```bash
# Analisis file APK / DEX / ELF / .so
python rev.py <file_target>

# Simpan artefak / script frida ke folder tertentu
python rev.py challenge.apk --outdir ./output

# Otomatis cek device emulator via ADB
python rev.py challenge.apk --adb
```

### Opsi CLI
- `<target>`: Path file APK, DEX, ELF, atau binary yang ingin dianalisa.
- `--outdir`: Folder penyimpanan script Frida dan artefak ter-ekstrak (default: `results`).
- `--adb`: Cek emulator / device yang terhubung via ADB.
- `--frida`: Mode bantuan injeksi live Frida.
- `--no-stop`: Scan tuntas tanpa berhenti pada temuan pertama.

## Setup (Linux / WSL / Windows)

```bash
pip install -r requirements.txt
```

Shortcut CLI di Linux / WSL:
```bash
chmod +x rev.py
sudo ln -sf $(pwd)/rev.py /usr/local/bin/rev
```

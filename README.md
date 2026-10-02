# Tool Analysis Reverse

Automated Static & Dynamic Android, DEX, ELF, and Frida Instrumentation Suite for CTF.

---

## 🚀 Quick Start

### 1. Instalasi Dependensi
```bash
# Windows / Linux / WSL
pip install -r requirements.txt
```

### 2. Shortcut Command
**Linux / WSL:**
```bash
chmod +x rev.py
sudo ln -sf $(pwd)/rev.py /usr/local/bin/rev
```

**Windows:**
```cmd
python rev.py challenge.apk
```

---

## 📖 Cara Penggunaan CLI (`rev.py`)

| Perintah | Deskripsi |
|---|---|
| `python rev.py <file>` | Analisis statis otomatis berkas APK, DEX, ELF, `.so`, atau binary. |
| `python rev.py ./folder_apks/` | Mode Batch: otomatis menganalisis semua APK/binary di dalam folder. |
| `python rev.py <file> --outdir ./output` | Tentukan folder spesifik untuk menyimpan script Frida dan artefak. |
| `python rev.py <file> --adb` | Cek status emulator/perangkat Android yang terhubung via ADB. |
| `python rev.py <file> --no-stop` | Scan mendalam tuntas tanpa berhenti pada temuan flag pertama. |

### Contoh Penggunaan CLI:
```bash
# Analisis APK tantangan
python rev.py "Challenge 0x2.apk"

# Analisis kumpulan file tantangan sekaligus dalam satu folder
python rev.py ./challenges/ --outdir ./triage_results

# Analisis binary ELF / library native Linux
python rev.py libnative.so
```

---

## 🖥️ Antarmuka GUI Frida (`GUI-ToolFrida`)

Alat bantu GUI interaktif untuk inspeksi aplikasi Android dan instrumentasi dinamis Frida secara visual.

### Menjalankan GUI:
```bash
cd GUI-ToolFrida
python main.py
```
*(Di Windows juga dapat langsung klik dua kali file `run.bat`)*

### Fitur Utama GUI:
1. **Device & Process Scanner:** Otomatis mendeteksi emulator (Genymotion, AVD, BlueStacks) dan list aplikasi yang sedang berjalan.
2. **APK Puller & Triage:** Menarik APK dari device, mengekstrak package name, main activity, permission, dan class list dalam hitungan detik.
3. **Universal Analysis (1-Click):** Menyiapkan script All-in-One hook yang otomatis menangani root bypass, string sniffer, crypto sniffer, dan method finder.
4. **Live Frida Injection:** Menjalankan script secara langsung via mode **Spawn (`-f`)** atau **Attach (`-n`)** dan menampilkan log interaktif secara real-time.

---

## 💉 Generator Script Frida Otomatis

Setiap analisis APK otomatis menghasilkan 11 script Frida targeted di folder `results/frida_scripts/`:

| Script | Fungsi |
|---|---|
| `00_universal_analysis.js` | **All-in-One Hook:** Root bypass, String `equals` sniffer, AES/DES/RSA key & ciphertext sniffer, Base64/Hash sniffer, SharedPreferences sniffer, dan Native log interceptor. |
| `00_universal_crypto_sniffer.js` | Khusus memonitor instansiasi cipher Java (`javax.crypto.Cipher`), `SecretKeySpec`, `IvParameterSpec`, dan hash MD5/SHA. |
| `01_invoke_static_method.js` | Memanggil method static target secara langsung tanpa menunggu input UI. |
| `02_choose_instance_invoker.js` | Menggunakan `Java.choose` untuk mencari objek target yang hidup di heap memori dan memanggil instance method-nya. |
| `03_modify_variables.js` | Mengubah nilai variabel class, static field, atau instance variable. |
| `04_hook_return_values.js` | Memaksa return value dari method pengecekan (misal checkFlag, isPremium) selalu mengembalikan `true`. |
| `05_native_so_hook.js` | Menghubungkan Interceptor pada library native `.so` (fungsi `strcmp`, `strncmp`, atau export symbol). |
| `06_root_bypass.js` | Bypass deteksi root Magisk, SuperSU, test-keys, dan emulator checks. |
| `07_string_equals_sniffer.js` | Merekam perbandingan string rahasia pada `String.equals()` dan `Arrays.equals()`. |
| `08_dex_in_memory_dumper.js` | Mendump DEX yang di-unpacking di memori saat runtime (cocok untuk APK ter-packer / obfuscated). |
| `09_biometric_keystore_bypass.js` | Mem-bypass verifikasi sidik jari/biometrik `BiometricPrompt` dan `FingerprintManager`. |

---

## 📊 Format Output

### Jika Flag Ditemukan:
```text
============================================================
[+] Flag found:
    - FLAG{BABY_HOOKS_0x2}
      Method: Crypto Solver: AES-CBC zero-IV (key='HILLBILLWILLBINN')

[+] Output: /path/to/results
============================================================
```

### Jika Perlu Triage / Analisis Lanjutan:
```text
------------------------------------------------------------
[-] Flag tidak ditemukan secara otomatis pada analisis statis.
[*] Rekomendasi langkah manual / dinamis:
    1. Periksa berkas hasil ekstraksi di:
       /path/to/results
------------------------------------------------------------
```
Langkah berikutnya: jalankan script Frida yang telah di-generate pada aplikasi yang berjalan di emulator untuk mendapatkan flag secara dinamis.

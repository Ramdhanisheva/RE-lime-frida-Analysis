# Frida Android CTF Assistant (GUI Tool)

Aplikasi desktop GUI modern untuk Android Hacking, Root Triage, APK Manager, dan Live Frida Hooking di CTF Final HackToday 2026.

## Cara Menjalankan

Cukup **double click** file:
```text
run.bat
```
Atau jalankan via PowerShell / Command Prompt:
```powershell
python main.py
```

---

## Fitur Utama

1. **Auto Device & Root Status**:
   - Mendeteksi emulator yang aktif secara real-time via ADB (`emulator-5554`).
   - Memeriksa status root (`UID 0 / Magisk`) secara otomatis.
   - Indikator status Frida Server (PID check / Running / Stopped).

2. **APK & Package Manager**:
   - Pilih file APK (`challenge.apk`), tool langsung membedah `Package Name` dan `Main Activity` secara instan.
   - Satu tombol **Install APK ke Emulator** (`adb install -r`).
   - Tombol cepat: **Buka Aplikasi**, **Force Stop**, **Clear Data**, dan **Uninstall**.
   - Daftar aplikasi 3rd party yang terpasang di emulator dengan fitur pencarian/filter cepat dan tombol **Set Target**.

3. **Frida Hooking Studio**:
   - Mode eksekusi: **Spawn (-f)** (aplikasi dimulai dan langsung di-hook dari awal) atau **Attach (-n)**.
   - Template CTF bawaan siap pakai:
     - `01_String_Equals_Sniffer`: Mencegat semua perbandingan string (menangkap flag langsung saat klik verify/submit).
     - `02_Universal_Crypto_Sniffer`: Mengambil key AES/DES, IV, dan plaintext sebelum/sesudah enkripsi.
     - `03_Root_And_AntiDebug_Bypass`: Melewati deteksi root Magisk, su file, dan build tags.
     - `04_Hook_Method_Return_True`: Memaksa fungsi validasi menghasilkan `true` / `1`.
     - `05_Native_Strcmp_Sniffer`: Mencegat perbandingan string C/C++ di library native `.so`.
     - `06_Java_Choose_Instance_Invoker`: Memanggil fungsi rahasia pada instance objek yang aktif di memory.
     - `07_In_Memory_DEX_Dumper`: Mendump file DEX yang di-load secara dinamis dari RAM ke file fisik.
     - `08_Universal_SSL_Pinning_Bypass`: Melewati proteksi SSL pinning.
     - `09_Biometric_Keystore_Bypass`: Bypass autentikasi fingerprint / biometric prompt.
     - `10_Logcat_Toast_Sniffer`: Menangkap pesan rahasia yang tercetak di Logcat atau Toast.
   - Live script editor: Bisa edit script langsung di GUI dan simpan ke file `.js`.
   - Real-time Output Terminal dengan auto-scroll.

4. **Device Tools & Logcat**:
   - Satu tombol untuk menyalakan/mematikan `frida-server` di emulator.
   - Fitur push binary `frida-server` dari Windows ke `/data/local/tmp/` dengan `chmod 755`.
   - Peluncur emulator Android Studio (AVD launcher).
   - Live Logcat monitor dengan filter pencarian kata kunci (`flag`, `secret`, dll.).

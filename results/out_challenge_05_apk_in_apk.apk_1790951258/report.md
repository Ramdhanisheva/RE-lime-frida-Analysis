# Reverse Engineering Triage Report: challenge_05_apk_in_apk.apk
- **Waktu Analisis:** 2026-10-02 21:27:38
- **Durasi Eksekusi:** 0.02s

## 🚩 Temuan Flag
*Belum ada flag langsung yang ditemukan secara statis. Gunakan script Frida yang telah digenerate.*

## 📱 Detail APK & Target
- **Package Name:** `com.hacktoday.challenge05`
- **Main Activity:** `com.hacktoday.challenge05.MainActivity`
- **DEX Files:** 1
- **Native Libraries (.so):** 0

## 💉 Frida Hooking Scripts (Ready to Run)
- **Universal Crypto Sniffer:** `00_universal_crypto_sniffer.js`
  ```bash
  frida -U -f com.hacktoday.challenge05 -l results\frida_scripts\00_universal_crypto_sniffer.js --no-pause
  ```
- **Static Method Invoker:** `01_invoke_static_method.js`
  ```bash
  frida -U -f com.hacktoday.challenge05 -l results\frida_scripts\01_invoke_static_method.js --no-pause
  ```
- **Instance Method Invoker (Java.choose):** `02_choose_instance_invoker.js`
  ```bash
  frida -U -f com.hacktoday.challenge05 -l results\frida_scripts\02_choose_instance_invoker.js --no-pause
  ```
- **Variable Modifier:** `03_modify_variables.js`
  ```bash
  frida -U -f com.hacktoday.challenge05 -l results\frida_scripts\03_modify_variables.js --no-pause
  ```
- **Method Return Value Override:** `04_hook_return_values.js`
  ```bash
  frida -U -f com.hacktoday.challenge05 -l results\frida_scripts\04_hook_return_values.js --no-pause
  ```
- **Native .so String Interceptor:** `05_native_so_hook.js`
  ```bash
  frida -U -f com.hacktoday.challenge05 -l results\frida_scripts\05_native_so_hook.js --no-pause
  ```
- **Root Detection Bypass:** `06_root_bypass.js`
  ```bash
  frida -U -f com.hacktoday.challenge05 -l results\frida_scripts\06_root_bypass.js --no-pause
  ```
# Reverse Engineering Triage Report: Challenge 0xB.apk
- **Waktu Analisis:** 2026-10-02 20:57:04
- **Durasi Eksekusi:** 13.93s

## 🚩 Temuan Flag
1. `FRIDA{NATIVE_HACKER}` - *Single-Byte XOR 0x2c* ([libfrida0xb.so] FRIDA{NATIVE_HACKER},YBIT\IOXIH,ssssv,KY)
2. `cj{jkPyf}` - *Native .so XOR 0x0f* (Raw bytes: __cxa_deleted_virtual)
3. `cj{jk/yf}` - *Native .so XOR 0x0f* (Raw bytes: Deleted virtual function called!)

## 📱 Detail APK & Target
- **Package Name:** `com.ad2001.frida0xb`
- **Main Activity:** `com.ad2001.frida0xb.MainActivity`
- **DEX Files:** 4
- **Native Libraries (.so):** 8

## 💉 Frida Hooking Scripts (Ready to Run)
- **Universal Crypto Sniffer:** `00_universal_crypto_sniffer.js`
  ```bash
  frida -U -f com.ad2001.frida0xb -l results\frida_scripts\00_universal_crypto_sniffer.js --no-pause
  ```
- **Static Method Invoker:** `01_invoke_static_method.js`
  ```bash
  frida -U -f com.ad2001.frida0xb -l results\frida_scripts\01_invoke_static_method.js --no-pause
  ```
- **Instance Method Invoker (Java.choose):** `02_choose_instance_invoker.js`
  ```bash
  frida -U -f com.ad2001.frida0xb -l results\frida_scripts\02_choose_instance_invoker.js --no-pause
  ```
- **Variable Modifier:** `03_modify_variables.js`
  ```bash
  frida -U -f com.ad2001.frida0xb -l results\frida_scripts\03_modify_variables.js --no-pause
  ```
- **Method Return Value Override:** `04_hook_return_values.js`
  ```bash
  frida -U -f com.ad2001.frida0xb -l results\frida_scripts\04_hook_return_values.js --no-pause
  ```
- **Native .so String Interceptor:** `05_native_so_hook.js`
  ```bash
  frida -U -f com.ad2001.frida0xb -l results\frida_scripts\05_native_so_hook.js --no-pause
  ```
- **Root Detection Bypass:** `06_root_bypass.js`
  ```bash
  frida -U -f com.ad2001.frida0xb -l results\frida_scripts\06_root_bypass.js --no-pause
  ```
# Automotion Reverse Engineering & CTF Triage Suite

Automated Reverse Engineering, Android APK static triage, cryptographic solver, and Frida hook generator designed for CTF competitions (HackToday, Cyber Jawara, picoCTF, COMPFEST) and mobile security challenges (Frida-Labs 0x1 – 0xB).

---

## Key Features

1. **Pure-Python Dalvik Executable (DEX) Engine**:
   - Zero-dependency parser for `classes.dex`, `classes2.dex`, `classes3.dex`, etc.
   - Extracts String Pools, Type Descriptors, Method IDs, and Class Definitions.
   - Automatically differentiates application classes from Android framework bloat (`androidx`, `kotlin`, `com.google`).

2. **Multi-Encoding Deep String Hunter**:
   - High-throughput scanning for flags in **Plaintext ASCII / UTF-8 / UTF-16LE**.
   - **Base64** decoding with automated flag prefix matching (`HackToday`, `FLAG{`, `FRIDA{`, etc.).
   - **Hex** encoded flag decoding.
   - **ROT13** Caesar cipher flag extraction.
   - **Single-Byte XOR** brute-force (0x01–0xFF) with instant prefix-seeking.
   - **Stack / Reversed String** detection.

3. **Automated Cryptography Solver**:
   - Extracts candidate symmetric keys (16, 24, 32 bytes) and Base64 ciphertexts directly from bytecode & string tables.
   - Cross-correlates and attempts automated decryption with:
     - **AES-128 / AES-192 / AES-256 (CBC mode with zero IV)**
     - **AES-CBC with key-as-IV**
     - **AES-ECB mode**
     - **RC4 stream cipher**
     - **Repeating XOR**
   - Automatically handles PKCS7 padding validation.
   - Tested offline against **Frida Lab 0x2** -> Recovers key `HILLBILLWILLBINN` and decrypts `FLAG{BABY_HOOKS_0x2}` in milliseconds.

4. **Native Shared Library (.so / ELF) Inspector**:
   - Pure-Python ELF header parser (Architecture, Bitness, Endianness).
   - JNI Export Enumeration (`Java_com_*`, `JNI_OnLoad`).
   - Native obfuscated string recovery (Single-Byte XOR).
   - Tested offline against **Frida Lab 0xB** -> Recovers `FRIDA{NATIVE_HACKER}` from XOR 0x2c in `libfrida0xb.so`.

5. **Automated Frida Script Generation**:
   Generates 7 ready-to-run, standalone Frida hooking scripts customized with the app's package name, main activity, and discovered target methods:
   - `00_universal_crypto_sniffer.js`: Intercepts `Cipher.getInstance`, `SecretKeySpec`, `IvParameterSpec`, and dumps `Cipher.doFinal` inputs/plaintexts live.
   - `01_invoke_static_method.js`: Calls static methods directly without user UI interaction.
   - `02_choose_instance_invoker.js`: Uses `Java.choose` to locate active heap instances and call methods.
   - `03_modify_variables.js`: Overwrites private/public static variables and heap instance fields.
   - `04_hook_return_values.js`: Forces target methods (like `checkPassword()` or `isLicenseValid()`) to return `true`.
   - `05_native_so_hook.js`: Hooks libc `strcmp`, `strncmp`, `memcmp` to intercept plaintext flag comparisons in `.so` files.
   - `06_root_bypass.js`: Universal root detection bypass for `RootBeer`, `/system/bin/su`, test-keys, and Build tags.

6. **Z3 SMT Solver Helper**:
   - Module for solving algebraic and BitVector crackme constraint systems ($A \cdot X = B \pmod N$, character XOR conditions, bit-rotations).

7. **Rich Reporting & Artifacts**:
   - Instant terminal alerts upon flag recovery.
   - Generates structured Markdown (`report.md`) and JSON (`report.json`) summaries.
   - Unpacks and stores extracted DEX files, `.so` libraries, and generated Frida scripts in `results/`.

---

## Installation

Ensure Python 3.10+ is installed:

```bash
pip install -r requirements.txt
```

### Dependencies
- `pycryptodome` (Cryptographic decryption & cipher routines)
- `z3-solver` (SMT constraint solving)
- `frida` & `frida-tools` (Dynamic instrumentation)
- `capstone` (Disassembly engine)

---

## Usage

### 1. Analyze an APK or Binary
Run the primary CLI against any APK, DEX, ELF, or raw challenge file:

```bash
python rev.py path/to/Challenge.apk
```

Or using the shorthand solver:

```bash
python solve.py path/to/Challenge.apk
```

### 2. Specify Custom Output Directory
```bash
python rev.py path/to/Challenge.apk --outdir output_folder
```

### 3. Check Connected ADB Devices & Prepare Frida Injection
```bash
python rev.py path/to/Challenge.apk --adb --frida
```

### 4. Running the Generated Frida Scripts
Once `rev.py` completes, targeted scripts are saved in `results/frida_scripts/`.
Inject any script into the running app or spawn it on an emulator/device:

```bash
# Spawn application with script
frida -U -f com.example.package -l results/frida_scripts/00_universal_crypto_sniffer.js --no-pause

# Or attach to running process
frida -U -N com.example.package -l results/frida_scripts/01_invoke_static_method.js
```

---

## Running Unit & Integration Tests

The test battery validates all core modules and verifies automated offline solving of real challenges:

```bash
python -m unittest discover -s tests -v
```

All 15 tests run and pass in ~18 seconds:
- `TestDEXParser`: Header validation and multi-DEX application class extraction.
- `TestStringHunter`: Plaintext, Base64, Hex, ROT13, Single-byte XOR.
- `TestCryptoSolver`: AES-CBC, AES-ECB, RC4, PKCS7 unpadding.
- `TestNativeInspector`: ELF headers and JNI symbol analysis.
- `TestFridaEngine`: Generation of 7 targeted scripts.
- `TestZ3Helper`: Linear system and constraint solving.
- `TestEndToEndChallenges`: End-to-end verification on Frida 0x2 (`FLAG{BABY_HOOKS_0x2}`) and Frida 0xB (`FRIDA{NATIVE_HACKER}`).

---

## Project Structure

```text
automationreverse/
├── config.py              # Flag regexes, target keywords, ADB / Frida paths
├── requirements.txt       # Python dependencies
├── rev.py                 # Primary CLI analysis runner
├── solve.py               # Quick alias entrypoint
├── README.md              # Documentation & user guide
├── core/
│   ├── apk_inspector.py   # Unpacker, AndroidManifest parser, DEX & .so organizer
│   ├── dex_parser.py      # Dalvik Executable (DEX) header & string pool parser
│   ├── string_hunter.py   # Multi-encoding scanner (Plaintext, B64, Hex, ROT13, XOR)
│   ├── crypto_solver.py   # Automated AES / DES / RC4 decryption engine
│   ├── native_inspector.py# ELF parser, JNI export extractor, .so XOR scanner
│   ├── frida_engine.py    # 7 targeted Frida hook templates & script generator
│   ├── z3_helper.py       # SMT constraint & linear algebra solver
│   └── reporter.py        # Terminal banners, flag alerts, Markdown/JSON export
└── tests/
    └── test_reverse.py    # Battery unit & integration tests
```

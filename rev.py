#!/usr/bin/env python3
"""
Automotion Reverse Engineering - Master Automated Triage & Solver CLI
Analyzes Android APKs, Native .so libraries, DEX files, and binary crackmes:
- Deep string scanning (Plaintext, Base64, Hex, ROT13, Single-byte XOR, Stack strings)
- Pure-Python DEX & AndroidManifest parsing
- Automatic AES / DES / RC4 decryption from extracted keys & ciphertexts
- Automatic generation of Frida hooking scripts (Frida Labs 0x1 - 0xB, Root Bypass, Crypto Sniffer)
- Optional ADB device detection & live Frida runner
"""

import argparse
import os
import sys
import time

# Ensure directory of rev.py is in sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import config
from core.apk_inspector import APKInspector
from core.crypto_solver import CryptoSolver
from core.dex_parser import DEXParser
from core.frida_engine import FridaEngine
from core.native_inspector import NativeInspector
from core.reporter import Reporter
from core.string_hunter import StringHunter


def analyze_single_target(target_path: str, args, reporter, hunter, crypto, frida_eng, apk_insp, nat_insp) -> Dict[str, Any]:
    start_time = time.time()
    file_size = os.path.getsize(target_path)
    target_name = os.path.basename(target_path)

    reporter.print_banner(target_name, file_size)

    all_flags = []
    seen_flag_strings = set()

    def register_flag(f_obj):
        flag_val = f_obj.get("flag", "")
        if flag_val and flag_val not in seen_flag_strings:
            seen_flag_strings.add(flag_val)
            all_flags.append(f_obj)
            reporter.print_flag_alert(f_obj["flag"], f_obj.get("encoding", ""))

    results = {
        "target": target_path,
        "file_size": file_size,
        "flags_found": [],
        "frida_scripts": {}
    }

    # Tahap 1: Deteksi Tipe File
    reporter.print_phase("Tahap 1: Deteksi Tipe Berkas & Format Target")
    is_apk = False
    is_elf = False
    is_dex = False

    with open(target_path, "rb") as f:
        header = f.read(16)

    if header.startswith(b"PK  ") or target_name.lower().endswith(".apk"):
        is_apk = True
        print(f" [+] Format: Android Application Package (APK)")
    elif header.startswith(b"\x7fELF") or target_name.lower().endswith(".so"):
        is_elf = True
        print(f" [+] Format: ELF Binary / Shared Library (.so)")
    elif header.startswith(b"dex\n"):
        is_dex = True
        print(f" [+] Format: Dalvik Executable (DEX)")
    else:
        print(f" [*] Format: Binary / Executable")

    # Tahap 2: Ekstraksi & Triage Berkas
    if is_apk:
        reporter.print_phase("Tahap 2: Unpacking APK & Static Manifest / DEX Triage")
        apk_res = apk_insp.inspect_apk(target_path)
        results.update(apk_res)

        print(f" [*] Package Name:    {apk_res.get('package_name', 'N/A')}")
        print(f" [*] Main Activity:   {apk_res.get('main_activity', 'N/A')}")
        print(f" [*] Total DEX Files: {len(apk_res.get('dex_files', []))}")
        print(f" [*] Native .so Libs: {len(apk_res.get('native_libraries', []))}")
        if apk_res.get("apk_in_apk"):
            print(f" [!] APK-in-APK Detected: {len(apk_res['apk_in_apk'])} nested package(s)")
            for nested in apk_res["apk_in_apk"][:3]:
                print(f"     - {nested.get('path')} ({nested.get('size', 0):,} bytes) [{nested.get('type', 'APK')}]")
        if apk_res.get("encrypted_assets"):
            print(f" [!] High-Entropy Assets: {len(apk_res['encrypted_assets'])}")
        if apk_res.get("app_classes"):
            print(f" [*] App Classes Found: {len(apk_res['app_classes'])} classes")
            for ac in apk_res["app_classes"][:5]:
                print(f"     - {ac}")

        # Tahap 3: Pemindaian String & Multi-Encoding
        reporter.print_phase("Tahap 3: Deep String Scanning & Multi-Encoding Grep")
        for fl in apk_res.get("flags_found", []):
            register_flag(fl)

        # Tahap 4: Automated Cryptography Solver (AES / DES / RC4)
        reporter.print_phase("Tahap 4: Automated Cryptography Decryption Solver")
        cand_keys = apk_res.get("crypto_candidates", {}).get("keys", [])
        cand_cts = apk_res.get("crypto_candidates", {}).get("ciphertexts", [])
        print(f" [*] Candidate Keys:        {len(cand_keys)}")
        print(f" [*] Candidate Ciphertexts: {len(cand_cts)}")

        if cand_keys and cand_cts:
            dec_flags = crypto.solve_candidates(cand_keys, cand_cts)
            for df in dec_flags:
                register_flag(df)
        else:
            dec_flags = crypto.solve_candidates([], cand_cts)
            for df in dec_flags:
                register_flag(df)

        # Tahap 5: Native .so Inspection
        if apk_res.get("native_libraries"):
            reporter.print_phase("Tahap 5: Native .so Library Inspection & JNI Exports")
            for so_info in apk_res["native_libraries"]:
                so_filename = so_info["filename"]
                so_path = os.path.join(apk_res["extracted_dir"], so_filename)
                if os.path.exists(so_path):
                    so_res = nat_insp.inspect_binary(so_path)
                    print(f" [*] Library: {so_filename} ({so_res.get('arch')}, {so_res.get('bitness')}-bit)")
                    if so_res.get("jni_exports"):
                        print(f"     JNI Exports: {', '.join(so_res['jni_exports'][:5])}")
                    for nfl in so_res.get("flags_found", []):
                        register_flag(nfl)

        # Tahap 6: Frida Script Generation
        reporter.print_phase("Tahap 6: Automated Frida Hooking Scripts Generation")
        so_names = [s["filename"] for s in apk_res.get("native_libraries", [])]
        scripts = frida_eng.generate_scripts_suite(
            package_name=apk_res.get("package_name", ""),
            main_activity=apk_res.get("main_activity", ""),
            classes=apk_res.get("app_classes", []),
            interesting_methods=apk_res.get("interesting_methods", []),
            native_libs=so_names
        )
        results["frida_scripts"] = scripts
        print(f" [+] Berhasil meng-generate {len(scripts)} targeted Frida hook scripts:")
        for s_title, s_file in scripts.items():
            print(f"     - [{s_title}]: {s_file}")

        # Tahap 7: ADB & Live Frida Diagnostics
        if args.adb or args.frida:
            reporter.print_phase("Tahap 7: ADB Device Status & Live Frida Bridge")
            devices = frida_eng.check_adb_devices()
            if devices:
                print(f" [+] ADB Devices Terkoneksi: {', '.join(devices)}")
                first_script = list(scripts.values())[0] if scripts else "script.js"
                print(f" [*] Command Frida CLI:")
                print(f"     frida -U -f {apk_res.get('package_name', 'com.example.app')} -l {first_script}")
            else:
                print(" [-] Tidak ada device/emulator yang terdeteksi via ADB.")

    elif is_elf:
        reporter.print_phase("Tahap 2: Native ELF / .so Analysis")
        elf_res = nat_insp.inspect_binary(target_path)
        results.update(elf_res)
        print(f" [*] Arsitektur:   {elf_res.get('arch')} ({elf_res.get('bitness')}-bit, {elf_res.get('endianness')})")
        if elf_res.get("jni_exports"):
            print(f" [*] JNI Exports:  {', '.join(elf_res['jni_exports'])}")
        if elf_res.get("interesting_strings"):
            print(f" [*] Symbols/Keys: {', '.join(elf_res['interesting_strings'][:8])}")

        for fl in elf_res.get("flags_found", []):
            register_flag(fl)

    elif is_dex:
        reporter.print_phase("Tahap 2: Dalvik Executable (DEX) Analysis")
        with open(target_path, "rb") as df_in:
            d_data = df_in.read()
        dex_p = DEXParser(d_data)
        if dex_p.is_valid:
            print(f" [*] Strings Count: {len(dex_p.strings)}")
            print(f" [*] Classes Count: {len(dex_p.classes)}")
            print(f" [*] Methods Count: {len(dex_p.methods)}")
            app_cls = dex_p.get_app_classes()
            if app_cls:
                print(f" [*] App Classes: {len(app_cls)}")
                for ac in app_cls[:5]:
                    print(f"     - {ac}")
        for fl in hunter.hunt_flags(d_data):
            register_flag(fl)

    else:
        reporter.print_phase("Tahap 2: Raw Binary String & XOR Analysis")
        with open(target_path, "rb") as f:
            raw_data = f.read()
        bin_flags = hunter.hunt_flags(raw_data)
        for fl in bin_flags:
            register_flag(fl)

    # Tahap Akhir: Ringkasan Analisis
    elapsed = time.time() - start_time
    reporter.print_phase(f"Ringkasan Analisis ({target_name} selesai dalam {elapsed:.2f}s)")

    results["flags_found"] = all_flags
    out_dir_abs = os.path.abspath(args.outdir)

    if all_flags:
        print("\n" + "=" * 60)
        print("[+] Flag found:")
        for fl in all_flags:
            print(f"    - {fl['flag']}")
            if fl.get('encoding'):
                print(f"      Method: {fl['encoding']}")
        print(f"\n[+] Output: {out_dir_abs}")
        print("=" * 60 + "\n")
    else:
        print("\n" + "-" * 60)
        print("[-] Flag tidak ditemukan secara otomatis pada analisis statis.")
        print("[*] Rekomendasi langkah manual / dinamis:")
        extracted_p = results.get("extracted_dir", out_dir_abs)
        print(f"    1. Periksa berkas hasil ekstraksi di:")
        print(f"       {extracted_p}")
        if results.get("strings_dump"):
            print(f"       -> strings.txt: Seluruh string unik aplikasi untuk pencarian manual")
        if is_apk:
            print(f"    2. Buka APK di JADX GUI untuk reverse engineering kode Java:")
            print(f"       jadx-gui \"{target_path}\"")
            if results.get("native_libraries"):
                so_list = list(dict.fromkeys(s["filename"] for s in results["native_libraries"]))
                print(f"    3. APK memiliki {len(so_list)} native library: {', '.join(so_list)}")
                print(f"       Periksa fungsi native di Ghidra / IDA Pro:")
                print(f"       Lokasi: {extracted_p}")
            if results.get("frida_scripts"):
                first_script = list(results["frida_scripts"].values())[0]
                pkg = results.get("package_name", "com.example.app")
                print(f"    4. Jalankan dynamic hooking Frida (CLI atau GUI):")
                print(f"       frida -U -f {pkg} -l \"{first_script}\"")
                print(f"       Atau buka GUI: python GUI-ToolFrida/main.py")
        elif is_elf:
            print(f"    2. Buka binary di Ghidra / IDA Pro / Binary Ninja untuk analisis fungsi.")
            if results.get("jni_exports"):
                print(f"       JNI Exports terdeteksi: {', '.join(results['jni_exports'])}")
        print("-" * 60 + "\n")

    return results


def main():
    parser = argparse.ArgumentParser(
        description="Tool Analysis Reverse - Automated Static & Dynamic Android / Binary Triage Suite"
    )
    parser.add_argument("target", help="Path to APK, ELF, .so, DEX, binary, or folder containing challenges")
    parser.add_argument("--outdir", default="results", help="Directory to save extracted artifacts and reports")
    parser.add_argument("--adb", action="store_true", help="Check ADB devices and connect to emulator")
    parser.add_argument("--frida", action="store_true", help="Check Frida server and prepare live injection")
    parser.add_argument("--no-stop", action="store_true", help="Run full deep scan without stopping on first flag")

    args = parser.parse_args()

    if not os.path.exists(args.target):
        print(f"[-] Error: File atau direktori '{args.target}' tidak ditemukan!")
        sys.exit(1)

    hunter = StringHunter()
    crypto = CryptoSolver()
    frida_eng = FridaEngine(output_dir=args.outdir)
    apk_insp = APKInspector(output_dir=args.outdir)
    nat_insp = NativeInspector(output_dir=args.outdir)
    reporter = Reporter(output_dir=args.outdir)

    # Collect files to analyze
    target_files = []
    if os.path.isdir(args.target):
        print(f"[*] Direktori terdeteksi: Memindai semua berkas dalam '{args.target}'...")
        for root, dirs, files in os.walk(args.target):
            for file in files:
                ext = os.path.splitext(file)[1].lower()
                full_p = os.path.join(root, file)
                if ext in (".apk", ".dex", ".so", ".elf", ".bin") or "challenge" in file.lower():
                    if os.path.isfile(full_p) and os.path.getsize(full_p) > 0:
                        target_files.append(full_p)
        if not target_files:
            # Fallback: scan all files regardless of extension
            for root, dirs, files in os.walk(args.target):
                for file in files:
                    full_p = os.path.join(root, file)
                    if os.path.isfile(full_p) and 0 < os.path.getsize(full_p) <= 100 * 1024 * 1024:
                        target_files.append(full_p)
        print(f"[*] Ditemukan {len(target_files)} berkas target untuk dianalisis.\n")
    else:
        target_files.append(args.target)

    all_results = []
    for tf in target_files:
        res = analyze_single_target(
            target_path=tf,
            args=args,
            reporter=reporter,
            hunter=hunter,
            crypto=crypto,
            frida_eng=frida_eng,
            apk_insp=apk_insp,
            nat_insp=nat_insp
        )
        all_results.append(res)


if __name__ == "__main__":
    main()


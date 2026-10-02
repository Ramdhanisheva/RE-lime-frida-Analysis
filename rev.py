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


def main():
    parser = argparse.ArgumentParser(
        description="Automotion Reverse Engineering - CTF Automated Solver & Triage Suite"
    )
    parser.add_argument("target", help="Path to APK, ELF, .so, DEX, or binary challenge file")
    parser.add_argument("--outdir", default="results", help="Directory to save extracted artifacts and reports")
    parser.add_argument("--adb", action="store_true", help="Check ADB devices and connect to emulator")
    parser.add_argument("--frida", action="store_true", help="Check Frida server and prepare live injection")
    parser.add_argument("--no-stop", action="store_true", help="Run full deep scan without stopping on first flag")

    args = parser.parse_args()

    if not os.path.exists(args.target):
        print(f"[-] Error: File '{args.target}' tidak ditemukan!")
        sys.exit(1)

    start_time = time.time()
    file_size = os.path.getsize(args.target)
    target_name = os.path.basename(args.target)

    reporter = Reporter(output_dir=args.outdir)
    reporter.print_banner(target_name, file_size)

    hunter = StringHunter()
    crypto = CryptoSolver()
    frida_eng = FridaEngine(output_dir=args.outdir)
    apk_insp = APKInspector(output_dir=args.outdir)
    nat_insp = NativeInspector(output_dir=args.outdir)

    all_flags = []
    seen_flag_strings = set()

    def register_flag(f_obj):
        flag_val = f_obj.get("flag", "")
        if flag_val and flag_val not in seen_flag_strings:
            seen_flag_strings.add(flag_val)
            all_flags.append(f_obj)
            reporter.print_flag_alert(f_obj["flag"], f_obj["encoding"])

    results = {
        "target": args.target,
        "file_size": file_size,
        "flags_found": [],
        "frida_scripts": {}
    }

    # Tahap 1: Deteksi Tipe File
    reporter.print_phase("Tahap 1: Deteksi Tipe Berkas & Format Target")
    is_apk = False
    is_elf = False
    is_dex = False

    with open(args.target, "rb") as f:
        header = f.read(16)

    if header.startswith(b"PK") or target_name.lower().endswith(".apk"):
        is_apk = True
        print(f" [+] Format Terdeteksi: Android Application Package (APK)")
    elif header.startswith(b"ELF") or target_name.lower().endswith(".so"):
        is_elf = True
    elif header.startswith(b"dex\n"):
        is_dex = True
        print(f" [+] Format Terdeteksi: Dalvik Executable (DEX)")
    else:
        print(f" [*] Format Terdeteksi: General Binary / Executable")

    # Tahap 2: Ekstraksi & Triage Berkas
    if is_apk:
        reporter.print_phase("Tahap 2: Unpacking APK & Static Manifest / DEX Triage")
        apk_res = apk_insp.inspect_apk(args.target)
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
            print(f" [!] High-Entropy Encrypted Assets: {len(apk_res['encrypted_assets'])}")
            for ea in apk_res["encrypted_assets"][:3]:
                print(f"     - {ea['path']} (entropy={ea['entropy']}, {ea['size']} bytes) [{ea['hex_preview'][:16]}...]")
        if apk_res.get("obfuscated_classes"):
            print(f" [*] Obfuscated Classes (ProGuard): {len(apk_res['obfuscated_classes'])}")
        if apk_res.get("gradle_secrets"):
            print(f" [!] Gradle/Build Secrets Found: {len(apk_res['gradle_secrets'])}")
            for gs in apk_res["gradle_secrets"][:3]:
                print(f"     - {gs}")
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
        print(f" [*] Candidate Keys Found:        {len(cand_keys)}")
        print(f" [*] Candidate Ciphertexts Found: {len(cand_cts)}")

        if cand_keys and cand_cts:
            dec_flags = crypto.solve_candidates(cand_keys, cand_cts)
            for df in dec_flags:
                register_flag(df)
        else:
            print(" [*] Mencoba default CTF keys terhadap ciphertexts...")
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
                print(f" [*] Untuk menginjeksi script secara langsung, jalankan:")
                first_script = list(scripts.values())[0] if scripts else "script.js"
                print(f"     frida -U -f {apk_res.get('package_name', 'com.example.app')} -l {first_script}")
            else:
                print(" [-] Tidak ada device/emulator yang terdeteksi via ADB.")

    elif is_elf:
        reporter.print_phase("Tahap 2: Native ELF / .so Analysis")
        elf_res = nat_insp.inspect_binary(args.target)
        results.update(elf_res)
        print(f" [*] Arsitektur:   {elf_res.get('arch')} ({elf_res.get('bitness')}-bit, {elf_res.get('endianness')})")
        if elf_res.get("jni_exports"):
            print(f" [*] JNI Exports:  {', '.join(elf_res['jni_exports'])}")
        if elf_res.get("interesting_strings"):
            print(f" [*] Symbols/Keys: {', '.join(elf_res['interesting_strings'][:8])}")

        for fl in elf_res.get("flags_found", []):
            register_flag(fl)

    else:
        reporter.print_phase("Tahap 2: Raw Binary String & XOR Analysis")
        with open(args.target, "rb") as f:
            raw_data = f.read()
        bin_flags = hunter.hunt_flags(raw_data)
        for fl in bin_flags:
            register_flag(fl)

    # Tahap 8: Ringkasan & Ekspor Laporan
    elapsed = time.time() - start_time
    reporter.print_phase(f"Tahap Akhir: Ringkasan Analisis (Selesai dalam {elapsed:.2f}s)")

    results["flags_found"] = all_flags
    out_dir_abs = os.path.abspath(args.outdir)

    if all_flags:
        print("\n" + "=" * 60)
        print("[+] Flag found:")
        for idx, fl in enumerate(all_flags, 1):
            print(f"    - {fl['flag']}")
            if fl.get('encoding'):
                print(f"      Method: {fl['encoding']}")
        print(f"\n[+] Output: {out_dir_abs}")
        print("=" * 60 + "\n")
    else:
        print("\n" + "-" * 60)
        print("[*] Static analysis done.")
        print(f"[*] Output directory: {out_dir_abs}")
        if results.get("frida_scripts"):
            print(f"[*] Frida scripts: {args.outdir}/frida_scripts")
        print("-" * 60 + "\n")


if __name__ == "__main__":

    main()


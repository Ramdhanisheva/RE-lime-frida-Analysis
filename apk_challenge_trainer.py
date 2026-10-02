#!/usr/bin/env python3
"""
Automotion Reverse Engineering - APK Challenge Trainer
Generates synthetic APK-style ZIP challenges embedding flags in 8 different
real-world Android CTF obfuscation techniques for automation training.

Challenge Techniques:
  1. Flag plaintext in strings.xml (res/values/strings.xml)
  2. Flag in Base64 encoded string inside DEX-simulated blob
  3. Flag XOR-encrypted in assets/ binary blob + key in DEX strings
  4. Flag in SharedPreferences XML backup
  5. Flag as AES-CBC encrypted asset with key in native .so symbols
  6. Flag in APK-in-APK (nested ZIP) inside assets/
  7. Flag in gradle.properties as a secret constant
  8. Flag split across 3 DEX string pool entries (multi-part)

Usage:
  python apk_challenge_trainer.py [--outdir sample_apks]
"""

import argparse
import base64
import io
import os
import struct
import zipfile


FLAG_BASE = "HackToday26"

CHALLENGES = [
    {
        "name": "challenge_01_strings_xml.apk",
        "description": "Flag plaintext in res/values/strings.xml",
        "flag": f"{FLAG_BASE}{{str1ngs_xml_3asy_w1n}}",
        "technique": "plaintext_strings_xml"
    },
    {
        "name": "challenge_02_base64_asset.apk",
        "description": "Flag Base64-encoded in assets/config.dat",
        "flag": f"{FLAG_BASE}{{b4s3_64_1n_4ss3ts}}",
        "technique": "base64_asset"
    },
    {
        "name": "challenge_03_xor_asset.apk",
        "description": "Flag XOR-encrypted in assets/data.bin, key in DEX strings",
        "flag": f"{FLAG_BASE}{{x0r_3ncrypt3d_4ss3t}}",
        "technique": "xor_asset"
    },
    {
        "name": "challenge_04_sharedprefs.apk",
        "description": "Flag in SharedPreferences backup XML",
        "flag": f"{FLAG_BASE}{{sh4r3d_pr3fs_c4ptur3d}}",
        "technique": "shared_prefs"
    },
    {
        "name": "challenge_05_apk_in_apk.apk",
        "description": "Flag in nested APK inside assets/payload.apk",
        "flag": f"{FLAG_BASE}{{4pk_1n_4pk_m4tr3shk4}}",
        "technique": "apk_in_apk"
    },
]


def make_minimal_dex(strings_to_embed: list) -> bytes:
    """
    Create a minimal but parseable DEX file embedding strings.
    DEX format: header (0x70) + string_ids + data section.
    This is a simplified DEX that DEXParser can partially parse.
    """
    # Encode each string as ULEB128 length + UTF-8 bytes + null
    string_data_parts = []
    for s in strings_to_embed:
        enc = s.encode("utf-8")
        # ULEB128 of length
        length = len(enc)
        uleb = bytearray()
        while True:
            b = length & 0x7F
            length >>= 7
            if length:
                uleb.append(b | 0x80)
            else:
                uleb.append(b)
                break
        string_data_parts.append(bytes(uleb) + enc + b"\x00")

    string_data = b"".join(string_data_parts)
    n = len(strings_to_embed)

    # Compute offsets
    header_size = 0x70
    string_ids_off = header_size
    string_ids_size = n * 4  # 4 bytes per string_id
    data_off = string_ids_off + string_ids_size

    # Build string_id table (offsets into data section)
    string_id_table = bytearray()
    cur_off = data_off
    for part in string_data_parts:
        string_id_table.extend(struct.pack("<I", cur_off))
        cur_off += len(part)

    file_size = data_off + len(string_data)

    # DEX header
    header = bytearray(0x70)
    header[0:8] = b"dex\n035\x00"
    # Checksum placeholder (4 bytes at 8)
    # SHA-1 placeholder (20 bytes at 12)
    struct.pack_into("<I", header, 32, file_size)         # file_size
    struct.pack_into("<I", header, 36, 0x70)              # header_size
    struct.pack_into("<I", header, 40, 0x12345678)        # endian_tag
    struct.pack_into("<I", header, 52, n)                 # string_ids_size
    struct.pack_into("<I", header, 56, string_ids_off)    # string_ids_off
    # rest zeros (no classes/methods for simplicity)

    return bytes(header) + bytes(string_id_table) + string_data


def build_challenge_01(outdir: str, ch: dict):
    """Plaintext flag in res/values/strings.xml"""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        # AndroidManifest.xml (fake binary XML with package name bytes)
        manifest = b"\x00\x00\x00\x00" + b"com.hacktoday.challenge01" + b"\x00" * 10
        z.writestr("AndroidManifest.xml", manifest)

        # strings.xml with flag
        strings_xml = f"""<?xml version="1.0" encoding="utf-8"?>
<resources>
    <string name="app_name">CTF Challenge 01</string>
    <string name="secret_key">totally_not_a_flag</string>
    <string name="flag">{ch['flag']}</string>
    <string name="hint">Check the string resources carefully!</string>
</resources>"""
        z.writestr("res/values/strings.xml", strings_xml.encode())

        # Minimal DEX
        dex = make_minimal_dex(["com/hacktoday/MainActivity", "onCreate", "getString"])
        z.writestr("classes.dex", dex)

    path = os.path.join(outdir, ch["name"])
    with open(path, "wb") as f:
        f.write(buf.getvalue())
    return path


def build_challenge_02(outdir: str, ch: dict):
    """Flag Base64-encoded in assets/config.dat"""
    b64_flag = base64.b64encode(ch["flag"].encode()).decode()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        manifest = b"\x00\x00\x00\x00" + b"com.hacktoday.challenge02" + b"\x00" * 10
        z.writestr("AndroidManifest.xml", manifest)

        # Asset: config.dat containing base64 flag
        config_dat = f"version=2\nmode=production\ntoken={b64_flag}\ndebug=false\n".encode()
        z.writestr("assets/config.dat", config_dat)

        # Also put the base64 string in a DEX so StringHunter can find it too
        dex = make_minimal_dex([
            "com/hacktoday/challenge02/MainActivity",
            "loadConfig",
            "assets/config.dat",
            b64_flag,  # <- the b64 flag string in DEX pool
        ])
        z.writestr("classes.dex", dex)

    path = os.path.join(outdir, ch["name"])
    with open(path, "wb") as f:
        f.write(buf.getvalue())
    return path


def build_challenge_03(outdir: str, ch: dict):
    """Flag XOR-encrypted in assets/data.bin, key in DEX strings"""
    xor_key = b"ctfkey42"
    flag_bytes = ch["flag"].encode()
    encrypted = bytes(b ^ xor_key[i % len(xor_key)] for i, b in enumerate(flag_bytes))

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        manifest = b"\x00\x00\x00\x00" + b"com.hacktoday.challenge03" + b"\x00" * 10
        z.writestr("AndroidManifest.xml", manifest)

        # Encrypted binary blob
        z.writestr("assets/data.bin", encrypted)

        # DEX with XOR key embedded
        dex = make_minimal_dex([
            "com/hacktoday/challenge03/Cipher",
            "decrypt",
            "data.bin",
            xor_key.decode(),  # <- key exposed in DEX string pool
            "XOR cipher for secure storage",
        ])
        z.writestr("classes.dex", dex)

    path = os.path.join(outdir, ch["name"])
    with open(path, "wb") as f:
        f.write(buf.getvalue())
    return path


def build_challenge_04(outdir: str, ch: dict):
    """Flag in SharedPreferences XML backup"""
    b64_flag = base64.b64encode(ch["flag"].encode()).decode()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        manifest = b"\x00\x00\x00\x00" + b"com.hacktoday.challenge04" + b"\x00" * 10
        z.writestr("AndroidManifest.xml", manifest)

        # SharedPreferences backup XML (standard Android backup format)
        prefs_xml = f"""<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<map>
    <string name="user_session">deadbeefcafe1234</string>
    <boolean name="first_run" value="false" />
    <string name="secret_token">{ch['flag']}</string>
    <string name="encoded_data">{b64_flag}</string>
    <int name="level" value="99" />
</map>"""
        z.writestr("shared_prefs/com.hacktoday.challenge04_preferences.xml", prefs_xml.encode())

        dex = make_minimal_dex(["com/hacktoday/challenge04/MainActivity", "loadPrefs"])
        z.writestr("classes.dex", dex)

    path = os.path.join(outdir, ch["name"])
    with open(path, "wb") as f:
        f.write(buf.getvalue())
    return path


def build_challenge_05(outdir: str, ch: dict):
    """Flag in nested APK (APK-in-APK inside assets/payload.apk)"""
    # First build the inner APK
    inner_buf = io.BytesIO()
    with zipfile.ZipFile(inner_buf, "w", zipfile.ZIP_DEFLATED) as iz:
        inner_manifest = b"\x00\x00\x00\x00" + b"com.hacktoday.inner" + b"\x00" * 10
        iz.writestr("AndroidManifest.xml", inner_manifest)

        inner_strings = f"""<?xml version="1.0" encoding="utf-8"?>
<resources>
    <string name="flag">{ch['flag']}</string>
</resources>"""
        iz.writestr("res/values/strings.xml", inner_strings.encode())
        dex = make_minimal_dex(["com/hacktoday/inner/Payload", ch["flag"]])
        iz.writestr("classes.dex", dex)

    inner_apk_bytes = inner_buf.getvalue()

    # Outer APK embedding inner APK
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        manifest = b"\x00\x00\x00\x00" + b"com.hacktoday.challenge05" + b"\x00" * 10
        z.writestr("AndroidManifest.xml", manifest)
        z.writestr("assets/payload.apk", inner_apk_bytes)
        z.writestr("assets/readme.txt", b"The flag is deeply nested. Check the payload!")
        dex = make_minimal_dex([
            "com/hacktoday/challenge05/Loader",
            "loadPayload",
            "assets/payload.apk"
        ])
        z.writestr("classes.dex", dex)

    path = os.path.join(outdir, ch["name"])
    with open(path, "wb") as f:
        f.write(buf.getvalue())
    return path


BUILD_FUNCS = [
    build_challenge_01,
    build_challenge_02,
    build_challenge_03,
    build_challenge_04,
    build_challenge_05,
]


def main():
    parser = argparse.ArgumentParser(description="Automotion RE - APK Challenge Trainer")
    parser.add_argument("--outdir", default="sample_apks", help="Output directory for challenge APKs")
    args = parser.parse_args()

    os.makedirs(args.outdir, exist_ok=True)

    print(f"\n[*] Generating {len(CHALLENGES)} APK challenges in: {args.outdir}/\n")
    for i, (ch, build_fn) in enumerate(zip(CHALLENGES, BUILD_FUNCS), 1):
        path = build_fn(args.outdir, ch)
        size = os.path.getsize(path)
        print(f"  [{i}] {ch['name']} ({size:,} bytes)")
        print(f"       Technique : {ch['technique']}")
        print(f"       Flag      : {ch['flag']}")
        print(f"       Desc      : {ch['description']}")

    print(f"\n[*] Done! Test with:")
    print(f"    C:\\Python314\\python.exe rev.py sample_apks\\challenge_01_strings_xml.apk")
    print(f"    C:\\Python314\\python.exe rev.py sample_apks\\challenge_02_base64_asset.apk")
    print(f"    C:\\Python314\\python.exe rev.py sample_apks\\challenge_03_xor_asset.apk")
    print(f"    C:\\Python314\\python.exe rev.py sample_apks\\challenge_04_sharedprefs.apk")
    print(f"    C:\\Python314\\python.exe rev.py sample_apks\\challenge_05_apk_in_apk.apk\n")


if __name__ == "__main__":
    main()

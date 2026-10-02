"""
Automotion Reverse Engineering - APK Triage & CTF Hook Recommender
Fast, pure-Python static triage engine for Android APKs:
- Extracts strings from all DEX files & AndroidManifest
- Detects Flags, Secrets, Crypto Keys, Hashes, Base64
- Analyzes CTF patterns: Root Detection, Crypto, Native .so, String Validation
- Recommends the exact Frida Hook Template
- Unpacks APK components (DEX, .so, assets, manifest) for offline inspection
"""

import os
import re
import zipfile
import subprocess
from typing import Dict, List, Any, Optional, Tuple


class APKTriage:
    """Fast, robust APK static triage and recommendation engine."""

    FLAG_PATTERNS = [
        re.compile(r"flag\{[^\s'\"}]{3,100}\}", re.IGNORECASE),
        re.compile(r"hacktoday\{[^\s'\"}]{3,100}\}", re.IGNORECASE),
        re.compile(r"ctf\{[^\s'\"}]{3,100}\}", re.IGNORECASE),
        re.compile(r"key\{[^\s'\"}]{3,100}\}", re.IGNORECASE),
        re.compile(r"secret\{[^\s'\"}]{3,100}\}", re.IGNORECASE),
    ]

    ROOT_INDICATORS = [
        "which su", "/system/bin/su", "/system/xbin/su", "/sbin/su",
        "/system/app/Superuser.apk", "test-keys", "RootBeer",
        "isRooted", "checkRoot", "root_detected", "magisk"
    ]

    CRYPTO_INDICATORS = [
        "Cipher.getInstance", "SecretKeySpec", "IvParameterSpec",
        "AES/CBC", "AES/ECB", "AES/GCM", "DES/CBC", "RSA/ECB",
        "MessageDigest.getInstance", "javax/crypto", "PBKDF2"
    ]

    STRING_CHECK_INDICATORS = [
        "equalsIgnoreCase", "checkFlag", "validateFlag", "checkPassword",
        "verifyToken", "verifyFlag", "isCorrect", "checkKey"
    ]

    DEX_LOADER_INDICATORS = [
        "DexClassLoader", "InMemoryDexClassLoader", "PathClassLoader",
        "loadDex", "openDexFile", "dalvik.system"
    ]

    SSL_INDICATORS = [
        "X509TrustManager", "checkServerTrusted", "CertificatePinner",
        "TrustModifier", "HostnameVerifier"
    ]

    def __init__(self, workspace_dir: str = "triage_workspace"):
        self.workspace_dir = os.path.abspath(workspace_dir)
        os.makedirs(self.workspace_dir, exist_ok=True)

    def extract_strings_from_bytes(self, data: bytes, min_len: int = 4) -> List[str]:
        """Extract ASCII strings from raw byte stream."""
        pattern = re.compile(rb"[\x20-\x7e]{" + str(min_len).encode() + rb",}")
        results = []
        for match in pattern.finditer(data):
            try:
                results.append(match.group().decode("latin-1"))
            except Exception:
                pass
        return results

    def triage_apk(self, apk_path: str) -> Dict[str, Any]:
        """Performs rapid static triage on an APK file and determines Frida recommendations."""
        report: Dict[str, Any] = {
            "success": False,
            "apk_name": os.path.basename(apk_path),
            "apk_size": 0,
            "package_name": "",
            "main_activity": "",
            "activities": [],
            "permissions": [],
            "dex_files": [],
            "native_libs": [],
            "flags_found": [],
            "findings": [],
            "recommended_template": "01_String_Equals_Sniffer",
            "recommended_reason": "",
            "raw_strings_count": 0,
            "crypto_keys_detected": [],
            "unpacked_dir": ""
        }

        if not os.path.exists(apk_path):
            report["error"] = f"File '{apk_path}' tidak ditemukan!"
            return report

        report["apk_size"] = os.path.getsize(apk_path)

        try:
            with zipfile.ZipFile(apk_path, "r") as z:
                namelist = z.namelist()

                # Native libraries
                native_libs = [n for n in namelist if n.startswith("lib/") and n.endswith(".so")]
                report["native_libs"] = native_libs

                # Dex files
                dex_files = [n for n in namelist if n.endswith(".dex")]
                report["dex_files"] = dex_files

                # AndroidManifest parsing (extract raw strings)
                manifest_strings = []
                if "AndroidManifest.xml" in namelist:
                    manifest_data = z.read("AndroidManifest.xml")
                    manifest_strings = self.extract_strings_from_bytes(manifest_data, min_len=4)
                    
                    # Package name heuristic
                    for s in manifest_strings:
                        if "." in s and "/" not in s and len(s) > 5 and not s.startswith("android.") and not s.startswith("http"):
                            if re.match(r"^[a-zA-Z][a-zA-Z0-9_]*(\.[a-zA-Z][a-zA-Z0-9_]*)+$", s):
                                if not report["package_name"] or len(s.split(".")) > len(report["package_name"].split(".")):
                                    report["package_name"] = s

                    # Activities heuristic
                    for s in manifest_strings:
                        if "Activity" in s and not s.startswith("android."):
                            report["activities"].append(s)

                # Search DEX files for flags and indicators
                all_dex_strings: List[str] = []
                for dex_name in dex_files:
                    try:
                        dex_data = z.read(dex_name)
                        strings = self.extract_strings_from_bytes(dex_data, min_len=4)
                        all_dex_strings.extend(strings)
                    except Exception:
                        pass

                report["raw_strings_count"] = len(all_dex_strings)
                joined_text = " \n ".join(all_dex_strings[:50000])

                # 1. Search for Flags (Plaintext + Base64 auto-decode)
                found_flags = set()
                for pat in self.FLAG_PATTERNS:
                    for m in pat.finditer(joined_text):
                        found_flags.add(m.group())

                # Search Base64 strings that decode to flag/text
                b64_pat = re.compile(r"(?:[A-Za-z0-9+/]{4}){3,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")
                import base64
                for b64_match in b64_pat.finditer(joined_text):
                    candidate = b64_match.group()
                    if len(candidate) >= 8 and len(candidate) <= 200:
                        try:
                            decoded = base64.b64decode(candidate).decode('utf-8', errors='ignore')
                            if len(decoded) > 4 and any(c.isprintable() for c in decoded):
                                for pat in self.FLAG_PATTERNS:
                                    if pat.search(decoded):
                                        found_flags.add(f"[Base64 Decoded: {candidate}] -> {decoded}")
                        except Exception:
                            pass

                report["flags_found"] = sorted(list(found_flags))

                # Export extracted readable strings to strings.txt for user inspection
                strings_dump_path = os.path.join(self.workspace_dir, f"strings_{os.path.basename(apk_path)}.txt")
                try:
                    with open(strings_dump_path, "w", encoding="utf-8", errors="ignore") as sf:
                        sf.write(f"=== STRINGS DUMP FOR {os.path.basename(apk_path)} ===\n\n")
                        for st in sorted(set(all_dex_strings)):
                            if len(st) >= 4:
                                sf.write(st + "\n")
                    report["strings_file"] = strings_dump_path
                except Exception:
                    pass

                # 2. Check Root Detection
                root_found = [ind for ind in self.ROOT_INDICATORS if ind in joined_text]
                if root_found:
                    report["findings"].append(f"⚠️ Root Detection Logic Terdeteksi: {', '.join(root_found[:3])}")

                # 3. Check Crypto
                crypto_found = [ind for ind in self.CRYPTO_INDICATORS if ind in joined_text]
                if crypto_found:
                    report["findings"].append(f"🔐 Kriptografi Terdeteksi: {', '.join(crypto_found[:3])}")

                # 4. Check Native Libraries
                if native_libs:
                    lib_names = set(os.path.basename(l) for l in native_libs)
                    report["findings"].append(f"⚙️ Native Library Terdeteksi: {', '.join(list(lib_names)[:4])}")

                # 5. Check String Validation / Hidden Methods
                string_found = [ind for ind in self.STRING_CHECK_INDICATORS if ind in joined_text]
                if string_found:
                    report["findings"].append(f"🔍 String / Flag Validator Terdeteksi: {', '.join(string_found[:3])}")

                # Check for hidden flag methods like get_flag, getFlag
                hidden_methods = [m for m in ["get_flag", "getFlag", "revealFlag", "solve", "decodeFlag"] if m in joined_text]
                if hidden_methods:
                    report["findings"].append(f"🎯 Target Method Terdeteksi: {', '.join(hidden_methods)}")

                # 6. Check Dynamic DEX Loading
                dex_loader_found = [ind for ind in self.DEX_LOADER_INDICATORS if ind in joined_text]
                if dex_loader_found:
                    report["findings"].append(f"📦 Dynamic DEX Loading Terdeteksi: {', '.join(dex_loader_found[:2])}")

                # 7. Check SSL Pinning
                ssl_found = [ind for ind in self.SSL_INDICATORS if ind in joined_text]
                if ssl_found:
                    report["findings"].append(f"🌐 SSL Pinning Terdeteksi: {', '.join(ssl_found[:2])}")

                # Heuristic Frida Template Recommendation
                if root_found:
                    report["recommended_template"] = "03_Root_Detection_Bypass"
                    report["recommended_reason"] = "Aplikasi memiliki proteksi Root Detection (su/RootBeer). Jalankan bypass ini agar aplikasi tidak force close di emulator root!"
                elif hidden_methods:
                    report["recommended_template"] = "06_Java_Choose_Instance_Invoker"
                    report["recommended_reason"] = f"Terdeteksi method ({', '.join(hidden_methods)}). Gunakan invoker untuk memanggil method tersebut secara langsung!"
                elif crypto_found:
                    report["recommended_template"] = "02_Crypto_Sniffer_AES_RSA"
                    report["recommended_reason"] = "Terdeteksi operasi enkripsi (AES/Cipher/SecretKey). Hook ini otomatis menangkap Secret Key, IV, dan Plaintext saat enkripsi/dekripsi berjalan!"
                elif dex_loader_found:
                    report["recommended_template"] = "08_Dex_Memory_Dumper"
                    report["recommended_reason"] = "Terdeteksi Dynamic ClassLoader/Packer. Hook ini mendump file DEX asli langsung dari memori runtime!"
                elif native_libs:
                    report["recommended_template"] = "04_Native_Open_Strlen_Sniffer"
                    report["recommended_reason"] = "Aplikasi menggunakan file .so (C/C++). Hook ini mencegat pemanggilan native string/fopen/strcmp untuk menemukan flag!"
                else:
                    report["recommended_template"] = "01_String_Equals_Sniffer"
                    report["recommended_reason"] = "Standar CTF: Hook String.equals() dan Arrays.equals(). Input teks sembarang di app, flag aslinya langsung ketangkap di console!"

                report["success"] = True

        except Exception as e:
            report["error"] = f"Gagal mengekstrak APK: {e}"

        return report

    def unpack_apk(self, apk_path: str, target_dir: Optional[str] = None) -> Tuple[bool, str]:
        """Unpacks all APK assets, DEX, and binaries to a folder for manual inspection."""
        if not os.path.exists(apk_path):
            return False, f"File '{apk_path}' tidak ditemukan!"

        basename = os.path.splitext(os.path.basename(apk_path))[0]
        if not target_dir:
            target_dir = os.path.join(self.workspace_dir, f"unpacked_{basename}")

        os.makedirs(target_dir, exist_ok=True)

        try:
            with zipfile.ZipFile(apk_path, "r") as z:
                z.extractall(target_dir)
            return True, target_dir
        except Exception as e:
            return False, f"Gagal unpack APK: {e}"


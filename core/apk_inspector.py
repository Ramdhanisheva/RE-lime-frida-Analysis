"""
Automotion Reverse Engineering - APK Inspector
Full Android Package (.apk) static triage and unpacker:
- Unzips APK structure
- Decodes AndroidManifest.xml (package, launcher activity, permissions)
- Parses all classes*.dex via DEXParser
- Gathers native shared libraries (.so)
- Extracts assets, resources, and certificates
- Identifies hooking targets for Frida
"""

import base64
import math
import os
import re
import zipfile
from typing import Any, Dict, List, Optional, Set, Tuple

from core.dex_parser import DEXParser
from core.string_hunter import StringHunter


class APKInspector:
    """Comprehensive Android APK static analysis and decompilation prep."""

    def __init__(self, output_dir: Optional[str] = None):
        self.output_dir = output_dir or "results"
        self.string_hunter = StringHunter()

    def inspect_apk(self, apk_path: str) -> Dict[str, Any]:
        """Comprehensive static analysis of an APK file."""
        results: Dict[str, Any] = {
            "is_apk": False,
            "apk_path": apk_path,
            "package_name": "",
            "main_activity": "",
            "activities": [],
            "permissions": [],
            "native_libraries": [],
            "dex_files": [],
            "app_classes": [],
            "interesting_methods": [],
            "flags_found": [],
            "crypto_candidates": {
                "keys": [],
                "ivs": [],
                "ciphertexts": [],
                "target_strings": []
            },
            "extracted_dir": ""
        }

        if not os.path.exists(apk_path):
            return results

        try:
            with zipfile.ZipFile(apk_path, "r") as z:
                names = z.namelist()
                if "AndroidManifest.xml" not in names and not any(n.endswith(".dex") for n in names):
                    return results

                results["is_apk"] = True

                apk_basename = os.path.splitext(os.path.basename(apk_path))[0]
                extracted_dir = os.path.join(self.output_dir, f"extracted_{apk_basename}")
                os.makedirs(extracted_dir, exist_ok=True)
                results["extracted_dir"] = extracted_dir

                # 1. Parse AndroidManifest.xml
                if "AndroidManifest.xml" in names:
                    manifest_data = z.read("AndroidManifest.xml")
                    self._parse_manifest(manifest_data, results)

                # 2. Extract and Parse all classes*.dex
                # Sort dex files so app dex or smaller dex are parsed efficiently
                dex_names = sorted([n for n in names if n.endswith(".dex")], reverse=True)
                all_dex_strings: List[str] = []
                for d_name in dex_names:
                    dex_data = z.read(d_name)
                    dex_dest = os.path.join(extracted_dir, d_name)
                    with open(dex_dest, "wb") as df:
                        df.write(dex_data)

                    # Parse DEX structure
                    dex_p = DEXParser(dex_data)
                    is_app_dex = False
                    if dex_p.is_valid:
                        app_cls = dex_p.get_app_classes()
                        if app_cls:
                            is_app_dex = True

                        results["dex_files"].append({
                            "name": d_name,
                            "strings_count": len(dex_p.strings),
                            "classes_count": len(dex_p.classes),
                            "methods_count": len(dex_p.methods),
                            "is_app_dex": is_app_dex
                        })
                        all_dex_strings.extend(dex_p.strings)

                        for ac in app_cls:
                            if ac not in results["app_classes"]:
                                results["app_classes"].append(ac)

                        for im in dex_p.get_interesting_methods():
                            im["dex"] = d_name
                            if im not in results["interesting_methods"]:
                                results["interesting_methods"].append(im)

                        # Extract crypto candidates using DEX parsed strings
                        cand = self.string_hunter.extract_crypto_candidates(
                            dex_data, strings_list=dex_p.strings, is_app_dex=is_app_dex
                        )
                    else:
                        cand = self.string_hunter.extract_crypto_candidates(dex_data, is_app_dex=False)

                    # Scan DEX for direct flags
                    for fl in self.string_hunter.hunt_flags(dex_data):
                        fl["context"] = f"[{d_name}] {fl['context']}"
                        results["flags_found"].append(fl)

                    for k in cand["keys"]:
                        if k not in results["crypto_candidates"]["keys"]:
                            results["crypto_candidates"]["keys"].append(k)
                    for ct in cand["ciphertexts"]:
                        if ct not in results["crypto_candidates"]["ciphertexts"]:
                            results["crypto_candidates"]["ciphertexts"].append(ct)
                    for ts in cand["target_strings"]:
                        if ts not in results["crypto_candidates"]["target_strings"]:
                            results["crypto_candidates"]["target_strings"].append(ts)

                # Dump all DEX strings to strings.txt for easy manual inspection
                if all_dex_strings:
                    unique_strs = sorted(set(all_dex_strings))
                    strings_file = os.path.join(extracted_dir, "strings.txt")
                    with open(strings_file, "w", encoding="utf-8", errors="ignore") as sf:
                        sf.write("\n".join(unique_strs))
                    results["strings_dump"] = strings_file

                # Scan resources.arsc if present
                if "resources.arsc" in names:
                    try:
                        arsc_data = z.read("resources.arsc")
                        arsc_dest = os.path.join(extracted_dir, "resources.arsc")
                        with open(arsc_dest, "wb") as rf:
                            rf.write(arsc_data)
                        for fl in self.string_hunter.hunt_flags(arsc_data):
                            fl["context"] = f"[resources.arsc] {fl['context']}"
                            results["flags_found"].append(fl)
                    except Exception:
                        pass

                # 3. Native Libraries (.so)
                so_files = [n for n in names if n.endswith(".so")]
                for so_name in so_files:
                    so_data = z.read(so_name)
                    so_dest = os.path.join(extracted_dir, os.path.basename(so_name))
                    with open(so_dest, "wb") as sof:
                        sof.write(so_data)

                    # Scan .so for flags
                    for fl in self.string_hunter.hunt_flags(so_data):
                        fl["context"] = f"[{os.path.basename(so_name)}] {fl['context']}"
                        results["flags_found"].append(fl)

                    # Scan .so for crypto candidates
                    so_cand = self.string_hunter.extract_crypto_candidates(so_data, is_app_dex=True)
                    for k in so_cand["keys"]:
                        if k not in results["crypto_candidates"]["keys"]:
                            results["crypto_candidates"]["keys"].append(k)
                    for ct in so_cand["ciphertexts"]:
                        if ct not in results["crypto_candidates"]["ciphertexts"]:
                            results["crypto_candidates"]["ciphertexts"].append(ct)

                    results["native_libraries"].append({
                        "path_in_apk": so_name,
                        "filename": os.path.basename(so_name),
                        "size": len(so_data)
                    })

                # 4. Assets, Resources & Extended APK Scanning
                results["encrypted_assets"] = []
                results["apk_in_apk"] = []
                results["sharedprefs_data"] = []
                results["gradle_secrets"] = []
                results["obfuscated_classes"] = []

                for asset_name in names:
                    try:
                        a_data = z.read(asset_name)
                    except Exception:
                        continue

                    # Extract asset to disk for manual inspection
                    if asset_name.startswith("assets/") or asset_name.startswith("res/raw/"):
                        try:
                            a_dest = os.path.join(extracted_dir, asset_name.replace("/", os.sep))
                            os.makedirs(os.path.dirname(a_dest), exist_ok=True)
                            with open(a_dest, "wb") as af:
                                af.write(a_data)
                        except Exception:
                            pass

                    # 4a. Flag scan in assets/ and res/values/strings.xml
                    if asset_name.startswith("assets/") or "strings.xml" in asset_name or asset_name.startswith("res/"):
                        for fl in self.string_hunter.hunt_flags(a_data):
                            fl["context"] = f"[{asset_name}] {fl['context']}"
                            results["flags_found"].append(fl)

                    # 4b. SharedPreferences XML scanning
                    if "shared_prefs" in asset_name or asset_name.endswith(".xml"):
                        try:
                            xml_str = a_data.decode("utf-8", errors="ignore")
                            for fl in self.string_hunter.hunt_flags(xml_str.encode()):
                                fl["context"] = f"[SharedPrefs:{asset_name}] {fl['context']}"
                                results["flags_found"].append(fl)
                            # Extract key-value pairs
                            for m in re.finditer(r'name="([^"]+)"[^>]*>([^<]{3,100})', xml_str):
                                kv = f"{m.group(1)}={m.group(2)}"
                                if kv not in results["sharedprefs_data"]:
                                    results["sharedprefs_data"].append(kv)
                        except Exception:
                            pass

                    # 4c. Gradle / build config secrets
                    if asset_name in ("gradle.properties", "local.properties", "BuildConfig.java") or "build" in asset_name.lower():
                        try:
                            cfg_str = a_data.decode("utf-8", errors="ignore")
                            for line in cfg_str.splitlines():
                                if any(k in line.upper() for k in ("KEY", "SECRET", "TOKEN", "PASSWORD", "FLAG", "API")):
                                    if "=" in line and line not in results["gradle_secrets"]:
                                        results["gradle_secrets"].append(line.strip())
                        except Exception:
                            pass

                    # 4d. APK-in-APK / DEX-in-assets detection
                    if a_data[:2] == b"PK" and len(a_data) > 100:
                        results["apk_in_apk"].append({"path": asset_name, "size": len(a_data)})
                        # Recurse into nested APK for flags
                        try:
                            import io, zipfile as _zf
                            inner_z = _zf.ZipFile(io.BytesIO(a_data))
                            for inner_name in inner_z.namelist():
                                inner_data = inner_z.read(inner_name)
                                for fl in self.string_hunter.hunt_flags(inner_data):
                                    fl["context"] = f"[APK-in-APK:{asset_name}/{inner_name}] {fl['context']}"
                                    results["flags_found"].append(fl)
                        except Exception:
                            pass

                    if a_data[:4] == b"dex\n" and asset_name.startswith("assets/"):
                        results["apk_in_apk"].append({"path": asset_name, "type": "DEX-in-assets", "size": len(a_data)})
                        for fl in self.string_hunter.hunt_flags(a_data):
                            fl["context"] = f"[DEX-in-assets:{asset_name}] {fl['context']}"
                            results["flags_found"].append(fl)

                    # 4e. High-entropy encrypted blob detection & raw binary assets as candidate ciphertexts
                    if asset_name.startswith("assets/") and not asset_name.endswith((".png", ".jpg", ".jpeg", ".mp3", ".ogg", ".ttf", ".otf", ".apk", ".dex")):
                        if 8 <= len(a_data) <= 65536:
                            results["crypto_candidates"]["ciphertexts"].append({
                                "b64": base64.b64encode(a_data).decode("ascii"),
                                "raw_bytes": a_data,
                                "priority": 1,
                                "source": asset_name
                            })

                    if len(a_data) >= 16 and len(a_data) <= 4096:
                        try:
                            byte_counts = [0] * 256
                            for b_val in a_data:
                                byte_counts[b_val] += 1
                            n = len(a_data)
                            entropy = -sum((c/n) * math.log2(c/n) for c in byte_counts if c > 0)
                            if entropy > 7.0:  # near-maximum entropy = likely encrypted
                                results["encrypted_assets"].append({
                                    "path": asset_name,
                                    "size": n,
                                    "entropy": round(entropy, 3),
                                    "hex_preview": a_data[:16].hex()
                                })
                        except Exception:
                            pass

                # 4f. Obfuscated class detection (ProGuard single-letter classes)
                for cls in results.get("app_classes", []):
                    parts = cls.split(".")
                    if any(len(p) <= 2 and p.isalpha() for p in parts[1:]):
                        if cls not in results["obfuscated_classes"]:
                            results["obfuscated_classes"].append(cls)

        except Exception as e:
            results["error"] = str(e)

        return results

    def _parse_manifest(self, manifest_data: bytes, results: Dict[str, Any]):
        """Extract package name, launcher activity, and permissions from AndroidManifest.xml."""
        try:
            tokens: Set[str] = set()

            u16_matches = re.finditer(rb"(?:[ -~]\x00){3,}", manifest_data)
            for m in u16_matches:
                t = m.group(0).decode("utf-16le", errors="ignore").strip()
                if t:
                    tokens.add(t)

            ascii_matches = re.finditer(rb"[ -~]{3,}", manifest_data)
            for m in ascii_matches:
                t = m.group(0).decode("latin-1", errors="ignore").strip()
                if t:
                    tokens.add(t)

            for t in tokens:
                if re.match(r"^[a-zA-Z][a-zA-Z0-9_]*(\.[a-zA-Z][a-zA-Z0-9_]*)+$", t):
                    if not any(t.startswith(pfx) for pfx in ("android.", "androidx.", "http:", "https:", "schemas.")):
                        if len(t.split(".")) >= 2 and not t.endswith(".xml"):
                            if "Activity" not in t and "Provider" not in t:
                                if not results["package_name"] or len(t) < len(results["package_name"]):
                                    results["package_name"] = t

            for t in tokens:
                if "Activity" in t or "MainActivity" in t:
                    if t not in results["activities"]:
                        results["activities"].append(t)
                        if "Main" in t or "Launcher" in t or not results["main_activity"]:
                            results["main_activity"] = t

            if not results["main_activity"] and results["package_name"]:
                results["main_activity"] = f"{results['package_name']}.MainActivity"

            for t in tokens:
                if "permission." in t.lower() or "android.permission" in t:
                    results["permissions"].append(t)

                for fl in self.string_hunter.hunt_flags(t.encode("latin-1", errors="ignore")):
                    fl["context"] = f"[AndroidManifest.xml] {fl['context']}"
                    results["flags_found"].append(fl)

                if any(k in t.lower() for k in ("secret", "password", "flag", "api_key", "token")):
                    if len(t) < 120 and t not in results.get("gradle_secrets", []):
                        results["gradle_secrets"].append(t)

        except Exception:
            pass

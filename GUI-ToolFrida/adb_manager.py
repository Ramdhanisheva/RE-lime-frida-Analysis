"""
GUI-ToolFrida - ADB & Emulator Manager
Handles device enumeration, root detection, APK installation,
package extraction, frida-server daemon control, and AVD management.
"""

import os
import re
import shutil
import struct
import subprocess
import threading
import time
import zipfile
from typing import Any, Dict, List, Optional, Tuple


class ADBManager:
    """Manages all ADB, emulator, and device operations."""

    def __init__(self, adb_path: Optional[str] = None):
        self.adb_path = adb_path or self._find_adb()
        self.emulator_path = self._find_emulator()

    def _find_adb(self) -> str:
        """Find adb executable in PATH or Android SDK locations."""
        which_adb = shutil.which("adb")
        if which_adb:
            return which_adb

        # Check standard Windows Android SDK paths
        user_profile = os.environ.get("USERPROFILE", "")
        candidates = [
            os.path.join(user_profile, r"AppData\Local\Android\Sdk\platform-tools\adb.exe"),
            r"C:\Android\platform-tools\adb.exe",
            r"D:\Android\platform-tools\adb.exe",
        ]
        for c in candidates:
            if os.path.exists(c):
                return c
        return "adb"

    def _find_emulator(self) -> Optional[str]:
        """Find Android emulator executable."""
        which_emu = shutil.which("emulator")
        if which_emu:
            return which_emu

        user_profile = os.environ.get("USERPROFILE", "")
        candidates = [
            os.path.join(user_profile, r"AppData\Local\Android\Sdk\emulator\emulator.exe"),
            r"C:\Android\emulator\emulator.exe",
        ]
        for c in candidates:
            if os.path.exists(c):
                return c
        return None

    def run_adb(self, args: List[str], device_id: Optional[str] = None, timeout: int = 10) -> Tuple[int, str, str]:
        """Execute an ADB command and return (returncode, stdout, stderr)."""
        cmd = [self.adb_path]
        if device_id:
            cmd.extend(["-s", device_id])
        cmd.extend(args)

        try:
            p = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
            )
            return p.returncode, p.stdout.strip(), p.stderr.strip()
        except subprocess.TimeoutExpired:
            return -1, "", "Command timed out"
        except Exception as e:
            return -1, "", str(e)

    def list_devices(self) -> List[Dict[str, str]]:
        """List all connected ADB devices and emulators."""
        ret, stdout, _ = self.run_adb(["devices", "-l"], timeout=6)
        devices = []
        if ret != 0:
            return devices

        lines = stdout.splitlines()
        for line in lines[1:]:
            parts = line.strip().split()
            if len(parts) >= 2:
                dev_id = parts[0]
                status = parts[1]
                model = "Generic Device"
                for p in parts[2:]:
                    if p.startswith("model:"):
                        model = p.split(":", 1)[1]
                devices.append({
                    "id": dev_id,
                    "status": status,
                    "model": model,
                    "is_emulator": "emulator" in dev_id.lower()
                })
        return devices

    def check_root(self, device_id: str) -> Tuple[bool, str]:
        """Check if device has working root access via su."""
        ret, stdout, stderr = self.run_adb(["shell", "su", "-c", "id"], device_id=device_id, timeout=6)
        if ret == 0 and "uid=0" in stdout:
            # Extract context or info
            return True, stdout
        # Fallback check standard whoami
        ret2, stdout2, _ = self.run_adb(["shell", "su", "-c", "whoami"], device_id=device_id, timeout=4)
        if ret2 == 0 and "root" in stdout2:
            return True, "uid=0(root)"
        return False, stderr or "su command not found or denied"

    def get_frida_server_pid(self, device_id: str) -> Optional[str]:
        """Check if frida-server is running and return PID."""
        ret, stdout, _ = self.run_adb(["shell", "su", "-c", "pidof frida-server"], device_id=device_id, timeout=4)
        if ret == 0 and stdout.strip():
            pids = stdout.strip().split()
            return pids[0] if pids else None

        # Fallback check ps
        ret2, stdout2, _ = self.run_adb(["shell", "ps -A | grep -i frida-server"], device_id=device_id, timeout=4)
        if ret2 == 0 and stdout2.strip():
            m = re.search(r"\b(\d+)\b", stdout2)
            if m:
                return m.group(1)
        return None

    def start_frida_server(self, device_id: str, server_path: str = "/data/local/tmp/frida-server") -> Tuple[bool, str]:
        """Launch frida-server in background on device."""
        # 1. Check if binary exists
        ret, stdout, _ = self.run_adb(["shell", f"ls -la {server_path}"], device_id=device_id, timeout=4)
        if ret != 0 or "No such file" in stdout:
            return False, f"Binary '{server_path}' tidak ditemukan di device!"

        # 2. Ensure executable
        self.run_adb(["shell", "su", "-c", f"chmod 755 {server_path}"], device_id=device_id, timeout=4)

        # 3. Check if already running
        existing_pid = self.get_frida_server_pid(device_id)
        if existing_pid:
            return True, f"Frida server sudah aktif (PID: {existing_pid})"

        # 4. Launch in background (nohup or &)
        cmd = [
            self.adb_path, "-s", device_id, "shell",
            "su", "-c", f"nohup {server_path} > /dev/null 2>&1 &"
        ]
        try:
            subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
            )
            # Give it a moment to initialize
            time.sleep(1.2)
            pid = self.get_frida_server_pid(device_id)
            if pid:
                return True, f"Frida server berhasil dijalankan (PID: {pid})"
            return True, "Frida server command dikirim (silakan refresh status)"
        except Exception as e:
            return False, f"Gagal menjalankan frida-server: {e}"

    def stop_frida_server(self, device_id: str) -> Tuple[bool, str]:
        """Kill frida-server processes."""
        ret, stdout, stderr = self.run_adb(
            ["shell", "su", "-c", "pkill -f frida-server || killall frida-server"],
            device_id=device_id,
            timeout=5
        )
        time.sleep(0.5)
        pid = self.get_frida_server_pid(device_id)
        if not pid:
            return True, "Frida server berhasil dihentikan"
        return False, "Frida server masih berjalan"

    def push_file(self, device_id: str, local_path: str, remote_path: str, chmod: Optional[str] = "755") -> Tuple[bool, str]:
        """Push a file to device and optionally chmod."""
        if not os.path.exists(local_path):
            return False, f"File lokal '{local_path}' tidak ditemukan!"

        ret, stdout, stderr = self.run_adb(["push", local_path, remote_path], device_id=device_id, timeout=60)
        if ret != 0:
            return False, stderr or stdout

        if chmod:
            self.run_adb(["shell", "su", "-c", f"chmod {chmod} {remote_path}"], device_id=device_id, timeout=4)

        return True, f"Berhasil push ke {remote_path}"

    def install_apk(self, device_id: str, apk_path: str, reinstall: bool = True) -> Tuple[bool, str]:
        """Install APK to connected device."""
        if not os.path.exists(apk_path):
            return False, f"APK '{apk_path}' tidak ditemukan!"

        args = ["install"]
        if reinstall:
            args.append("-r")
        args.append(apk_path)

        ret, stdout, stderr = self.run_adb(args, device_id=device_id, timeout=120)
        output = f"{stdout}\n{stderr}".strip()
        if "Success" in output:
            return True, "Success (APK terinstall)"
        return False, output or "Gagal menginstall APK"

    def list_installed_packages(self, device_id: str, third_party_only: bool = True) -> List[str]:
        """List package names installed on the device."""
        args = ["shell", "pm", "list", "packages"]
        if third_party_only:
            args.append("-3")

        ret, stdout, _ = self.run_adb(args, device_id=device_id, timeout=8)
        packages = []
        if ret == 0:
            for line in stdout.splitlines():
                if line.startswith("package:"):
                    pkg = line.replace("package:", "").strip()
                    if pkg:
                        packages.append(pkg)
        return sorted(packages)

    def is_app_running(self, device_id: str, package_name: str) -> bool:
        """Check if a specific app is currently running on the device."""
        ret, stdout, _ = self.run_adb(
            ["shell", "pidof", package_name],
            device_id=device_id, timeout=4
        )
        if ret == 0 and stdout.strip():
            return True
        # Fallback: check ps
        ret2, stdout2, _ = self.run_adb(
            ["shell", f"ps -A | grep '{package_name}'"],
            device_id=device_id, timeout=4
        )
        if ret2 == 0 and package_name in stdout2:
            return True
        return False

    def get_detailed_packages(self, device_id: str) -> List[Dict[str, Any]]:
        """
        Lists all packages on device with categorization:
        - CTF Target Candidate (non-OEM, 3rd party, challenge names)
        - User Installed (/data/app)
        - System / OEM
        """
        # 1. Get 3rd party packages
        ret_3rd, out_3rd, _ = self.run_adb(["shell", "pm", "list", "packages", "-3"], device_id=device_id, timeout=8)
        third_party_set = set()
        if ret_3rd == 0:
            for line in out_3rd.splitlines():
                if line.startswith("package:"):
                    third_party_set.add(line.replace("package:", "").strip())

        # 2. Get packages with path (-f)
        ret_f, out_f, _ = self.run_adb(["shell", "pm", "list", "packages", "-f"], device_id=device_id, timeout=10)
        detailed_list = []
        seen = set()

        if ret_f == 0:
            for line in out_f.splitlines():
                line = line.strip()
                if line.startswith("package:"):
                    rest = line[8:]
                    if "=" in rest:
                        apk_path, pkg_name = rest.rsplit("=", 1)
                        pkg_name = pkg_name.strip()
                        apk_path = apk_path.strip()
                    else:
                        pkg_name = rest.strip()
                        apk_path = ""

                    if not pkg_name or pkg_name in seen:
                        continue
                    seen.add(pkg_name)

                    is_user = (pkg_name in third_party_set) or ("/data/app" in apk_path)
                    
                    # Heuristic for CTF / Challenge candidate
                    lower_pkg = pkg_name.lower()
                    oem_prefixes = [
                        "com.google.android.", "com.android.", "com.qualcomm.",
                        "com.google.ar.", "android"
                    ]
                    is_oem = any(lower_pkg.startswith(p) for p in oem_prefixes)

                    is_ctf = False
                    if is_user and not is_oem:
                        is_ctf = True

                    chall_keywords = ["ctf", "challenge", "crackme", "hack", "flag", "rev", "vuln", "target", "sample", "test", "root", "magisk"]
                    if any(k in lower_pkg for k in chall_keywords):
                        is_ctf = True

                    if is_ctf:
                        category = "CTF_TARGET"
                    elif is_user:
                        category = "USER_APP"
                    else:
                        category = "SYSTEM"

                    detailed_list.append({
                        "package": pkg_name,
                        "path": apk_path,
                        "is_user": is_user,
                        "is_ctf": is_ctf,
                        "category": category
                    })

        def sort_key(item):
            cat_priority = {"CTF_TARGET": 0, "USER_APP": 1, "SYSTEM": 2}
            return (cat_priority.get(item["category"], 3), item["package"])

        detailed_list.sort(key=sort_key)
        return detailed_list

    def pull_apk(self, device_id: str, package_name: str, dest_dir: str = "pulled_apks") -> Tuple[bool, str]:
        """Pulls base.apk of an installed package from device to local machine."""
        ret, stdout, stderr = self.run_adb(["shell", "pm", "path", package_name], device_id=device_id, timeout=8)
        if ret != 0 or not stdout.strip():
            return False, f"Tidak dapat menemukan path APK untuk {package_name}: {stderr}"

        remote_path = ""
        for line in stdout.splitlines():
            line = line.strip()
            if line.startswith("package:"):
                remote_path = line.replace("package:", "").strip()
                if remote_path.endswith("base.apk"):
                    break

        if not remote_path:
            return False, f"Path APK untuk {package_name} kosong!"

        dest_dir = os.path.abspath(dest_dir)
        os.makedirs(dest_dir, exist_ok=True)
        local_filename = f"{package_name}.apk"
        local_dest = os.path.join(dest_dir, local_filename)

        ret, out, err = self.run_adb(["pull", remote_path, local_dest], device_id=device_id, timeout=60)
        if ret == 0 and os.path.exists(local_dest):
            return True, local_dest
        return False, f"Gagal menarik APK: {err or out}"

    def launch_app(self, device_id: str, package_name: str) -> Tuple[bool, str]:
        """Launch application using monkey launcher."""
        cmd = ["shell", "monkey", "-p", package_name, "-c", "android.intent.category.LAUNCHER", "1"]
        ret, stdout, stderr = self.run_adb(cmd, device_id=device_id, timeout=8)
        if "Events injected: 1" in stdout or ret == 0:
            return True, f"Aplikasi {package_name} dibuka!"
        return False, stderr or stdout

    def force_stop_app(self, device_id: str, package_name: str) -> Tuple[bool, str]:
        """Force stop package."""
        ret, stdout, stderr = self.run_adb(["shell", "am", "force-stop", package_name], device_id=device_id, timeout=6)
        if ret == 0:
            return True, f"Aplikasi {package_name} dihentikan"
        return False, stderr or stdout

    def clear_app_data(self, device_id: str, package_name: str) -> Tuple[bool, str]:
        """Clear application data (pm clear)."""
        ret, stdout, stderr = self.run_adb(["shell", "pm", "clear", package_name], device_id=device_id, timeout=6)
        if "Success" in stdout or ret == 0:
            return True, f"Data aplikasi {package_name} dibersihkan"
        return False, stderr or stdout

    def uninstall_app(self, device_id: str, package_name: str) -> Tuple[bool, str]:
        """Uninstall package from device."""
        ret, stdout, stderr = self.run_adb(["uninstall", package_name], device_id=device_id, timeout=15)
        if "Success" in stdout:
            return True, f"Aplikasi {package_name} berhasil di-uninstall"
        return False, stderr or stdout

    def list_avds(self) -> List[str]:
        """List available Android Virtual Devices (AVD)."""
        if not self.emulator_path or not os.path.exists(self.emulator_path):
            return []
        try:
            p = subprocess.run(
                [self.emulator_path, "-list-avds"],
                capture_output=True,
                text=True,
                timeout=5,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
            )
            if p.returncode == 0:
                return [line.strip() for line in p.stdout.splitlines() if line.strip()]
        except Exception:
            pass
        return []

    def start_avd(self, avd_name: str):
        """Launch AVD emulator in a separate background process."""
        if not self.emulator_path or not avd_name:
            return False
        cmd = [self.emulator_path, "-avd", avd_name]
        try:
            subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
            )
            return True
        except Exception:
            return False

    @staticmethod
    def extract_apk_info(apk_path: str) -> Dict[str, Any]:
        """
        Fast Pure-Python extraction of Package Name & Main Activity
        from AndroidManifest.xml inside the APK zip without external dependencies.
        """
        info = {
            "package_name": "",
            "main_activity": "",
            "activities": [],
            "file_size": 0,
            "filename": os.path.basename(apk_path)
        }
        if not os.path.exists(apk_path):
            return info

        info["file_size"] = os.path.getsize(apk_path)

        try:
            with zipfile.ZipFile(apk_path, "r") as zf:
                if "AndroidManifest.xml" in zf.namelist():
                    manifest_data = zf.read("AndroidManifest.xml")
                    # Extract strings from binary XML String Pool
                    strings = ADBManager._extract_strings_from_axml(manifest_data)
                    
                    # 1. Package Name typically looks like com.xxx.yyy
                    pkg_candidates = [
                        s for s in strings
                        if re.match(r"^[a-zA-Z][a-zA-Z0-9_]*(\.[a-zA-Z][a-zA-Z0-9_]*)+$", s)
                        and not any(s.startswith(p) for p in ("android.", "schemas.", "http", "androidx."))
                    ]
                    if pkg_candidates:
                        info["package_name"] = pkg_candidates[0]

                    # 2. Main Activity / Activities
                    activities = [
                        s for s in strings
                        if ("Activity" in s or s.startswith("."))
                        and not any(s.startswith(p) for p in ("android.", "androidx."))
                    ]
                    info["activities"] = activities
                    for act in activities:
                        if "MainActivity" in act or act == ".MainActivity":
                            info["main_activity"] = act
                            break
                    if not info["main_activity"] and activities:
                        info["main_activity"] = activities[0]
        except Exception:
            pass

        return info

    @staticmethod
    def _extract_strings_from_axml(data: bytes) -> List[str]:
        """Parse string pool from Android binary XML."""
        strings = []
        if len(data) < 8:
            return strings
        try:
            # Check magic 0x00080003
            header_type = struct.unpack("<H", data[0:2])[0]
            if header_type != 0x0003:
                # Fallback printable ASCII scan
                return [m.decode("ascii") for m in re.findall(rb"[a-zA-Z0-9_.]{4,}", data)]

            # String Pool chunk follows header (type 0x0001)
            chunk_type, chunk_size = struct.unpack("<II", data[8:16])
            if chunk_type == 0x0001:
                string_count = struct.unpack("<I", data[16:20])[0]
                strings_start = 8 + struct.unpack("<I", data[28:32])[0]
                
                # Extract UTF-8/UTF-16 strings
                pattern = rb"[a-zA-Z0-9_.]{3,80}"
                matches = re.findall(pattern, data[strings_start:strings_start + chunk_size])
                for m in matches:
                    try:
                        s = m.decode("ascii")
                        if s not in strings:
                            strings.append(s)
                    except Exception:
                        pass
        except Exception:
            # Fallback regex
            matches = re.findall(rb"[a-zA-Z0-9_.]{4,80}", data)
            strings = [m.decode("latin-1") for m in matches]
        return strings

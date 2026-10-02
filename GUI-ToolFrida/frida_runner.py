"""
GUI-ToolFrida - Frida Asynchronous Runner
Spawns and manages live Frida instrumentation sessions without freezing the GUI.
"""

import os
import queue
import shutil
import subprocess
import threading
import time
from typing import Callable, List, Optional


class FridaRunner:
    """Manages asynchronous live Frida sessions."""

    def __init__(self, on_output: Optional[Callable[[str], None]] = None, on_exit: Optional[Callable[[int], None]] = None):
        self.on_output = on_output
        self.on_exit = on_exit
        self.process: Optional[subprocess.Popen] = None
        self.reader_thread: Optional[threading.Thread] = None
        self.is_running = False
        self.frida_bin = self._find_frida_bin()

    def _find_frida_bin(self) -> str:
        """Locate frida CLI executable."""
        which_frida = shutil.which("frida")
        if which_frida:
            return which_frida
        # Check standard Windows Python Scripts folder
        user_profile = os.environ.get("USERPROFILE", "")
        candidates = [
            os.path.join(user_profile, r"AppData\Roaming\Python\Python314\Scripts\frida.exe"),
            os.path.join(user_profile, r"AppData\Roaming\Python\Python312\Scripts\frida.exe"),
            os.path.join(user_profile, r"AppData\Roaming\Python\Python311\Scripts\frida.exe"),
            os.path.join(user_profile, r"AppData\Local\Programs\Python\Python314\Scripts\frida.exe"),
            os.path.join(user_profile, r"AppData\Local\Programs\Python\Python312\Scripts\frida.exe"),
        ]
        for c in candidates:
            if os.path.exists(c):
                return c
        return "frida"

    def start_hook(
        self,
        package_name: str,
        script_path: str,
        spawn: bool = True,
        device_id: Optional[str] = None,
        no_pause: bool = True
    ) -> bool:
        """Start a live Frida hooking session."""
        if self.is_running:
            self.stop_hook()

        if not os.path.exists(script_path):
            if self.on_output:
                self.on_output(f"[-] Error: Script '{script_path}' tidak ditemukan!\n")
            return False

        cmd = [self.frida_bin]
        if device_id:
            cmd.extend(["--device", device_id])
        else:
            cmd.append("-U")

        if spawn:
            cmd.extend(["-f", package_name])
            if no_pause:
                cmd.append("--no-pause")
        else:
            cmd.extend(["-n", package_name])

        cmd.extend(["-l", script_path])

        if self.on_output:
            self.on_output(f"[*] Menjalankan command:\n    {' '.join(cmd)}\n\n")

        try:
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
            )
            self.is_running = True

            self.reader_thread = threading.Thread(target=self._stream_output, daemon=True)
            self.reader_thread.start()
            return True
        except Exception as e:
            if self.on_output:
                self.on_output(f"[-] Gagal menjalankan Frida: {e}\n")
            self.is_running = False
            return False

    def _stream_output(self):
        """Read stdout/stderr line-by-line in a background thread."""
        if not self.process or not self.process.stdout:
            return

        try:
            for line in iter(self.process.stdout.readline, ""):
                if not self.is_running:
                    break
                if self.on_output:
                    self.on_output(line)
        except Exception:
            pass

        returncode = self.process.poll() if self.process else 0
        self.is_running = False
        if self.on_output:
            self.on_output(f"\n[*] Sesi Frida selesai (Exit code: {returncode}).\n")
        if self.on_exit:
            self.on_exit(returncode or 0)

    def stop_hook(self):
        """Terminate the active Frida process."""
        self.is_running = False
        if self.process:
            try:
                self.process.terminate()
                self.process.kill()
            except Exception:
                pass
            self.process = None
        if self.on_output:
            self.on_output("[*] Sesi Frida dihentikan secara manual.\n")

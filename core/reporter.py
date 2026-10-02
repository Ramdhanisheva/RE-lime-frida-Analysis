"""
Automotion Reverse Engineering - Terminal Reporter & Exporter
Provides terminal UI, instant flag alerts, and exports markdown/json reports.
"""

import json
import os
import time
from typing import Any, Dict, List, Optional, Tuple


class Reporter:
    """Manages CLI reporting and output generation."""

    def __init__(self, output_dir: Optional[str] = None):
        self.output_dir = output_dir or "results"
        os.makedirs(self.output_dir, exist_ok=True)

    def print_banner(self, target_name: str, file_size: int):
        """Display stylish tool header."""
        print("=" * 70)
        print(" [*] AUTOMOTION REVERSE ENGINEERING & ANDROID EXPLOIT SUITE")
        print(f" Target: {target_name} ({file_size} bytes)")
        print("=" * 70)

    def print_phase(self, phase_name: str):
        """Print stage separator."""
        print(f"\n--- [ {phase_name} ] ---")

    def print_flag_alert(self, flag: str, source: str):
        """Instant visual highlight when a flag is found."""
        print("\n" + "=" * 70)
        print(f" [+] [BINGO! FLAG DITEMUKAN]")
        print(f" FLAG:   {flag}")
        print(f" Sumber: {source}")
        print("=" * 70 + "\n")

    def export_report(self, results: Dict[str, Any], elapsed_time: float) -> Tuple[str, str]:
        """Export comprehensive report.md and report.json."""
        target_name = os.path.basename(results.get("apk_path", results.get("binary_path", "target")))
        ts = int(time.time())
        target_out = os.path.join(self.output_dir, f"out_{target_name}_{ts}")
        os.makedirs(target_out, exist_ok=True)

        json_path = os.path.join(target_out, "report.json")
        md_path = os.path.join(target_out, "report.md")

        # 1. Write JSON
        try:
            with open(json_path, "w", encoding="utf-8") as jf:
                # Handle non-serializable objects
                clean_res = json.loads(json.dumps(results, default=str))
                json.dump(clean_res, jf, indent=2)
        except Exception:
            pass

        # 2. Write Markdown
        md_lines = [
            f"# Reverse Engineering Triage Report: {target_name}",
            f"- **Waktu Analisis:** {time.strftime('%Y-%m-%d %H:%M:%S')}",
            f"- **Durasi Eksekusi:** {elapsed_time:.2f}s",
            "",
            "## 🚩 Temuan Flag",
        ]

        flags = results.get("flags_found", [])
        if flags:
            for idx, fl in enumerate(flags, 1):
                md_lines.append(f"{idx}. `{fl.get('flag')}` - *{fl.get('encoding')}* ({fl.get('context')})")
        else:
            md_lines.append("*Belum ada flag langsung yang ditemukan secara statis. Gunakan script Frida yang telah digenerate.*")

        md_lines.extend([
            "",
            "## 📱 Detail APK & Target",
            f"- **Package Name:** `{results.get('package_name', 'N/A')}`",
            f"- **Main Activity:** `{results.get('main_activity', 'N/A')}`",
            f"- **DEX Files:** {len(results.get('dex_files', []))}",
            f"- **Native Libraries (.so):** {len(results.get('native_libraries', []))}",
            "",
            "## 💉 Frida Hooking Scripts (Ready to Run)",
        ])

        frida_scripts = results.get("frida_scripts", {})
        if frida_scripts:
            for s_name, s_path in frida_scripts.items():
                md_lines.append(f"- **{s_name}:** `{os.path.basename(s_path)}`")
                md_lines.append(f"  ```bash")
                md_lines.append(f"  frida -U -f {results.get('package_name', 'com.example.app')} -l {s_path} --no-pause")
                md_lines.append(f"  ```")
        else:
            md_lines.append("*Tidak ada script Frida yang digenerate.*")

        try:
            with open(md_path, "w", encoding="utf-8") as mf:
                mf.write("\n".join(md_lines))
        except Exception:
            pass

        return md_path, target_out

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
        """Display clean tool header."""
        print(f"\n[*] Analysis Reverse & Android: \033[1;33m{target_name}\033[0m ({file_size:,} bytes)\n")

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
        """Disabled to keep competition workspace clean without bot/AI trace."""
        return "", self.output_dir

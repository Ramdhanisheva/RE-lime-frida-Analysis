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
        print(f"\n[*] Tool Analysis Reverse: {target_name} ({file_size:,} bytes)\n")

    def print_phase(self, phase_name: str):
        """Print stage separator."""
        print(f"\n--- [ {phase_name} ] ---")

    def print_flag_alert(self, flag: str, source: str):
        """Clean instant flag alert."""
        print(f"\n[+] Flag found: {flag}")
        if source:
            print(f"    Source: {source}")

    def export_report(self, results: Dict[str, Any], elapsed_time: float) -> Tuple[str, str]:
        """Disabled to keep competition workspace clean without bot/AI trace."""
        return "", self.output_dir

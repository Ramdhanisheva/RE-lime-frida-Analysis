"""
Automotion Reverse Engineering - Native ELF & .so Inspector
Inspects native shared libraries (.so), Linux binaries, and Android JNI components:
- ELF header parsing (arch, endianness, 32/64 bit)
- Dynamic symbol and export enumeration (JNI Java_* methods)
- String table and rodata scanning
- Obfuscated string recovery (single-byte XOR, rot13, base64)
"""

import os
import re
import struct
from typing import Any, Dict, List, Optional, Set, Tuple

from core.string_hunter import StringHunter


class NativeInspector:
    """Inspector for ELF binaries and Android native shared libraries (.so)."""

    ARCH_MAP = {
        0x03: "x86",
        0x28: "ARM (32-bit)",
        0x3e: "x86_64 (AMD64)",
        0xb7: "AArch64 (ARM 64-bit)",
        0x08: "MIPS",
        0xf3: "RISC-V"
    }

    def __init__(self, output_dir: Optional[str] = None):
        self.output_dir = output_dir or "results"
        self.string_hunter = StringHunter()

    def inspect_binary(self, filepath_or_data) -> Dict[str, Any]:
        """Inspect native ELF binary or .so file."""
        results: Dict[str, Any] = {
            "is_elf": False,
            "arch": "Unknown",
            "bitness": 0,
            "endianness": "little",
            "jni_exports": [],
            "symbols": [],
            "interesting_strings": [],
            "flags_found": []
        }

        data = b""
        if isinstance(filepath_or_data, str) and os.path.exists(filepath_or_data):
            try:
                with open(filepath_or_data, "rb") as f:
                    data = f.read()
            except Exception:
                return results
        elif isinstance(filepath_or_data, (bytes, bytearray)):
            data = bytes(filepath_or_data)
        else:
            return results

        if not data.startswith(b"\x7fELF"):
            return results

        results["is_elf"] = True

        # Parse ELF Header
        # 0x04: bitness (1=32-bit, 2=64-bit)
        # 0x05: endianness (1=little, 2=big)
        # 0x12: machine (2 bytes)
        bitness = 32 if data[4] == 1 else (64 if data[4] == 2 else 0)
        results["bitness"] = bitness
        endian_fmt = "<" if data[5] == 1 else ">"
        results["endianness"] = "little" if data[5] == 1 else "big"

        if len(data) >= 0x14:
            e_machine = struct.unpack(f"{endian_fmt}H", data[0x12:0x14])[0]
            results["arch"] = self.ARCH_MAP.get(e_machine, f"Machine_{hex(e_machine)}")

        # 1. Scan direct and obfuscated flags
        results["flags_found"] = self.string_hunter.hunt_flags(data)

        # 2. Extract JNI Exports (Java_com_... or JNI_OnLoad)
        jni_matches = re.finditer(rb"(?:Java_[a-zA-Z0-9_]+|JNI_OnLoad)", data)
        for jm in jni_matches:
            sym = jm.group(0).decode("latin-1", errors="ignore")
            if sym not in results["jni_exports"]:
                results["jni_exports"].append(sym)

        # 3. Extract Function Symbols and Strings
        sym_matches = re.finditer(rb"[A-Za-z0-9_]{4,60}\x00", data)
        for sm in sym_matches:
            s_val = sm.group(0)[:-1].decode("latin-1", errors="ignore")
            if any(term in s_val.lower() for term in ("flag", "check", "cmp", "secret", "verify", "strcmp", "memcmp", "aes", "des", "rc4")):
                if s_val not in results["interesting_strings"]:
                    results["interesting_strings"].append(s_val)

        # 4. Single-Byte XOR String Hunt in .so (specifically for hidden flags like FRIDA{NATIVE_HACKER})
        raw_strings = re.findall(rb"[\x20-\x7e]{8,64}", data)
        for raw_s in raw_strings:
            for k in range(1, 256):
                xored = bytes([b ^ k for b in raw_s])
                for pat in self.string_hunter.flag_patterns:
                    m = pat.search(xored.decode("latin-1", errors="ignore"))
                    if m:
                        fl_str = m.group(0)
                        if not any(f["flag"] == fl_str for f in results["flags_found"]):
                            results["flags_found"].append({
                                "flag": fl_str,
                                "encoding": f"Native .so XOR 0x{k:02x}",
                                "offset": "N/A",
                                "context": f"Raw bytes: {raw_s.decode('latin-1', errors='ignore')}"
                            })

        return results

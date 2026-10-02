"""
Automotion Reverse Engineering - Deep String & Pattern Hunter
Multi-encoding static scanner:
- Plaintext ASCII / UTF-8 / UTF-16LE
- Base64 / Hex / ROT13
- Single-Byte XOR (0x01-0xFF) & Repeating XOR
- Candidate Symmetric Keys (AES 16/24/32 bytes, DES 8 bytes)
- Candidate Ciphertexts (Base64 / Hex blobs)
- Sensitive Reverse Engineering Keywords & Methods
"""

import base64
import binascii
import codecs
import re
from typing import Any, Dict, List, Optional, Set, Tuple

import config


class StringHunter:
    """Specialized string and symbol hunter for Reverse Engineering challenges."""

    def __init__(self, flag_patterns: Optional[List[re.Pattern]] = None):
        self.flag_patterns = flag_patterns or config.FLAG_PATTERNS
        self.keywords = config.TARGET_KEYWORDS

    def is_valid_flag(self, text: str) -> bool:
        """Strict validation of flag strings."""
        if not text or not isinstance(text, str):
            return False
        clean = text.strip().strip("'\"`()[]")
        for pat in self.flag_patterns:
            m = pat.search(clean)
            if m:
                match_str = m.group(0)
                if "{" in match_str and match_str.endswith("}"):
                    inner = match_str[match_str.find("{") + 1 : -1]
                    if len(inner) >= 3 and any(c.isalnum() for c in inner):
                        return True
        return False

    def hunt_flags(self, data: bytes) -> List[Dict[str, Any]]:
        """
        Deep scan data across multiple encodings for CTF flags.
        Returns a list of dicts with flag, encoding, context, offset.
        """
        flags_found: List[Dict[str, Any]] = []
        seen_flags: Set[str] = set()

        def add_flag(flag_str: str, encoding: str, offset: int = -1, context: str = ""):
            flag_str = flag_str.strip()
            for pat in self.flag_patterns:
                m = pat.search(flag_str)
                if m:
                    f = m.group(0)
                    if f not in seen_flags and self.is_valid_flag(f):
                        seen_flags.add(f)
                        flags_found.append({
                            "flag": f,
                            "encoding": encoding,
                            "offset": hex(offset) if offset >= 0 else "N/A",
                            "context": context[:80] if context else f
                        })

        # 1. Plaintext ASCII & UTF-8
        latin_text = data.decode("latin-1", errors="ignore")
        for pat in self.flag_patterns:
            for m in pat.finditer(latin_text):
                add_flag(m.group(0), "Plaintext ASCII", m.start())

        # 2. UTF-16LE (Windows / Java Android strings) - only check if null bytes present
        if b"\x00" in data:
            try:
                utf16_text = data.decode("utf-16le", errors="ignore")
                for pat in self.flag_patterns:
                    for m in pat.finditer(utf16_text):
                        add_flag(m.group(0), "UTF-16LE", m.start())
            except Exception:
                pass

        # 3. Base64 Encoded Flags
        # Fast prefix matching for known flag prefixes in Base64:
        b64_pfxs = [b"SGFja1RvZGF5", b"ZmxhZ3", b"RkxBR3", b"cGljb0NURn", b"RlJJREF", b"Q1RGew"]
        for pfx in b64_pfxs:
            idx = 0
            while True:
                pos = data.find(pfx, idx)
                if pos == -1:
                    break
                chunk = data[pos : min(len(data), pos + 128)]
                m = re.match(rb"^[A-Za-z0-9+/=]+", chunk)
                if m:
                    cand_b64 = m.group(0)
                    missing_padding = len(cand_b64) % 4
                    if missing_padding:
                        cand_b64 += b"=" * (4 - missing_padding)
                    try:
                        decoded = base64.b64decode(cand_b64).decode("latin-1", errors="ignore")
                        for pat in self.flag_patterns:
                            m_flag = pat.search(decoded)
                            if m_flag:
                                add_flag(m_flag.group(0), "Base64", pos, cand_b64.decode("ascii", errors="ignore"))
                    except Exception:
                        pass
                idx = pos + len(pfx)

        # 4. Hex Encoded Flags
        for m in re.finditer(rb"(?:[0-9a-fA-F]{2}){10,120}", data):
            raw_hex = m.group(0).lower()
            if b"7b" in raw_hex and b"7d" in raw_hex:
                try:
                    decoded = bytes.fromhex(raw_hex.decode("ascii")).decode("latin-1", errors="ignore")
                    for pat in self.flag_patterns:
                        m_flag = pat.search(decoded)
                        if m_flag:
                            add_flag(m_flag.group(0), "Hex Encoded", m.start(), raw_hex.decode("ascii")[:40])
                except Exception:
                    pass

        # 5. ROT13 Flags
        # In ROT13, '{' and '}' are untouched. Only inspect flag-shaped strings:
        for m in re.finditer(rb"[a-zA-Z0-9_]{3,30}\{[a-zA-Z0-9_\-!@#$%^&*+=?]{3,100}\}", data):
            cand = m.group(0).decode("latin-1", errors="ignore")
            rot = codecs.decode(cand, "rot_13")
            for pat in self.flag_patterns:
                m_rot = pat.search(rot)
                if m_rot:
                    add_flag(m_rot.group(0), "ROT13", m.start(), cand)

        # 6. Single-Byte XOR Brute Force (0x01-0xFF)
        prefixes = [b"HackToday", b"flag{", b"FLAG{", b"picoCTF{", b"FRIDA{", b"CTF{"]
        for pfx in prefixes:
            for k in range(1, 256):
                xored_pfx = bytes([b ^ k for b in pfx])
                idx = 0
                while True:
                    pos = data.find(xored_pfx, idx)
                    if pos == -1:
                        break
                    chunk = data[pos : min(len(data), pos + 128)]
                    dec = bytes([b ^ k for b in chunk]).decode("latin-1", errors="ignore")
                    for pat in self.flag_patterns:
                        m = pat.search(dec)
                        if m:
                            add_flag(m.group(0), f"Single-Byte XOR 0x{k:02x}", pos, dec[:40])
                    idx = pos + len(xored_pfx)

        # 7. Caesar Shift / Additive Byte Shift (e.g. char - 1 or + 1)
        prefixes = [b"HackToday", b"flag{", b"FLAG{", b"picoCTF{", b"FRIDA{", b"CTF{"]
        for pfx in prefixes:
            for shift in (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 128, 255):
                # Search for data where (b - shift) % 256 == pfx
                shifted_pfx = bytes([(b + shift) % 256 for b in pfx])
                idx = 0
                while True:
                    pos = data.find(shifted_pfx, idx)
                    if pos == -1:
                        break
                    chunk = data[pos : min(len(data), pos + 128)]
                    dec = bytes([(b - shift) % 256 for b in chunk]).decode("latin-1", errors="ignore")
                    for pat in self.flag_patterns:
                        m = pat.search(dec)
                        if m:
                            add_flag(m.group(0), f"Caesar Shift -{shift}", pos, dec[:40])
                    idx = pos + len(shifted_pfx)

        # 8. Base32 Encoded Flags
        try:
            # Look for Base32 patterns
            for m in re.finditer(rb"[A-Z2-7]{16,}={0,6}", data):
                cand_b32 = m.group(0)
                try:
                    dec_b32 = base64.b32decode(cand_b32, casefold=True).decode("latin-1", errors="ignore")
                    for pat in self.flag_patterns:
                        m_flag = pat.search(dec_b32)
                        if m_flag:
                            add_flag(m_flag.group(0), "Base32", m.start(), cand_b32.decode("ascii")[:40])
                except Exception:
                    pass
        except Exception:
            pass

        # 9. Stack String / Reversed String Scan
        if len(data) <= 2 * 1024 * 1024:
            reversed_data = data[::-1]
            rev_text = reversed_data.decode("latin-1", errors="ignore")
            for pat in self.flag_patterns:
                for m in pat.finditer(rev_text):
                    add_flag(m.group(0), "Reversed / Stack String")
        else:
            rev_prefixes = [b"}yadToTkaH", b"}galf", b"}GALF", b"}ADIRF", b"}FTC"]
            for rpfx in rev_prefixes:
                pos = data.find(rpfx)
                if pos != -1:
                    chunk = data[max(0, pos - 100) : pos + len(rpfx)]
                    rev_chunk = chunk[::-1].decode("latin-1", errors="ignore")
                    for pat in self.flag_patterns:
                        m = pat.search(rev_chunk)
                        if m:
                            add_flag(m.group(0), "Reversed / Stack String", pos, rev_chunk[:40])

        return flags_found

    def extract_crypto_candidates(
        self,
        data: bytes,
        strings_list: Optional[List[str]] = None,
        is_app_dex: bool = True
    ) -> Dict[str, Any]:
        """
        Extract candidate symmetric keys, initialization vectors, and ciphertexts
        from DEX string pool or raw binary data.
        """
        candidates: Dict[str, Any] = {
            "keys": [],
            "ivs": [],
            "ciphertexts": [],
            "target_strings": []
        }

        framework_words = (
            "android", "androidx", "kotlin", "google", "support",
            "Landroid", "Landroidx", "Lkotlin", "Ljava", "Ljavax",
            "Exception", "Activity", "Thread", "Handler", "Context",
            "Layout", "Resource", "Drawable", "AppCompat", "Material"
        )

        seen_keys: Set[str] = set()
        seen_cts: Set[str] = set()

        # Build candidate string collection
        pool: List[str] = []
        if strings_list is not None:
            pool = strings_list
        else:
            raw_strs = re.findall(rb"[A-Za-z0-9_\-\.\$]{8,128}", data)
            pool = [s.decode("latin-1", errors="ignore") for s in raw_strs]

        key_regex = re.compile(r"^[A-Za-z0-9_!@#$%^&*+=?~-]{8}$|^[A-Za-z0-9_!@#$%^&*+=?~-]{16}$|^[A-Za-z0-9_!@#$%^&*+=?~-]{24}$|^[A-Za-z0-9_!@#$%^&*+=?~-]{32}$")
        b64_regex = re.compile(r"^[A-Za-z0-9+/]{16,}={0,2}$")

        for s in pool:
            # 1. Candidate Key check (8 for DES/XOR, 16/24/32 for AES)
            if len(s) in (8, 16, 24, 32) and key_regex.match(s):
                if s not in seen_keys:
                    if not any(fw.lower() in s.lower() for fw in framework_words) and not s.startswith("Lcom/"):
                        seen_keys.add(s)
                        candidates["keys"].append({
                            "key": s,
                            "bytes": s.encode("latin-1"),
                            "length": len(s),
                            "priority": 1 if is_app_dex else 2
                        })

            # 2. Candidate Ciphertext check
            if len(s) >= 20 and b64_regex.match(s):
                if s not in seen_cts:
                    if not any(fw.lower() in s.lower() for fw in framework_words):
                        try:
                            dec = base64.b64decode(s)
                            if len(dec) >= 16 and (len(dec) % 16 == 0 or len(dec) % 8 == 0):
                                seen_cts.add(s)
                                candidates["ciphertexts"].append({
                                    "b64": s,
                                    "raw_bytes": dec,
                                    "length": len(dec),
                                    "priority": 1 if is_app_dex else 2
                                })
                        except Exception:
                            pass

            # 3. Keywords check
            s_lower = s.lower()
            if any(k in s_lower for k in self.keywords):
                if len(s) <= 60 and s not in candidates["target_strings"]:
                    candidates["target_strings"].append(s)

        candidates["target_strings"] = candidates["target_strings"][:50]
        return candidates

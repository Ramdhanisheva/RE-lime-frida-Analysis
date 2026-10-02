"""
Automotion Reverse Engineering - Automated Cryptography Solver
Cross-correlates extracted symmetric keys, IVs, and Base64 ciphertexts:
- AES (ECB, CBC with zero IV / key IV / extracted IVs)
- DES / Triple DES
- RC4 stream cipher
- Automatically tests PKCS7 padding and extracts valid CTF flags.
"""

import base64
from typing import Any, Dict, List, Optional, Set, Tuple

from Crypto.Cipher import AES, DES, DES3, ARC4
from core.string_hunter import StringHunter


def unpad_pkcs7(data: bytes) -> bytes:
    """Safely remove PKCS7 padding if valid."""
    if not data:
        return data
    pad_len = data[-1]
    if 1 <= pad_len <= 16 and len(data) >= pad_len:
        if all(b == pad_len for b in data[-pad_len:]):
            return data[:-pad_len]
    return data


class CryptoSolver:
    """Automated cryptographic correlation and decryption solver."""

    def __init__(self):
        self.string_hunter = StringHunter()

    def solve_candidates(
        self,
        candidate_keys: List[Dict[str, Any]],
        candidate_ciphertexts: List[Dict[str, Any]],
        custom_keys: Optional[List[bytes]] = None
    ) -> List[Dict[str, Any]]:
        """
        Cross-correlate candidate keys and ciphertexts to auto-decrypt flags.
        Prioritizes App-DEX keys (priority=1) over framework keys.
        """
        recovered_flags: List[Dict[str, Any]] = []
        seen_flags: Set[str] = set()

        # Build list of raw keys with priority
        # Tuple: (raw_bytes, label, priority)
        keys_pool: List[Tuple[bytes, str, int]] = []
        for k in candidate_keys:
            raw_k = k.get("bytes", k.get("key", "").encode("latin-1"))
            prio = k.get("priority", 2)
            if raw_k:
                keys_pool.append((raw_k, k.get("key", str(raw_k)), prio))

        if custom_keys:
            for ck in custom_keys:
                keys_pool.append((ck, ck.decode("latin-1", errors="ignore"), 1))

        # Default CTF keys
        default_ctf_keys = [
            b"HILLBILLWILLBINN",
            b"0123456789abcdef",
            b"1234567890123456",
            b"password12345678",
            b"secret_key_12345"
        ]
        for dk in default_ctf_keys:
            if not any(k[0] == dk for k in keys_pool):
                keys_pool.append((dk, dk.decode("latin-1"), 1))

        # Sort keys: priority 1 first, then shorter/cleaner
        keys_pool.sort(key=lambda x: (x[2], len(x[0])))

        # Cap keys pool to top 60 most relevant candidates to prevent hanging
        keys_pool = keys_pool[:60]

        # Prioritize ciphertexts with priority 1
        sorted_cts = sorted(candidate_ciphertexts, key=lambda x: x.get("priority", 2))[:30]

        # Candidate ciphertexts
        for ct_obj in sorted_cts:
            raw_ct = ct_obj.get("raw_bytes")
            if not raw_ct:
                b64_str = ct_obj.get("b64", "")
                try:
                    raw_ct = base64.b64decode(b64_str)
                except Exception:
                    continue

            if len(raw_ct) < 8:
                continue

            for key_bytes, key_label, _ in keys_pool:
                # 1. AES Decryption (key len 16, 24, 32)
                if len(key_bytes) in (16, 24, 32) and len(raw_ct) % 16 == 0:
                    # Mode A: AES-ECB
                    try:
                        cipher_ecb = AES.new(key_bytes, AES.MODE_ECB)
                        pt = unpad_pkcs7(cipher_ecb.decrypt(raw_ct))
                        self._check_and_add_flag(pt, f"AES-ECB (key='{key_label}')", recovered_flags, seen_flags)
                    except Exception:
                        pass

                    # Mode B: AES-CBC with Zero IV
                    try:
                        zero_iv = b"\x00" * 16
                        cipher_cbc = AES.new(key_bytes, AES.MODE_CBC, iv=zero_iv)
                        pt = unpad_pkcs7(cipher_cbc.decrypt(raw_ct))
                        self._check_and_add_flag(pt, f"AES-CBC zero-IV (key='{key_label}')", recovered_flags, seen_flags)
                    except Exception:
                        pass

                    # Mode C: AES-CBC with Key as IV
                    try:
                        cipher_cbc_kiv = AES.new(key_bytes, AES.MODE_CBC, iv=key_bytes[:16])
                        pt = unpad_pkcs7(cipher_cbc_kiv.decrypt(raw_ct))
                        self._check_and_add_flag(pt, f"AES-CBC key-as-IV (key='{key_label}')", recovered_flags, seen_flags)
                    except Exception:
                        pass

                # 2. RC4 Decryption
                try:
                    cipher_rc4 = ARC4.new(key_bytes)
                    pt_rc4 = cipher_rc4.decrypt(raw_ct)
                    self._check_and_add_flag(pt_rc4, f"RC4 (key='{key_label}')", recovered_flags, seen_flags)
                except Exception:
                    pass

                # 3. Repeating XOR Decryption
                try:
                    pt_xor = bytes([c ^ key_bytes[i % len(key_bytes)] for i, c in enumerate(raw_ct)])
                    self._check_and_add_flag(pt_xor, f"Repeating XOR (key='{key_label}')", recovered_flags, seen_flags)
                except Exception:
                    pass

        return recovered_flags

    def _check_and_add_flag(self, pt: bytes, method: str, results: List[Dict[str, Any]], seen: Set[str]):
        """Helper to scan decrypted plaintext for flags."""
        text = pt.decode("latin-1", errors="ignore").strip()
        for pat in self.string_hunter.flag_patterns:
            m = pat.search(text)
            if m:
                fl = m.group(0)
                if fl not in seen and self.string_hunter.is_valid_flag(fl):
                    seen.add(fl)
                    results.append({
                        "flag": fl,
                        "encoding": f"Crypto Solver: {method}",
                        "context": f"Plaintext: {text[:60]}"
                    })

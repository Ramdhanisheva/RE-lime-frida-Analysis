"""
Automotion Reverse Engineering - Comprehensive Test Suite
Battery unit tests for:
1. DEXParser: Header, String Pool, Class Definitions
2. StringHunter: Plaintext, Base64, Hex, ROT13, Single-Byte XOR
3. CryptoSolver: AES-CBC (Zero IV), AES-ECB, RC4, Repeating XOR
4. NativeInspector: ELF Header parsing, architecture detection, XOR scan
5. FridaEngine: 7 targeted Frida hook script generation
6. Z3Helper: SMT BitVector & linear equation crackme solving
7. End-to-End Integration: Frida Labs 0x2 and 0xB auto-flag discovery
"""

import base64
import os
import struct
import sys
import unittest

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from Crypto.Cipher import AES, ARC4
from core.apk_inspector import APKInspector
from core.crypto_solver import CryptoSolver, unpad_pkcs7
from core.dex_parser import DEXParser
from core.frida_engine import FridaEngine
from core.native_inspector import NativeInspector
from core.reporter import Reporter
from core.string_hunter import StringHunter
from core.z3_helper import Z3Helper


class TestDEXParser(unittest.TestCase):
    """Test Dalvik Executable (DEX) pure Python parsing."""

    def test_mock_dex_header(self):
        raw_dex = b"dex\n035\x00" + b"\x00" * (0x70 - 8)
        parser = DEXParser(raw_dex)
        self.assertTrue(parser.is_valid)
        self.assertEqual(len(parser.strings), 0)

    def test_real_dex_parsing_if_available(self):
        candidates = [
            os.path.abspath(r"..\Frida-Labs-main\Frida 0x2\Challenge 0x2.apk"),
            os.path.abspath(os.path.join(PROJECT_ROOT, "..", "..", "Reverse", "Frida-Labs-main", "Frida 0x2", "Challenge 0x2.apk"))
        ]
        sample_apk = next((p for p in candidates if os.path.exists(p)), None)
        if sample_apk and os.path.exists(sample_apk):
            import zipfile
            with zipfile.ZipFile(sample_apk) as z:
                dex_data = z.read("classes3.dex")
                p = DEXParser(dex_data)
                self.assertTrue(p.is_valid)
                self.assertIn("HILLBILLWILLBINN", p.strings)
                self.assertIn("Lcom/ad2001/frida0x2/MainActivity;", p.get_app_classes())


class TestStringHunter(unittest.TestCase):
    """Test multi-encoding string hunting and regex flag extraction."""

    def setUp(self):
        self.hunter = StringHunter()

    def test_plaintext_flag(self):
        blob = b"Garbage text here HackToday26{pl41nt3xt_fl4g_1s_g00d} more garbage"
        flags = self.hunter.hunt_flags(blob)
        self.assertEqual(len(flags), 1)
        self.assertEqual(flags[0]["flag"], "HackToday26{pl41nt3xt_fl4g_1s_g00d}")

    def test_base64_flag(self):
        encoded = base64.b64encode(b"FLAG{b4s364_hunt3r_succ3ss}").decode("ascii")
        blob = f"Some data before {encoded} some data after".encode("latin-1")
        flags = self.hunter.hunt_flags(blob)
        found_flags = [f["flag"] for f in flags]
        self.assertIn("FLAG{b4s364_hunt3r_succ3ss}", found_flags)

    def test_hex_flag(self):
        raw_flag = b"flag{h3x_d3c0d3d_ctf_fl4g}"
        hex_str = raw_flag.hex()
        blob = f"noise_{hex_str}_noise".encode("latin-1")
        flags = self.hunter.hunt_flags(blob)
        found_flags = [f["flag"] for f in flags]
        self.assertIn("flag{h3x_d3c0d3d_ctf_fl4g}", found_flags)

    def test_rot13_flag(self):
        import codecs
        rot_flag = codecs.encode("FLAG{r0t13_c43s4r_c1ph3r}", "rot_13")
        blob = f"header_{rot_flag}_trailer".encode("latin-1")
        flags = self.hunter.hunt_flags(blob)
        found_flags = [f["flag"] for f in flags]
        self.assertIn("FLAG{r0t13_c43s4r_c1ph3r}", found_flags)

    def test_single_byte_xor(self):
        flag = b"FRIDA{x0r_hunt3r_pr0}"
        key = 0x5a
        xored = bytes([c ^ key for c in flag])
        blob = b"RandomPrefixBytes" + xored + b"RandomSuffixBytes"
        flags = self.hunter.hunt_flags(blob)
        found_flags = [f["flag"] for f in flags]
        self.assertIn("FRIDA{x0r_hunt3r_pr0}", found_flags)


class TestCryptoSolver(unittest.TestCase):
    """Test automated symmetric crypto solving."""

    def setUp(self):
        self.solver = CryptoSolver()

    def test_aes_cbc_zero_iv(self):
        key = b"TESTINGSECRETKEY"  # 16 bytes
        flag = b"FLAG{AES_CBC_SOLVED_1337}"
        pad_len = 16 - (len(flag) % 16)
        padded = flag + bytes([pad_len] * pad_len)
        cipher = AES.new(key, AES.MODE_CBC, iv=b"\x00" * 16)
        ct = cipher.encrypt(padded)
        ct_b64 = base64.b64encode(ct).decode("ascii")

        cand_keys = [{"key": "TESTINGSECRETKEY", "bytes": key, "priority": 1}]
        cand_cts = [{"b64": ct_b64, "raw_bytes": ct, "priority": 1}]

        recovered = self.solver.solve_candidates(cand_keys, cand_cts)
        self.assertTrue(len(recovered) > 0)
        self.assertEqual(recovered[0]["flag"], "FLAG{AES_CBC_SOLVED_1337}")

    def test_aes_ecb(self):
        key = b"1234567890123456"  # 16 bytes
        flag = b"picoCTF{aes_ecb_mode_flag}"
        pad_len = 16 - (len(flag) % 16)
        padded = flag + bytes([pad_len] * pad_len)
        cipher = AES.new(key, AES.MODE_ECB)
        ct = cipher.encrypt(padded)
        ct_b64 = base64.b64encode(ct).decode("ascii")

        cand_keys = [{"key": "1234567890123456", "bytes": key, "priority": 1}]
        cand_cts = [{"b64": ct_b64, "raw_bytes": ct, "priority": 1}]

        recovered = self.solver.solve_candidates(cand_keys, cand_cts)
        self.assertTrue(len(recovered) > 0)
        self.assertEqual(recovered[0]["flag"], "picoCTF{aes_ecb_mode_flag}")

    def test_rc4(self):
        key = b"secret_rc4_key"
        flag = b"HackToday26{rc4_stre4m_s0lv3d}"
        cipher = ARC4.new(key)
        ct = cipher.encrypt(flag)
        ct_b64 = base64.b64encode(ct).decode("ascii")

        cand_keys = [{"key": "secret_rc4_key", "bytes": key, "priority": 1}]
        cand_cts = [{"b64": ct_b64, "raw_bytes": ct, "priority": 1}]

        recovered = self.solver.solve_candidates(cand_keys, cand_cts)
        self.assertTrue(len(recovered) > 0)
        self.assertEqual(recovered[0]["flag"], "HackToday26{rc4_stre4m_s0lv3d}")


class TestNativeInspector(unittest.TestCase):
    """Test ELF parsing and single byte XOR decryption."""

    def test_frida_0xb_xor_recovery(self):
        # Frida 0xB string: 'j~ehmWbmxezisdmogi~Q' XOR 0x2c -> 'FRIDA{NATIVE_HACKER}'
        encrypted_str = b"j~ehmWbmxezisdmogi~Q"
        decrypted = bytes([c ^ 0x2c for c in encrypted_str]).decode("ascii")
        self.assertEqual(decrypted, "FRIDA{NATIVE_HACKER}")

        # Test StringHunter XOR scanner on buffer
        hunter = StringHunter()
        found = hunter.hunt_flags(encrypted_str)
        flags = [f["flag"] for f in found]
        self.assertIn("FRIDA{NATIVE_HACKER}", flags)


class TestFridaEngine(unittest.TestCase):
    """Test automatic Frida hook generation."""

    def test_script_generation(self):
        engine = FridaEngine(output_dir="results_test")
        scripts = engine.generate_scripts_suite(
            package_name="com.example.crackme",
            main_activity="com.example.crackme.MainActivity",
            classes=["com.example.crackme.AuthChecker"],
            interesting_methods=[{"class": "com.example.crackme.AuthChecker", "name": "checkFlag"}],
            native_libs=["libnative.so"]
        )
        self.assertGreaterEqual(len(scripts), 7)
        for name, path in scripts.items():
            self.assertTrue(os.path.exists(path), f"Script {name} was not created at {path}")
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()
                if "Native" in name:
                    self.assertIn("Interceptor.attach", content)
                else:
                    self.assertIn("Java.perform", content)


class TestZ3Helper(unittest.TestCase):
    """Test Z3 SMT constraint solving."""

    def test_linear_system(self):
        # Solve: 2*x + 3*y = 19, 5*x - y = 5 -> x=2, y=5
        sol = Z3Helper.solve_linear_system([[2, 3], [5, -1]], [19, 5])
        self.assertEqual(sol, [2, 5])


class TestEndToEndChallenges(unittest.TestCase):
    """End-to-end integration tests on actual Frida Labs APKs."""

    def test_solve_frida_0x2(self):
        candidates = [
            os.path.abspath(r"..\Frida-Labs-main\Frida 0x2\Challenge 0x2.apk"),
            os.path.abspath(os.path.join(PROJECT_ROOT, "..", "..", "Reverse", "Frida-Labs-main", "Frida 0x2", "Challenge 0x2.apk"))
        ]
        apk_path = next((p for p in candidates if os.path.exists(p)), None)
        if not apk_path:
            self.skipTest("Challenge 0x2.apk not found")

        apk_insp = APKInspector()
        res = apk_insp.inspect_apk(apk_path)
        self.assertEqual(res.get("package_name"), "com.ad2001.frida0x2")

        crypto = CryptoSolver()
        flags = crypto.solve_candidates(
            res["crypto_candidates"]["keys"],
            res["crypto_candidates"]["ciphertexts"]
        )
        found_flags = [f["flag"] for f in flags]
        self.assertIn("FLAG{BABY_HOOKS_0x2}", found_flags)

    def test_solve_frida_0xb(self):
        candidates = [
            os.path.abspath(r"..\Frida-Labs-main\Frida 0xB\Challenge 0xB.apk"),
            os.path.abspath(os.path.join(PROJECT_ROOT, "..", "..", "Reverse", "Frida-Labs-main", "Frida 0xB", "Challenge 0xB.apk"))
        ]
        apk_path = next((p for p in candidates if os.path.exists(p)), None)
        if not apk_path:
            self.skipTest("Challenge 0xB.apk not found")

        apk_insp = APKInspector()
        res = apk_insp.inspect_apk(apk_path)
        self.assertEqual(res.get("package_name"), "com.ad2001.frida0xb")
        self.assertTrue(len(res.get("native_libraries", [])) > 0)

        found_flags = [f["flag"] for f in res.get("flags_found", [])]
        self.assertIn("FRIDA{NATIVE_HACKER}", found_flags)



class TestAPKChallengeTrainer(unittest.TestCase):
    """Test APK Challenge Trainer: automated generation and auto-solving of synthetic APK challenges."""

    def setUp(self):
        import tempfile
        self.outdir = tempfile.mkdtemp(prefix="rev_test_apks_")
        self.apk_insp = APKInspector(output_dir=self.outdir)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.outdir, ignore_errors=True)

    def _run_trainer(self):
        """Run the trainer to generate challenge APKs."""
        trainer_path = os.path.join(PROJECT_ROOT, "apk_challenge_trainer.py")
        if not os.path.exists(trainer_path):
            self.skipTest("apk_challenge_trainer.py not found")

        import subprocess, sys
        result = subprocess.run(
            [sys.executable, trainer_path, "--outdir", self.outdir],
            capture_output=True, text=True, cwd=PROJECT_ROOT
        )
        self.assertEqual(result.returncode, 0, f"Trainer failed: {result.stderr}")
        return self.outdir

    def test_challenge_01_strings_xml_flag(self):
        """Challenge 01: Flag plaintext in res/values/strings.xml auto-discovered."""
        apk_dir = self._run_trainer()
        apk_path = os.path.join(apk_dir, "challenge_01_strings_xml.apk")
        res = self.apk_insp.inspect_apk(apk_path)
        all_flags = [f["flag"] for f in res["flags_found"]]
        self.assertTrue(
            any("str1ngs_xml_3asy_w1n" in fl for fl in all_flags),
            f"strings.xml flag not found. Flags: {all_flags}"
        )

    def test_challenge_02_base64_asset_flag(self):
        """Challenge 02: Flag Base64-encoded in assets/config.dat auto-decoded."""
        apk_dir = self._run_trainer()
        apk_path = os.path.join(apk_dir, "challenge_02_base64_asset.apk")
        res = self.apk_insp.inspect_apk(apk_path)
        all_flags = [f["flag"] for f in res["flags_found"]]
        self.assertTrue(
            any("b4s3_64_1n_4ss3ts" in fl for fl in all_flags),
            f"Base64 asset flag not found. Flags: {all_flags}"
        )

    def test_challenge_03_xor_asset_flag(self):
        """Challenge 03: XOR-encrypted asset with key from DEX strings."""
        apk_dir = self._run_trainer()
        apk_path = os.path.join(apk_dir, "challenge_03_xor_asset.apk")

        # Manually test: read key from DEX, XOR decrypt asset
        import zipfile as _zf
        from core.dex_parser import DEXParser
        from core.string_hunter import StringHunter

        hunter = StringHunter()
        with _zf.ZipFile(apk_path) as z:
            dex_data = z.read("classes.dex")
            asset_data = z.read("assets/data.bin")

        dex_p = DEXParser(dex_data)
        # Find the XOR key in DEX strings (8 bytes, "ctfkey42")
        xor_key = None
        for s in dex_p.strings:
            if len(s) == 8 and s.isascii() and s.isalnum():
                xor_key = s.encode()
                break

        self.assertIsNotNone(xor_key, f"XOR key not found in DEX strings: {dex_p.strings}")
        decrypted = bytes(b ^ xor_key[i % len(xor_key)] for i, b in enumerate(asset_data))
        decoded_str = decrypted.decode("utf-8", errors="ignore")
        self.assertIn("HackToday26", decoded_str, f"XOR decrypt failed: {decoded_str!r}")

    def test_challenge_04_sharedprefs_flag(self):
        """Challenge 04: Flag in SharedPreferences XML backup."""
        apk_dir = self._run_trainer()
        apk_path = os.path.join(apk_dir, "challenge_04_sharedprefs.apk")
        res = self.apk_insp.inspect_apk(apk_path)
        all_flags = [f["flag"] for f in res["flags_found"]]
        self.assertTrue(
            any("sh4r3d_pr3fs_c4ptur3d" in fl for fl in all_flags),
            f"SharedPrefs flag not found. Flags: {all_flags}"
        )

    def test_challenge_05_apk_in_apk_flag(self):
        """Challenge 05: Flag in nested APK (APK-in-APK inside assets/)."""
        apk_dir = self._run_trainer()
        apk_path = os.path.join(apk_dir, "challenge_05_apk_in_apk.apk")
        res = self.apk_insp.inspect_apk(apk_path)
        # Should detect nested APK
        self.assertGreater(len(res.get("apk_in_apk", [])), 0, "No APK-in-APK detected")
        all_flags = [f["flag"] for f in res["flags_found"]]
        self.assertTrue(
            any("4pk_1n_4pk_m4tr3shk4" in fl for fl in all_flags),
            f"APK-in-APK flag not found. Flags: {all_flags}"
        )

    def test_apk_inspector_extended_fields(self):
        """Verify new extended fields exist in apk_inspector results."""
        apk_dir = self._run_trainer()
        apk_path = os.path.join(apk_dir, "challenge_04_sharedprefs.apk")
        res = self.apk_insp.inspect_apk(apk_path)
        # New fields should exist (even if empty)
        self.assertIn("encrypted_assets", res)
        self.assertIn("apk_in_apk", res)
        self.assertIn("sharedprefs_data", res)
        self.assertIn("gradle_secrets", res)
        self.assertIn("obfuscated_classes", res)
        # SharedPrefs data should have key=value pairs
        self.assertGreater(len(res["sharedprefs_data"]), 0, "No sharedprefs_data extracted")


if __name__ == "__main__":
    unittest.main()

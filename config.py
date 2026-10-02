"""
Automotion Reverse Engineering Toolkit - Global Configuration
"""

import os
import re

# Comprehensive CTF Flag regex patterns
FLAG_PATTERNS = [
    re.compile(r"HackToday26\{[ -~]{3,120}\}", re.IGNORECASE),
    re.compile(r"HackToday25\{[ -~]{3,120}\}", re.IGNORECASE),
    re.compile(r"HackToday24\{[ -~]{3,120}\}", re.IGNORECASE),
    re.compile(r"HackToday\{[ -~]{3,120}\}", re.IGNORECASE),
    re.compile(r"flag\{[ -~]{3,120}\}", re.IGNORECASE),
    re.compile(r"FLAG\{[ -~]{3,120}\}", re.IGNORECASE),
    re.compile(r"picoCTF\{[ -~]{3,120}\}", re.IGNORECASE),
    re.compile(r"FRIDA\{[ -~]{3,120}\}", re.IGNORECASE),
    re.compile(r"Frida\{[ -~]{3,120}\}", re.IGNORECASE),
    re.compile(r"COMPFEST\{[ -~]{3,120}\}", re.IGNORECASE),
    re.compile(r"CJ(?:20\d\d)?\{[ -~]{3,120}\}"),
    re.compile(r"ITToday\{[ -~]{3,120}\}", re.IGNORECASE),
    re.compile(r"CTF\{[ -~]{3,120}\}"),
]

# Sensitive / target keywords in code & resources
TARGET_KEYWORDS = [
    "flag", "secret", "password", "passwd", "token", "auth", "key",
    "decrypt", "encrypt", "cipher", "check", "verify", "validate",
    "cmpstr", "get_flag", "getflag", "chall", "checker", "solution",
    "aes", "des", "rc4", "xor", "iv", "hash", "salt", "signature"
]

DEFAULT_OUTPUT_DIR = "results"
ADB_PATH = r"C:\Users\ramdh\AppData\Local\Android\Sdk\platform-tools\adb.exe"
FRIDA_SERVER_BINARY = r"C:\Users\ramdh\Documents\A-FinalisHackToday\Reverse\RootDevice\frida-server-17.20.0-android-x86_64"

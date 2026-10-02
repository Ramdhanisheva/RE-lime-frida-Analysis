"""
Automotion Reverse Engineering - Pure Python DEX Parser
Parses Dalvik Executable (.dex) headers, string pool, type descriptors,
method definitions, field definitions, and class structures.
"""

import struct
from typing import Any, Dict, List, Optional, Set, Tuple


def read_uleb128(data: bytes, off: int) -> Tuple[int, int]:
    """Read an unsigned LEB128 integer from data at offset."""
    result = 0
    shift = 0
    while True:
        if off >= len(data):
            break
        byte = data[off]
        off += 1
        result |= (byte & 0x7f) << shift
        if (byte & 0x80) == 0:
            break
        shift += 7
    return result, off


class DEXParser:
    """Pure Python Dalvik Executable (DEX) parser."""

    ACC_PUBLIC = 0x0001
    ACC_PRIVATE = 0x0002
    ACC_PROTECTED = 0x0004
    ACC_STATIC = 0x0008
    ACC_FINAL = 0x0010
    ACC_SYNCHRONIZED = 0x0020
    ACC_VOLATILE = 0x0040
    ACC_BRIDGE = 0x0040
    ACC_TRANSIENT = 0x0080
    ACC_VARARGS = 0x0080
    ACC_NATIVE = 0x0100
    ACC_INTERFACE = 0x0200
    ACC_ABSTRACT = 0x0400
    ACC_STRICT = 0x0800
    ACC_SYNTHETIC = 0x1000

    def __init__(self, dex_data: bytes):
        self.data = dex_data
        self.is_valid = False
        self.strings: List[str] = []
        self.types: List[str] = []
        self.fields: List[Dict[str, str]] = []
        self.methods: List[Dict[str, Any]] = []
        self.classes: List[Dict[str, Any]] = []

        if len(dex_data) >= 0x70 and dex_data.startswith(b"dex\n"):
            self.is_valid = True
            self._parse_dex()

    def _parse_dex(self):
        """Parse core DEX tables."""
        try:
            # Header layout:
            # 0x00: magic (8)
            # 0x08: checksum (4)
            # 0x0c: signature (20)
            # 0x20: file_size (4)
            # 0x24: header_size (4)
            # 0x28: endian_tag (4)
            # 0x2c: link_size (4), link_off (4)
            # 0x34: map_off (4)
            # 0x38: string_ids_size (4), string_ids_off (4)
            # 0x40: type_ids_size (4), type_ids_off (4)
            # 0x48: proto_ids_size (4), proto_ids_off (4)
            # 0x50: field_ids_size (4), field_ids_off (4)
            # 0x58: method_ids_size (4), method_ids_off (4)
            # 0x60: class_defs_size (4), class_defs_off (4)
            # 0x68: data_size (4), data_off (4)
            (
                str_size, str_off,
                type_size, type_off,
                proto_size, proto_off,
                field_size, field_off,
                method_size, method_off,
                class_size, class_off
            ) = struct.unpack("<12I", self.data[0x38:0x68])

            # 1. Parse String IDs
            for i in range(str_size):
                str_data_off = struct.unpack("<I", self.data[str_off + i*4 : str_off + (i+1)*4])[0]
                _, data_start = read_uleb128(self.data, str_data_off)
                null_pos = self.data.find(b"\x00", data_start)
                if null_pos != -1:
                    s = self.data[data_start:null_pos].decode("utf-8", errors="ignore")
                    self.strings.append(s)
                else:
                    self.strings.append("")

            # 2. Parse Type IDs
            for i in range(type_size):
                desc_idx = struct.unpack("<I", self.data[type_off + i*4 : type_off + (i+1)*4])[0]
                if desc_idx < len(self.strings):
                    self.types.append(self.strings[desc_idx])
                else:
                    self.types.append(f"Type_{desc_idx}")

            # 3. Parse Field IDs: class_idx (ushort), type_idx (ushort), name_idx (uint)
            for i in range(field_size):
                c_idx, t_idx, n_idx = struct.unpack("<HHI", self.data[field_off + i*8 : field_off + (i+1)*8])
                c_name = self.types[c_idx] if c_idx < len(self.types) else "UnknownClass"
                t_name = self.types[t_idx] if t_idx < len(self.types) else "UnknownType"
                f_name = self.strings[n_idx] if n_idx < len(self.strings) else "UnknownField"
                self.fields.append({
                    "class": c_name,
                    "type": t_name,
                    "name": f_name
                })

            # 4. Parse Method IDs: class_idx (ushort), proto_idx (ushort), name_idx (uint)
            for i in range(method_size):
                c_idx, p_idx, n_idx = struct.unpack("<HHI", self.data[method_off + i*8 : method_off + (i+1)*8])
                c_name = self.types[c_idx] if c_idx < len(self.types) else "UnknownClass"
                m_name = self.strings[n_idx] if n_idx < len(self.strings) else "UnknownMethod"
                self.methods.append({
                    "class": c_name,
                    "proto_idx": p_idx,
                    "name": m_name
                })

            # 5. Parse Class Definitions: class_idx (uint), access_flags (uint), superclass_idx (uint), ...
            for i in range(class_size):
                rec = self.data[class_off + i*32 : class_off + (i+1)*32]
                c_idx, access_flags, super_idx = struct.unpack("<III", rec[:12])
                c_name = self.types[c_idx] if c_idx < len(self.types) else f"Class_{c_idx}"
                s_name = self.types[super_idx] if super_idx < len(self.types) else "java/lang/Object"
                self.classes.append({
                    "name": c_name,
                    "superclass": s_name,
                    "access_flags": access_flags,
                    "is_public": bool(access_flags & self.ACC_PUBLIC),
                    "is_abstract": bool(access_flags & self.ACC_ABSTRACT),
                    "is_interface": bool(access_flags & self.ACC_INTERFACE)
                })

        except Exception:
            pass

    def get_app_classes(self) -> List[str]:
        """Return non-framework application classes (filtering out android, androidx, kotlin, etc.)."""
        app_classes = []
        framework_prefixes = (
            "Landroid/", "Landroidx/", "Lkotlin/", "Lkotlinx/",
            "Lcom/google/", "Lorg/intellij/", "Lorg/jetbrains/",
            "Ljava/", "Ljavax/"
        )
        for c in self.classes:
            name = c.get("name", "")
            if not any(name.startswith(p) for p in framework_prefixes):
                app_classes.append(name)
        return app_classes

    def get_interesting_methods(self, keywords: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """Return methods matching suspicious or target CTF keywords."""
        keys = tuple(keywords or ["flag", "check", "verify", "cmp", "secret", "get_flag", "pass"])
        interesting = []
        for m in self.methods:
            m_name_lower = m["name"].lower()
            if any(k in m_name_lower for k in keys):
                interesting.append(m)
        return interesting

    def get_native_methods(self) -> List[Dict[str, Any]]:
        """Find methods that are native (e.g. loaded via JNI / System.loadLibrary)."""
        # Cross reference with strings or class data if available
        natives = []
        for m in self.methods:
            if any(term in m["class"].lower() for term in ("native", "jni")) or "native" in m["name"].lower():
                natives.append(m)
        return natives

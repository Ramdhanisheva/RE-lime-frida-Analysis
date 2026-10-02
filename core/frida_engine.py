"""
Automotion Reverse Engineering - Frida Automation & Script Generator
Handles ADB device connectivity, frida-server management, and automatic
generation of ready-to-run Frida hooks for CTF challenges:
- Static & Instance method callers (Frida Labs 0x1, 0x2, 0x4, 0x5)
- Variable & Field modifiers (Frida Labs 0x3)
- Method hooking & Return value replacement (Frida Labs 0x6, 0x7)
- Native .so JNI exports & NativeFunction invocation (Frida Labs 0x8, 0x9, 0xA, 0xB)
- Root detection bypass (hiding su, test-keys, TracerPid)
- SSL pinning bypass
- Universal Live Crypto Sniffer (dumps Cipher keys, IVs, and plaintexts live)
"""

import os
import subprocess
from typing import Any, Dict, List, Optional

import config


class FridaEngine:
    """Manages ADB and generates targeted Frida scripts."""

    def __init__(self, adb_path: Optional[str] = None, output_dir: Optional[str] = None):
        self.adb_path = adb_path or config.ADB_PATH
        self.output_dir = output_dir or "results"
        self.frida_server_bin = config.FRIDA_SERVER_BINARY
        os.makedirs(self.output_dir, exist_ok=True)

    def check_adb_devices(self) -> List[str]:
        """Check for connected ADB devices or emulators."""
        devices = []
        if not os.path.exists(self.adb_path):
            return devices
        try:
            res = subprocess.run([self.adb_path, "devices"], capture_output=True, text=True, timeout=5)
            lines = res.stdout.strip().splitlines()
            for line in lines[1:]:
                parts = line.split()
                if len(parts) >= 2 and parts[1] == "device":
                    devices.append(parts[0])
        except Exception:
            pass
        return devices

    def generate_scripts_suite(
        self,
        package_name: str,
        main_activity: str,
        classes: List[str],
        interesting_methods: List[Dict[str, Any]],
        native_libs: List[str]
    ) -> Dict[str, str]:
        """
        Generate a complete suite of targeted Frida scripts tailored for the APK.
        Saves each script to disk and returns a dictionary of {name: script_path}.
        """
        scripts_generated: Dict[str, str] = {}
        script_dir = os.path.join(self.output_dir, "frida_scripts")
        os.makedirs(script_dir, exist_ok=True)

        pkg = package_name or "com.example.app"
        main_act = main_activity or f"{pkg}.MainActivity"
        clean_classes = []
        for c in classes:
            if c.startswith("L") and c.endswith(";"):
                clean_classes.append(c[1:-1].replace("/", "."))
            else:
                clean_classes.append(c)

        # 1. Universal Crypto Sniffer
        crypto_js = """
Java.perform(function() {
    console.log("[*] === Universal Crypto Sniffer Active ===");

    // 1. Hook SecretKeySpec constructor
    var SecretKeySpec = Java.use("javax.crypto.spec.SecretKeySpec");
    SecretKeySpec.$init.overload('[B', 'java.lang.String').implementation = function(keyBytes, algorithm) {
        var keyHex = "";
        var keyAscii = "";
        for (var i = 0; i < keyBytes.length; i++) {
            var b = keyBytes[i] & 0xFF;
            keyHex += (b < 16 ? "0" : "") + b.toString(16) + " ";
            keyAscii += (b >= 32 && b <= 126) ? String.fromCharCode(b) : ".";
        }
        console.log("[*] [SecretKeySpec] Algorithm: " + algorithm);
        console.log("    Key (ASCII): " + keyAscii);
        console.log("    Key (HEX):   " + keyHex);
        return this.$init(keyBytes, algorithm);
    };

    // 2. Hook IvParameterSpec constructor
    try {
        var IvParameterSpec = Java.use("javax.crypto.spec.IvParameterSpec");
        IvParameterSpec.$init.overload('[B').implementation = function(ivBytes) {
            var ivHex = "";
            for (var i = 0; i < ivBytes.length; i++) {
                var b = ivBytes[i] & 0xFF;
                ivHex += (b < 16 ? "0" : "") + b.toString(16) + " ";
            }
            console.log("[*] [IvParameterSpec] IV (HEX): " + ivHex);
            return this.$init(ivBytes);
        };
    } catch(e) {}

    // 3. Hook Cipher.doFinal
    var Cipher = Java.use("javax.crypto.Cipher");
    Cipher.doFinal.overload('[B').implementation = function(input) {
        var result = this.doFinal(input);
        try {
            var StringClass = Java.use("java.lang.String");
            var outStr = StringClass.$new(result);
            console.log("[+] [Cipher.doFinal] Output String: " + outStr);
        } catch(err) {
            console.log("[+] [Cipher.doFinal] Output len: " + (result ? result.length : 0));
        }
        return result;
    };
});
"""
        p0 = os.path.join(script_dir, "00_universal_crypto_sniffer.js")
        with open(p0, "w", encoding="utf-8") as f0:
            f0.write(crypto_js.strip())
        scripts_generated["Universal Crypto Sniffer"] = p0

        # 2. Static Method Invoker
        target_static_meth = "get_flag"
        for im in interesting_methods:
            if "flag" in im["name"].lower():
                target_static_meth = im["name"]
                break

        static_js = f"""
Java.perform(function() {{
    console.log("[*] Calling static method: {target_static_meth}");
    try {{
        var act = Java.use("{main_act}");
        try {{
            var res = act.{target_static_meth}();
            console.log("[+] Result: " + res);
        }} catch(e) {{
            var candidates = [4919, 1337, 1234, 1, 0];
            for (var i = 0; i < candidates.length; i++) {{
                try {{
                    var res = act.{target_static_meth}(candidates[i]);
                    console.log("[+] Success with arg (" + candidates[i] + "): " + res);
                    break;
                }} catch(err) {{}}
            }}
        }}
    }} catch(e) {{
        console.log("[-] Error: " + e);
    }}
}});
"""
        p1 = os.path.join(script_dir, "01_invoke_static_method.js")
        with open(p1, "w", encoding="utf-8") as f1:
            f1.write(static_js.strip())
        scripts_generated["Static Method Invoker"] = p1

        # 3. Existing Instance Finder
        instance_js = f"""
Java.performNow(function() {{
    console.log("[*] Searching for existing instances of {main_act}...");
    Java.choose("{main_act}", {{
        onMatch: function(instance) {{
            console.log("[+] Instance found: " + instance);
            var methods = ["{target_static_meth}", "flag", "get_flag", "getFlag", "check", "verify"];
            for (var i = 0; i < methods.length; i++) {{
                var m = methods[i];
                try {{
                    var res = instance[m]();
                    console.log("[+] Called " + m + "() -> " + res);
                }} catch(e) {{
                    try {{
                        var res = instance[m](1337);
                        console.log("[+] Called " + m + "(1337) -> " + res);
                    }} catch(e2) {{}}
                }}
            }}
        }},
        onComplete: function() {{
            console.log("[*] Java.choose scan completed.");
        }}
    }});
}});
"""
        p2 = os.path.join(script_dir, "02_choose_instance_invoker.js")
        with open(p2, "w", encoding="utf-8") as f2:
            f2.write(instance_js.strip())
        scripts_generated["Instance Method Invoker (Java.choose)"] = p2

        # 4. Variable / Field Modifier
        var_target_class = clean_classes[0] if clean_classes else main_act
        for c in clean_classes:
            if "check" in c.lower() or "flag" in c.lower():
                var_target_class = c
                break

        var_js = f"""
Java.perform(function() {{
    console.log("[*] Modifying fields on class: {var_target_class}");
    try {{
        var target = Java.use("{var_target_class}");
        var fields = ["code", "is_admin", "isAdmin", "flag", "unlocked", "score", "token", "pass"];
        for (var i = 0; i < fields.length; i++) {{
            var f = fields[i];
            try {{
                if (target[f] !== undefined) {{
                    target[f].value = 512;
                    console.log("[+] Set static field " + f + " = 512");
                }}
            }} catch(e) {{}}
        }}

        try {{
            for (var k = 0; k < 256; k++) {{
                target.increase();
            }}
            console.log("[+] Called increase() 256 times");
        }} catch(e) {{}}
    }} catch(e) {{
        console.log("[-] Error: " + e);
    }}
}});
"""
        p3 = os.path.join(script_dir, "03_modify_variables.js")
        with open(p3, "w", encoding="utf-8") as f3:
            f3.write(var_js.strip())
        scripts_generated["Variable Modifier"] = p3

        # 5. Method Hook & Return Value Override
        hook_js = f"""
Java.perform(function() {{
    console.log("[*] Hooking validation methods in {main_act}...");
    var target = Java.use("{main_act}");
    var hook_candidates = ["check", "verify", "validate", "isFlagValid", "checkPassword", "cmpstr", "check_flag"];
    
    hook_candidates.forEach(function(mName) {{
        try {{
            if (target[mName]) {{
                target[mName].implementation = function() {{
                    console.log("[+] Method " + mName + " intercepted! Forcing return 1 / true.");
                    return 1;
                }};
                console.log("[*] Successfully hooked " + mName);
            }}
        }} catch(e) {{}}
    }});
}});
"""
        p4 = os.path.join(script_dir, "04_hook_return_values.js")
        with open(p4, "w", encoding="utf-8") as f4:
            f4.write(hook_js.strip())
        scripts_generated["Method Return Value Override"] = p4

        # 6. Native Shared Library Hooking
        native_target = native_libs[0] if native_libs else "libnative.so"
        native_js = f"""
console.log("[*] Attaching to native exports in {native_target}...");
["strcmp", "strncmp", "memcmp"].forEach(function(funcName) {{
    var addr = Module.findExportByName(null, funcName);
    if (addr) {{
        Interceptor.attach(addr, {{
            onEnter: function(args) {{
                try {{
                    var s1 = Memory.readUtf8String(args[0]);
                    var s2 = Memory.readUtf8String(args[1]);
                    if (s1 && s2 && (s1.includes("flag") || s2.includes("flag") || s1.includes("FLAG") || s2.includes("FLAG") || s1.includes("HackToday") || s2.includes("HackToday") || s1.includes("FRIDA") || s2.includes("FRIDA"))) {{
                        console.log("[BINGO strcmp] Arg1: " + s1 + " | Arg2: " + s2);
                    }}
                }} catch(e) {{}}
            }}
        }});
    }}
}});
"""
        p5 = os.path.join(script_dir, "05_native_so_hook.js")
        with open(p5, "w", encoding="utf-8") as f5:
            f5.write(native_js.strip())
        scripts_generated["Native .so String Interceptor"] = p5

        # 7. Root Detection & Anti-Debug Bypass
        root_bypass_js = """
Java.perform(function() {
    console.log("[*] Bypassing Root Detection & Anti-Debug...");

    var File = Java.use("java.io.File");
    File.exists.implementation = function() {
        var path = this.getAbsolutePath();
        if (path.indexOf("/system/bin/su") !== -1 ||
            path.indexOf("/system/xbin/su") !== -1 ||
            path.indexOf("/sbin/su") !== -1 ||
            path.indexOf("frida-server") !== -1 ||
            path.indexOf("magisk") !== -1) {
            console.log("[*] Hidden root binary: " + path);
            return false;
        }
        return this.exists();
    };

    var Build = Java.use("android.os.Build");
    try {
        Build.TAGS.value = "release-keys";
    } catch(e) {}

    var Runtime = Java.use("java.lang.Runtime");
    Runtime.exec.overload('java.lang.String').implementation = function(cmd) {
        if (cmd.indexOf("su") !== -1 || cmd.indexOf("which") !== -1) {
            console.log("[*] Blocked root exec: " + cmd);
            return this.exec("echo fake");
        }
        return this.exec(cmd);
    };
});
"""
        p6 = os.path.join(script_dir, "06_root_bypass.js")
        with open(p6, "w", encoding="utf-8") as f6:
            f6.write(root_bypass_js.strip())
        scripts_generated["Root Detection Bypass"] = p6

        return scripts_generated

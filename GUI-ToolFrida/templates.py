"""
GUI-ToolFrida - Frida Script Templates for Android CTF Competitions
"""

TEMPLATES = {
    "00_AUTO_SOLVER_ALL_IN_ONE": """/*
 * ============================================================================
 * [CTF MASTER AUTO-SOLVER] ALL-IN-ONE UNIVERSAL SNIFFER & BYPASS
 * Otomatis meng-hook:
 * 1. Root & Magisk Detection Bypass (Aplikasi tidak akan force-close di root)
 * 2. String & Bytes Comparison Sniffer (String.equals, compareTo, Arrays.equals)
 * 3. Cryptography Sniffer (AES/DES/RSA Key, IV, Plaintext & Ciphertext)
 * 4. Base64 & Hash Sniffer (Base64.decode/encode)
 * 5. Toast & Logcat Sniffer (Mencegat pesan flag di layar)
 * ============================================================================
 */
Java.perform(function() {
    console.log("========================================================");
    console.log("[🔥 CTF MASTER AUTO-SOLVER] SEMUA HOOK AKTIF & STANDBY!");
    console.log("-> Root Bypass: AKTIF");
    console.log("-> String & Flag Sniffer: AKTIF");
    console.log("-> Crypto (AES/Key/IV) Sniffer: AKTIF");
    console.log("-> Silakan buka app di emulator & ketik flag / klik tombol!");
    console.log("========================================================\\n");

    function bytesToHex(bytes) {
        if (!bytes) return "";
        var hex = [];
        for (var i = 0; i < bytes.length; i++) {
            var b = (bytes[i] & 0xFF).toString(16);
            if (b.length === 1) b = "0" + b;
            hex.push(b);
        }
        return hex.join("");
    }

    function bytesToString(bytes) {
        if (!bytes) return "";
        try {
            var StringClass = Java.use("java.lang.String");
            return StringClass.$new(bytes, "UTF-8").toString();
        } catch(e) {
            return "";
        }
    }

    // 1. ROOT DETECTION BYPASS
    try {
        var File = Java.use("java.io.File");
        File.exists.implementation = function() {
            var path = this.getAbsolutePath();
            if (path.indexOf("su") !== -1 || path.indexOf("busybox") !== -1 ||
                path.indexOf("magisk") !== -1 || path.indexOf("Superuser") !== -1) {
                console.log("[BYPASS ROOT] File.exists diblokir -> " + path);
                return false;
            }
            return this.exists();
        };
    } catch(e) {}

    try {
        var Runtime = Java.use("java.lang.Runtime");
        Runtime.exec.overload('java.lang.String').implementation = function(cmd) {
            if (cmd.indexOf("su") !== -1 || cmd.indexOf("which") !== -1) {
                console.log("[BYPASS ROOT] Runtime.exec diblokir -> " + cmd);
                return this.exec("echo no_root");
            }
            return this.exec(cmd);
        };
    } catch(e) {}

    // 2. STRING & BYTES COMPARISON (FLAG SNIFFER - SAFE RE-ENTRANCY LOCK)
    var inHook = false;
    try {
        var StringClass = Java.use("java.lang.String");
        StringClass.equals.implementation = function(obj) {
            if (inHook || obj === null) {
                return this.equals(obj);
            }
            inHook = true;
            try {
                var s1 = "" + this;
                var s2 = "" + obj;
                if (s1.length > 2 && s2.length > 2 && s1 !== s2) {
                    var s1_l = s1.toLowerCase();
                    var s2_l = s2.toLowerCase();
                    if (s1_l.indexOf("flag") !== -1 || s2_l.indexOf("flag") !== -1 ||
                        s1.indexOf("{") !== -1 || s2.indexOf("{") !== -1 ||
                        s1_l.indexOf("hacktoday") !== -1 || s2_l.indexOf("hacktoday") !== -1 ||
                        s1_l.indexOf("ctf") !== -1 || s2_l.indexOf("ctf") !== -1 ||
                        s1_l.indexOf("key") !== -1 || s2_l.indexOf("key") !== -1) {
                        console.log("\n[🚩 BINGO String.equals]");
                        console.log("   -> Value A (Target/Input) : " + s1);
                        console.log("   -> Value B (Target/Input) : " + s2);
                    }
                }
            } catch(err) {}
            finally {
                inHook = false;
            }
            return this.equals(obj);
        };
    } catch(e) {}

    try {
        var Arrays = Java.use("java.util.Arrays");
        Arrays.equals.overload('[B', '[B').implementation = function(a, b) {
            if (a !== null && b !== null && a.length > 3) {
                var strA = bytesToString(a);
                var strB = bytesToString(b);
                if (strA || strB) {
                    console.log("\n[🚩 BINGO Arrays.equals byte[]]");
                    console.log("   -> Bytes A (ASCII) : " + strA + " [Hex: " + bytesToHex(a) + "]");
                    console.log("   -> Bytes B (ASCII) : " + strB + " [Hex: " + bytesToHex(b) + "]");
                }
            }
            return this.equals(a, b);
        };
    } catch(e) {}


    // 3. CRYPTOGRAPHY SNIFFER (AES / DES / RSA)
    try {
        var SecretKeySpec = Java.use("javax.crypto.spec.SecretKeySpec");
        SecretKeySpec.$init.overload('[B', 'java.lang.String').implementation = function(keyBytes, algo) {
            console.log("\\n[🔐 CRYPTO SecretKeySpec]");
            console.log("   -> Algorithm : " + algo);
            console.log("   -> Key (Hex) : " + bytesToHex(keyBytes));
            console.log("   -> Key (Txt) : " + bytesToString(keyBytes));
            return this.$init(keyBytes, algo);
        };
    } catch(e) {}

    try {
        var IvParameterSpec = Java.use("javax.crypto.spec.IvParameterSpec");
        IvParameterSpec.$init.overload('[B').implementation = function(ivBytes) {
            console.log("\\n[🔐 CRYPTO IV Parameter]");
            console.log("   -> IV (Hex) : " + bytesToHex(ivBytes));
            console.log("   -> IV (Txt) : " + bytesToString(ivBytes));
            return this.$init(ivBytes);
        };
    } catch(e) {}

    try {
        var Cipher = Java.use("javax.crypto.Cipher");
        Cipher.doFinal.overload('[B').implementation = function(input) {
            var ret = this.doFinal(input);
            console.log("\\n[🔐 CRYPTO Cipher.doFinal]");
            console.log("   -> Input  (Hex) : " + bytesToHex(input));
            console.log("   -> Input  (Txt) : " + bytesToString(input));
            console.log("   -> Output (Hex) : " + bytesToHex(ret));
            console.log("   -> Output (Txt) : " + bytesToString(ret));
            return ret;
        };
    } catch(e) {}

    // 4. BASE64 SNIFFER
    try {
        var Base64 = Java.use("android.util.Base64");
        Base64.decode.overload('java.lang.String', 'int').implementation = function(str, flags) {
            var ret = this.decode(str, flags);
            var decodedStr = bytesToString(ret);
            if (decodedStr && decodedStr.length > 2) {
                console.log("\\n[📦 Base64.decode] Input: " + str + " --> Output: " + decodedStr);
            }
            return ret;
        };
    } catch(e) {}

    // 5. TOAST SNIFFER
    try {
        var Toast = Java.use("android.widget.Toast");
        Toast.makeText.overload('android.content.Context', 'java.lang.CharSequence', 'int').implementation = function(ctx, text, dur) {
            console.log("\\n[📢 Toast.makeText] " + text);
            return this.makeText(ctx, text, dur);
        };
    } catch(e) {}
});
""",
    "01_String_Equals_Sniffer": """/*
 * [CTF SOLVER] Universal String & Array Comparison Sniffer
 * Intercepts java.lang.String.equals, equalsIgnoreCase, and Arrays.equals
 * Catches flag comparisons when user clicks 'Check / Submit'
 */
Java.perform(function() {
    console.log("[*] === Universal String.equals Sniffer Active ===");
    var StringClass = Java.use("java.lang.String");
    var inHook = false;

    StringClass.equals.implementation = function(obj) {
        if (inHook || obj === null) {
            return this.equals(obj);
        }
        inHook = true;
        try {
            var s1 = "" + this;
            var s2 = "" + obj;
            if (s1.length > 2 && s2.length > 2 && s1 !== s2) {
                var s1_l = s1.toLowerCase();
                var s2_l = s2.toLowerCase();
                if (s1_l.indexOf("flag") !== -1 || s2_l.indexOf("flag") !== -1 ||
                    s1.indexOf("{") !== -1 || s2.indexOf("{") !== -1 ||
                    s1_l.indexOf("hacktoday") !== -1 || s2_l.indexOf("hacktoday") !== -1 ||
                    s1_l.indexOf("ctf") !== -1 || s2_l.indexOf("ctf") !== -1) {
                    console.log("\n[🚩 BINGO String.equals]");
                    console.log("   -> Expected / Input: " + s1);
                    console.log("   -> Input / Expected: " + s2);
                }
            }
        } catch(e) {}
        finally {
            inHook = false;
        }
        return this.equals(obj);
    };


    var Arrays = Java.use("java.util.Arrays");
    Arrays.equals.overload('[B', '[B').implementation = function(a, b) {
        if (a !== null && b !== null && a.length > 3) {
            try {
                var strA = StringClass.$new(a);
                var strB = StringClass.$new(b);
                if (strA.indexOf("flag") !== -1 || strB.indexOf("flag") !== -1 ||
                    strA.indexOf("HackToday") !== -1 || strB.indexOf("HackToday") !== -1) {
                    console.log("[BINGO Arrays.equals byte[]] A: " + strA + " | B: " + strB);
                }
            } catch(e) {}
        }
        return this.equals(a, b);
    };
});
""",

    "02_Universal_Crypto_Sniffer": """/*
 * [CTF SOLVER] Universal Cryptography Key & Plaintext Sniffer
 * Dumps SecretKeySpec, IvParameterSpec, and Cipher.doFinal output
 */
Java.perform(function() {
    console.log("[*] === Universal Crypto Sniffer Active ===");

    // 1. Hook SecretKeySpec
    var SecretKeySpec = Java.use("javax.crypto.spec.SecretKeySpec");
    SecretKeySpec.$init.overload('[B', 'java.lang.String').implementation = function(keyBytes, algorithm) {
        var keyHex = "";
        var keyAscii = "";
        for (var i = 0; i < keyBytes.length; i++) {
            var b = keyBytes[i] & 0xFF;
            keyHex += (b < 16 ? "0" : "") + b.toString(16) + " ";
            keyAscii += (b >= 32 && b <= 126) ? String.fromCharCode(b) : ".";
        }
        console.log("[+] [SecretKeySpec] Algorithm: " + algorithm);
        console.log("    Key (ASCII): " + keyAscii);
        console.log("    Key (HEX):   " + keyHex);
        return this.$init(keyBytes, algorithm);
    };

    // 2. Hook IvParameterSpec
    try {
        var IvParameterSpec = Java.use("javax.crypto.spec.IvParameterSpec");
        IvParameterSpec.$init.overload('[B').implementation = function(ivBytes) {
            var ivHex = "";
            for (var i = 0; i < ivBytes.length; i++) {
                var b = ivBytes[i] & 0xFF;
                ivHex += (b < 16 ? "0" : "") + b.toString(16) + " ";
            }
            console.log("[+] [IvParameterSpec] IV (HEX): " + ivHex);
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
            console.log("[BINGO Cipher.doFinal] Output Plaintext: " + outStr);
        } catch(err) {
            console.log("[+] [Cipher.doFinal] Output len: " + (result ? result.length : 0));
        }
        return result;
    };
});
""",

    "03_Root_And_AntiDebug_Bypass": """/*
 * [CTF SOLVER] Universal Root Detection & Anti-Debug Bypass
 * Hides su files, Magisk, test-keys, and blocks Runtime root commands
 */
Java.perform(function() {
    console.log("[*] === Root & Anti-Debug Bypass Active ===");

    // 1. File.exists bypass
    var File = Java.use("java.io.File");
    File.exists.implementation = function() {
        var path = this.getAbsolutePath();
        if (path.indexOf("/system/bin/su") !== -1 ||
            path.indexOf("/system/xbin/su") !== -1 ||
            path.indexOf("/sbin/su") !== -1 ||
            path.indexOf("frida-server") !== -1 ||
            path.indexOf("magisk") !== -1 ||
            path.indexOf("Superuser.apk") !== -1) {
            console.log("[*] Hidden root file: " + path);
            return false;
        }
        return this.exists();
    };

    // 2. Build TAGS bypass
    try {
        var Build = Java.use("android.os.Build");
        Build.TAGS.value = "release-keys";
    } catch(e) {}

    // 3. Runtime.exec bypass
    var Runtime = Java.use("java.lang.Runtime");
    Runtime.exec.overload('java.lang.String').implementation = function(cmd) {
        if (cmd.indexOf("su") !== -1 || cmd.indexOf("which") !== -1) {
            console.log("[*] Blocked root exec: " + cmd);
            return this.exec("echo fake");
        }
        return this.exec(cmd);
    };
});
""",

    "04_Hook_Method_Return_True": """/*
 * [CTF SOLVER] Force Validation Methods Return True / 1
 * Edit 'targetClass' below with the APK's main class or validator!
 */
Java.perform(function() {
    console.log("[*] === Return True / Validation Bypass Active ===");

    // Ubah nama class sesuai target di Jadx:
    var targetClassName = "com.example.challenge.MainActivity";

    try {
        var target = Java.use(targetClassName);
        var methods = ["check", "verify", "validate", "isFlagValid", "checkPassword", "isLicenseValid", "check_flag"];

        methods.forEach(function(mName) {
            try {
                if (target[mName]) {
                    target[mName].implementation = function() {
                        console.log("[BINGO] Method " + mName + " intercepted! Forcing return true / 1.");
                        return 1;
                    };
                    console.log("[+] Successfully hooked " + mName);
                }
            } catch(err) {}
        });
    } catch(e) {
        console.log("[-] Class " + targetClassName + " not found: " + e);
    }
});
""",

    "05_Native_Strcmp_Sniffer": """/*
 * [CTF SOLVER] Native libc strcmp / memcmp Sniffer
 * Intercepts native C/C++ string comparisons in .so libraries
 */
console.log("[*] === Native strcmp / strncmp / memcmp Sniffer Active ===");

["strcmp", "strncmp", "memcmp"].forEach(function(funcName) {
    var addr = Module.findExportByName(null, funcName);
    if (addr) {
        Interceptor.attach(addr, {
            onEnter: function(args) {
                try {
                    var s1 = Memory.readUtf8String(args[0]);
                    var s2 = Memory.readUtf8String(args[1]);
                    if (s1 && s2 && s1.length > 3 && s2.length > 3) {
                        if (s1.indexOf("flag") !== -1 || s2.indexOf("flag") !== -1 ||
                            s1.indexOf("FLAG") !== -1 || s2.indexOf("FLAG") !== -1 ||
                            s1.indexOf("HackToday") !== -1 || s2.indexOf("HackToday") !== -1 ||
                            s1.indexOf("{") !== -1 || s2.indexOf("{") !== -1) {
                            console.log("[BINGO native " + funcName + "]");
                            console.log("   Arg1: " + s1);
                            console.log("   Arg2: " + s2);
                        }
                    }
                } catch(e) {}
            }
        });
    }
});
""",

    "06_Java_Choose_Instance_Invoker": """/*
 * [CTF SOLVER] Java.choose Instance Method Invoker
 * Finds instantiated objects on the Android heap and invokes uncalled methods
 */
Java.perform(function() {
    // Ubah nama class target:
    var targetClass = "com.example.challenge.MainActivity";
    console.log("[*] Searching for active heap instances of: " + targetClass);

    Java.choose(targetClass, {
        onMatch: function(instance) {
            console.log("[+] Active instance found: " + instance);
            var candidates = ["get_flag", "getFlag", "flag", "check", "revealFlag", "solve"];
            candidates.forEach(function(m) {
                try {
                    var res = instance[m]();
                    console.log("[BINGO] Called " + m + "() -> Result: " + res);
                } catch(e) {}
            });
        },
        onComplete: function() {
            console.log("[*] Java.choose scan completed.");
        }
    });
});
""",

    "07_In_Memory_DEX_Dumper": """/*
 * [CTF SOLVER] In-Memory Dynamic DEX Dumper
 * Intercepts InMemoryDexClassLoader and dumps the decrypted DEX buffer from RAM
 */
Java.perform(function() {
    console.log("[*] === In-Memory DEX Dumper Active ===");

    try {
        var InMemoryDexClassLoader = Java.use("dalvik.system.InMemoryDexClassLoader");
        InMemoryDexClassLoader.$init.overload('java.nio.ByteBuffer', 'java.lang.ClassLoader').implementation = function(buffer, loader) {
            console.log("[+] Intercepted InMemoryDexClassLoader! Dumping buffer...");
            try {
                var FileOutputStream = Java.use("java.io.FileOutputStream");
                var dumpPath = "/data/local/tmp/dumped_" + Date.now() + ".dex";
                var fos = FileOutputStream.$new(dumpPath);
                var channel = fos.getChannel();
                channel.write(buffer);
                fos.close();
                console.log("[BINGO] DEX dumped successfully to: " + dumpPath);
                console.log("        Run: adb pull " + dumpPath + " .");
            } catch(err) {
                console.log("[-] Failed to write DEX: " + err);
            }
            return this.$init(buffer, loader);
        };
    } catch(e) {}
});
""",

    "08_Universal_SSL_Pinning_Bypass": """/*
 * [CTF SOLVER] Universal Android SSL Pinning Bypass
 * Bypasses TrustManager, OkHttp3, CertificatePinner, and Conscrypt
 */
Java.perform(function() {
    console.log("[*] === Universal SSL Pinning Bypass Active ===");

    // TrustManager bypass
    var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
    var SSLContext = Java.use('javax.net.ssl.SSLContext');
    var TrustManager = Java.registerClass({
        name: 'com.custom.TrustManager',
        implements: [X509TrustManager],
        methods: {
            checkClientTrusted: function(chain, authType) {},
            checkServerTrusted: function(chain, authType) {},
            getAcceptedIssuers: function() { return []; }
        }
    });

    var TrustManagers = [TrustManager.$new()];
    var SSLContext_init = SSLContext.init.overload(
        '[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom'
    );
    SSLContext_init.implementation = function(km, tm, sr) {
        console.log("[+] Intercepted SSLContext.init! Applying permissive TrustManager.");
        SSLContext_init.call(this, km, TrustManagers, sr);
    };
});
""",

    "09_Biometric_Keystore_Bypass": """/*
 * [CTF SOLVER] Biometric & Fingerprint Authentication Bypass
 */
Java.perform(function() {
    console.log("[*] === Biometric Authentication Bypass Active ===");

    try {
        var BiometricPromptAuth = Java.use("android.hardware.biometrics.BiometricPrompt$AuthenticationCallback");
        BiometricPromptAuth.onAuthenticationFailed.implementation = function() {
            console.log("[*] Biometric failed intercepted -> Forcing onAuthenticationSucceeded!");
            this.onAuthenticationSucceeded(null);
        };
    } catch(e) {}

    try {
        var BiometricPromptCompat = Java.use("androidx.biometric.BiometricPrompt$AuthenticationCallback");
        BiometricPromptCompat.onAuthenticationFailed.implementation = function() {
            console.log("[*] AndroidX Biometric failed intercepted -> Forcing onAuthenticationSucceeded!");
            this.onAuthenticationSucceeded(null);
        };
    } catch(e) {}
});
""",

    "10_Logcat_Toast_Sniffer": """/*
 * [CTF SOLVER] Android Logcat & Toast Sniffer
 * Catches Toast messages and hidden Log.d / Log.i / Log.e messages
 */
Java.perform(function() {
    console.log("[*] === Logcat & Toast Sniffer Active ===");

    var Toast = Java.use("android.widget.Toast");
    Toast.makeText.overload('android.content.Context', 'java.lang.CharSequence', 'int').implementation = function(ctx, text, duration) {
        console.log("[BINGO Toast.makeText] " + text.toString());
        return this.makeText(ctx, text, duration);
    };

    var Log = Java.use("android.util.Log");
    ["d", "i", "v", "e", "w"].forEach(function(lvl) {
        try {
            Log[lvl].overload('java.lang.String', 'java.lang.String').implementation = function(tag, msg) {
                if (msg && (msg.indexOf("flag") !== -1 || msg.indexOf("FLAG") !== -1 || msg.indexOf("HackToday") !== -1 || msg.indexOf("{") !== -1)) {
                    console.log("[BINGO Log." + lvl + "][" + tag + "] " + msg);
                }
                return this[lvl](tag, msg);
            };
        } catch(e) {}
    });
});
""",

    "11_Call_Static_Method_Frida0x2": """/*
 * [CTF SOLVER] Panggil Static Method (Contoh: Frida-Labs 0x2)
 * Memanggil MainActivity.get_flag(4919) langsung di runtime
 */
Java.perform(function() {
    console.log("[*] Memanggil MainActivity.get_flag(4919)...");
    try {
        var MainActivity = Java.use("com.ad2001.frida0x2.MainActivity");
        MainActivity.get_flag(4919);
        console.log("[🚩 BINGO] get_flag(4919) berhasil dieksekusi! Lihat layar emulator!");
    } catch(e) {
        console.log("[-] Gagal memanggil method: " + e);
    }
});
"""
}


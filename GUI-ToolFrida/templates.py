"""
GUI-ToolFrida - Frida Script Templates for Android CTF Competitions
"""

TEMPLATES = {
    "00_UNIVERSAL_AUTO_SOLVER_ALL_IN_ONE": """/*
 * ============================================================================
 * [CTF MASTER UNIVERSAL AUTO-SOLVER]
 * Bekerja otomatis untuk SEMUA tipe soal Android CTF:
 * 1. Root & Magisk Bypass (File.exists, Runtime.exec, Build.TAGS)
 * 2. String & Bytes Comparison Sniffer (String.equals, Arrays.equals)
 * 3. Cryptography Sniffer (AES/DES/RSA Key, IV, Plaintext, Ciphertext, MessageDigest)
 * 4. Base64 & Hash Sniffer (Base64.decode, MD5, SHA-256)
 * 5. Storage Sniffer (SharedPreferences getString/putString)
 * 6. Toast & Logcat Sniffer (Mencegat pesan flag tersembunyi)
 * 7. Dynamic Method Finder (Mencari method *flag* / *secret* / *solve* di package)
 * ============================================================================
 */
Java.perform(function() {
    console.log("========================================================");
    console.log("[🔥 CTF MASTER AUTO-SOLVER] Universal Sniffer Aktif!");
    console.log("-> 🛡️ Root & Emulator Bypass : AKTIF");
    console.log("-> 🚩 String & Flag Sniffer  : AKTIF");
    console.log("-> 🔐 Crypto (AES/RSA/Key)   : AKTIF");
    console.log("-> 📦 Base64 & Storage       : AKTIF");
    console.log("-> 📢 Toast & Logcat Sniffer : AKTIF");
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

    // 1. ROOT DETECTION & EMULATOR BYPASS
    try {
        var File = Java.use("java.io.File");
        File.exists.implementation = function() {
            var path = this.getAbsolutePath();
            if (path.indexOf("su") !== -1 || path.indexOf("busybox") !== -1 ||
                path.indexOf("magisk") !== -1 || path.indexOf("Superuser") !== -1 ||
                path.indexOf("frida-server") !== -1) {
                console.log("[🛡️ BYPASS ROOT] File.exists blocked -> " + path);
                return false;
            }
            return this.exists();
        };
    } catch(e) {}

    try {
        var Runtime = Java.use("java.lang.Runtime");
        Runtime.exec.overload('java.lang.String').implementation = function(cmd) {
            if (cmd.indexOf("su") !== -1 || cmd.indexOf("which") !== -1 || cmd.indexOf("getprop") !== -1) {
                console.log("[🛡️ BYPASS ROOT] Runtime.exec blocked -> " + cmd);
                return this.exec("echo no_root");
            }
            return this.exec(cmd);
        };
    } catch(e) {}

    try {
        var Build = Java.use("android.os.Build");
        Build.TAGS.value = "release-keys";
        Build.FINGERPRINT.value = "google/pixel7/pixel7:13/TQ2A.230505.002/9892780:user/release-keys";
    } catch(e) {}

    // 2. STRING & BYTES COMPARISON SNIFFER (SAFE RE-ENTRANCY & NOISE FILTER)
    var inHook = false;
    var IGNORE_SYSTEM = ["androidkeystore", "androidnssp", "robolectric", "android@android.com", "mountain view", "california", "x509"];

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
                    
                    var isSystem = false;
                    for (var i = 0; i < IGNORE_SYSTEM.length; i++) {
                        if (s1_l.indexOf(IGNORE_SYSTEM[i]) !== -1 || s2_l.indexOf(IGNORE_SYSTEM[i]) !== -1) {
                            isSystem = true;
                            break;
                        }
                    }

                    if (!isSystem && (
                        s1_l.indexOf("flag") !== -1 || s2_l.indexOf("flag") !== -1 ||
                        s1.indexOf("{") !== -1 || s2.indexOf("{") !== -1 ||
                        s1_l.indexOf("hacktoday") !== -1 || s2_l.indexOf("hacktoday") !== -1 ||
                        s1_l.indexOf("ctf") !== -1 || s2_l.indexOf("ctf") !== -1 ||
                        s1_l.indexOf("secret") !== -1 || s2_l.indexOf("secret") !== -1 ||
                        s1_l.indexOf("password") !== -1 || s2_l.indexOf("password") !== -1 ||
                        s1_l.indexOf("auth") !== -1 || s2_l.indexOf("auth") !== -1)) {
                        console.log("\\n[🚩 BINGO String.equals]");
                        console.log("   -> Target / Expected : " + s1);
                        console.log("   -> Input  / Actual   : " + s2);
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
                var strA_l = strA.toLowerCase();
                var strB_l = strB.toLowerCase();
                
                var isSystem = false;
                for (var i = 0; i < IGNORE_SYSTEM.length; i++) {
                    if (strA_l.indexOf(IGNORE_SYSTEM[i]) !== -1 || strB_l.indexOf(IGNORE_SYSTEM[i]) !== -1) {
                        isSystem = true;
                        break;
                    }
                }

                if (!isSystem && (
                    strA_l.indexOf("flag") !== -1 || strB_l.indexOf("flag") !== -1 ||
                    strA.indexOf("{") !== -1 || strB.indexOf("{") !== -1 ||
                    strA_l.indexOf("hacktoday") !== -1 || strB_l.indexOf("hacktoday") !== -1 ||
                    strA_l.indexOf("ctf") !== -1 || strB_l.indexOf("ctf") !== -1)) {
                    console.log("\\n[🚩 BINGO Arrays.equals byte[]]");
                    console.log("   -> Bytes A (ASCII) : " + strA + " [Hex: " + bytesToHex(a) + "]");
                    console.log("   -> Bytes B (ASCII) : " + strB + " [Hex: " + bytesToHex(b) + "]");
                }
            }
            return this.equals(a, b);
        };
    } catch(e) {}


    // 3. CRYPTOGRAPHY SNIFFER (AES / DES / RSA / Key / IV / Plaintext)
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

    // 5. SHARED PREFERENCES SNIFFER
    try {
        var SharedPreferencesImpl = Java.use("android.app.SharedPreferencesImpl");
        SharedPreferencesImpl.getString.implementation = function(key, defValue) {
            var res = this.getString(key, defValue);
            if (key && (key.indexOf("flag") !== -1 || key.indexOf("key") !== -1 || key.indexOf("token") !== -1 || key.indexOf("pass") !== -1)) {
                console.log("\\n[💾 SharedPreferences.getString] Key: '" + key + "' -> Value: '" + res + "'");
            }
            return res;
        };
    } catch(e) {}

    // 6. TOAST & LOGCAT SNIFFER
    try {
        var Toast = Java.use("android.widget.Toast");
        Toast.makeText.overload('android.content.Context', 'java.lang.CharSequence', 'int').implementation = function(ctx, text, dur) {
            console.log("\\n[📢 Toast.makeText] " + text);
            return this.makeText(ctx, text, dur);
        };
    } catch(e) {}

    try {
        var Log = Java.use("android.util.Log");
        ["d", "i", "v", "e", "w"].forEach(function(lvl) {
            try {
                Log[lvl].overload('java.lang.String', 'java.lang.String').implementation = function(tag, msg) {
                    if (msg && (msg.indexOf("flag") !== -1 || msg.indexOf("FLAG") !== -1 || msg.indexOf("HackToday") !== -1 || msg.indexOf("{") !== -1)) {
                        console.log("\\n[📝 Log." + lvl + "][" + tag + "] " + msg);
                    }
                    return this[lvl](tag, msg);
                };
            } catch(e) {}
        });
    } catch(e) {}

    // 7. DYNAMIC AUTO-EXPLORER & METHOD AUTO-INVOKER (AUTO-SOLVER ENGINE)
    setTimeout(function() {
        Java.perform(function() {
            try {
                Java.enumerateLoadedClasses({
                    onMatch: function(className) {
                        if (!className.startsWith("android.") && !className.startsWith("java.") &&
                            !className.startsWith("androidx.") && !className.startsWith("com.google.") &&
                            !className.startsWith("kotlin.") && !className.startsWith("io.flutter.")) {
                            
                            try {
                                var Cls = Java.use(className);
                                var methods = Cls.class.getDeclaredMethods();
                                
                                methods.forEach(function(m) {
                                    var mName = m.getName();
                                    var mName_l = mName.toLowerCase();
                                    
                                    // Target method patterns: flag, solve, reveal, decode, secret, check
                                    if (mName_l.indexOf("flag") !== -1 || mName_l.indexOf("solve") !== -1 ||
                                        mName_l.indexOf("reveal") !== -1 || mName_l.indexOf("secret") !== -1 ||
                                        mName_l.indexOf("get_") !== -1 || mName_l.indexOf("decode") !== -1) {
                                        
                                        var paramTypes = m.getParameterTypes();
                                        console.log("\\n[🎯 AUTO-SOLVER] Ditemukan target method: " + className + "." + mName + "()");
                                        
                                        // A. No args -> Auto invoke
                                        if (paramTypes.length === 0) {
                                            try {
                                                var res = Cls[mName]();
                                                console.log("[🚩 BINGO Auto-Invoked Static] " + className + "." + mName + "() -> " + res);
                                            } catch(e) {}
                                            
                                            // Try instance via Java.choose
                                            Java.choose(className, {
                                                onMatch: function(inst) {
                                                    try {
                                                        var res = inst[mName]();
                                                        console.log("[🚩 BINGO Auto-Invoked Instance] " + className + "." + mName + "() -> " + res);
                                                    } catch(err) {}
                                                },
                                                onComplete: function() {}
                                            });
                                        }
                                        
                                        // B. 1 Integer parameter -> Try common CTF numbers (4919, 1337, 512, etc.)
                                        else if (paramTypes.length === 1 && paramTypes[0].getName() === "int") {
                                            var candidateInts = [4919, 1337, 512, 100, 0, 1, 42, 256, 1024, 0x1337, 7777];
                                            candidateInts.forEach(function(val) {
                                                try {
                                                    var res = Cls[mName](val);
                                                    console.log("[🚩 BINGO Auto-Invoked with " + val + "] " + className + "." + mName + "(" + val + ") -> " + res);
                                                } catch(err) {}
                                            });
                                        }
                                    }
                                });

                                // Check static variables (e.g. Checker.code = 512)
                                var fields = Cls.class.getDeclaredFields();
                                fields.forEach(function(f) {
                                    var fName = f.getName().toLowerCase();
                                    if (fName === "code" || fName === "flag" || fName === "key" || fName === "secret" || fName === "isvalid") {
                                        try {
                                            f.setAccessible(true);
                                            var val = f.get(null);
                                            console.log("\\n[💾 AUTO-SOLVER] Ditemukan static field: " + className + "." + f.getName() + " = " + val);
                                            if (typeof val === "number" && val === 0) {
                                                [512, 1337, 4919, 1, 100].forEach(function(testVal) {
                                                    try {
                                                        Cls[f.getName()].value = testVal;
                                                        console.log("[⚡ AUTO-SET] Set " + className + "." + f.getName() + " = " + testVal);
                                                    } catch(e) {}
                                                });
                                            }
                                        } catch(e) {}
                                    }
                                });

                            } catch(e) {}
                        }
                    },
                    onComplete: function() {
                        console.log("[*] Auto-Explorer selesai memindai semua method aplikasi.\\n");
                    }
                });
            } catch(e) {}
        });
    }, 1500);
});

""",

    "01_Universal_Live_Method_Tracer": """/*
 * [UNIVERSAL TRACER] Live Method Call Tracer
 * Otomatis melacak dan mencatat SEMUA pemanggilan method di package target!
 * Buka app di emulator -> klik tombol/input -> lihat method apa yang jalan & return value-nya!
 */
Java.perform(function() {
    console.log("[*] === Live Universal Method Tracer Active ===");
    console.log("[*] Menelusuri semua class target di memori runtime...\\n");

    Java.enumerateLoadedClasses({
        onMatch: function(className) {
            // Filter hanya class aplikasi (bukan android.* / java.*)
            if (!className.startsWith("android.") && !className.startsWith("java.") &&
                !className.startsWith("androidx.") && !className.startsWith("com.google.") &&
                !className.startsWith("kotlin.") && !className.startsWith("io.flutter.")) {
                
                try {
                    var hookClass = Java.use(className);
                    var methods = hookClass.class.getDeclaredMethods();
                    
                    methods.forEach(function(method) {
                        var methodName = method.getName();
                        if (methodName !== "$init" && methodName !== "toString" && methodName !== "equals" && methodName !== "hashCode") {
                            try {
                                var overloads = hookClass[methodName].overloads;
                                overloads.forEach(function(ovl) {
                                    ovl.implementation = function() {
                                        var argsStr = [];
                                        for (var i = 0; i < arguments.length; i++) {
                                            argsStr.push(arguments[i]);
                                        }
                                        var ret = this[methodName].apply(this, arguments);
                                        console.log("[🎯 TRACE] " + className + "." + methodName + "(" + argsStr.join(", ") + ") -> Return: " + ret);
                                        return ret;
                                    };
                                });
                            } catch(err) {}
                        }
                    });
                } catch(e) {}
            }
        },
        onComplete: function() {
            console.log("[+] Semua class aplikasi berhasil di-hook! Silakan berinteraksi dengan app!");
        }
    });
});
""",

    "02_Force_Return_True_Universal": """/*
 * [UNIVERSAL BYPASS] Paksa Semua Method Validasi / Check Return True
 * Otomatis mencari semua method check*, is*, verify*, validate* dan memaksa return true!
 */
Java.perform(function() {
    console.log("[*] === Universal Return True / Validation Bypass Active ===");

    Java.enumerateLoadedClasses({
        onMatch: function(className) {
            if (!className.startsWith("android.") && !className.startsWith("java.") &&
                !className.startsWith("androidx.") && !className.startsWith("com.google.")) {
                
                try {
                    var hookClass = Java.use(className);
                    var methods = hookClass.class.getDeclaredMethods();

                    methods.forEach(function(method) {
                        var mName = method.getName().toLowerCase();
                        if (mName.startsWith("check") || mName.startsWith("is") ||
                            mName.startsWith("verify") || mName.startsWith("validate") ||
                            mName.startsWith("equal") || mName.indexOf("flag") !== -1 ||
                            mName.indexOf("auth") !== -1 || mName.indexOf("license") !== -1) {
                            
                            try {
                                var actualName = method.getName();
                                var overloads = hookClass[actualName].overloads;
                                overloads.forEach(function(ovl) {
                                    ovl.implementation = function() {
                                        console.log("\\n[🚩 BINGO BYPASS] " + className + "." + actualName + "() dipanggil! -> DIPAKSA RETURN TRUE (1)");
                                        var retType = method.getReturnType().getName();
                                        if (retType === "boolean") return true;
                                        if (retType === "int") return 1;
                                        if (retType === "java.lang.Boolean") {
                                            var BooleanClass = Java.use("java.lang.Boolean");
                                            return BooleanClass.TRUE.value;
                                        }
                                        return this[actualName].apply(this, arguments);
                                    };
                                });
                            } catch(e) {}
                        }
                    });
                } catch(e) {}
            }
        },
        onComplete: function() {
            console.log("[+] Semua validator check/verify berhasil dipaksa return true!");
        }
    });
});
""",

    "03_Dynamic_Method_Invoker_And_Heap_Explorer": """/*
 * [DYNAMIC CALLER] Java.choose Instance Searcher & Method Invoker
 * Mencari instance aktif di RAM dan memanggil method (misal: get_flag, solve, dll)
 */
Java.perform(function() {
    console.log("[*] === Dynamic Method Invoker & Heap Explorer Active ===");

    // Ganti dengan nama package/class target jika spesifik, atau biarkan universal scan:
    var targetPatterns = ["MainActivity", "Checker", "Flag", "Challenge", "Secret", "Crypto"];

    Java.enumerateLoadedClasses({
        onMatch: function(className) {
            targetPatterns.forEach(function(pattern) {
                if (className.indexOf(pattern) !== -1 && !className.startsWith("android.") && !className.startsWith("java.")) {
                    try {
                        console.log("[+] Ditemukan target class: " + className);
                        var Cls = Java.use(className);

                        // 1. Coba panggil static method yang mencurigakan
                        var methods = Cls.class.getDeclaredMethods();
                        methods.forEach(function(m) {
                            var mName = m.getName();
                            if (mName.indexOf("flag") !== -1 || mName.indexOf("Flag") !== -1 ||
                                mName.indexOf("solve") !== -1 || mName.indexOf("get") !== -1) {
                                try {
                                    var res = Cls[mName]();
                                    console.log("[🚩 BINGO Static Call] " + className + "." + mName + "() -> " + res);
                                } catch(e) {}
                            }
                        });

                        // 2. Coba cari instance di Heap RAM
                        Java.choose(className, {
                            onMatch: function(instance) {
                                console.log("[+] Active Heap Instance: " + className);
                                methods.forEach(function(m) {
                                    var mName = m.getName();
                                    if (mName.indexOf("flag") !== -1 || mName.indexOf("Flag") !== -1 ||
                                        mName.indexOf("reveal") !== -1 || mName.indexOf("solve") !== -1) {
                                        try {
                                            var res = instance[mName]();
                                            console.log("[🚩 BINGO Instance Call] " + className + "." + mName + "() -> " + res);
                                        } catch(e) {}
                                    }
                                });
                            },
                            onComplete: function() {}
                        });
                    } catch(e) {}
                }
            });
        },
        onComplete: function() {
            console.log("[*] Scan heap & dynamic invoker selesai.");
        }
    });
});
""",

    "04_Native_JNI_And_Strcmp_Sniffer": """/*
 * [NATIVE SNIFFER] Intercept C/C++ strcmp, memcmp, & JNI GetStringUTFChars
 * Cocok untuk soal dengan file .so / Native C++
 */
console.log("[*] === Native strcmp & JNI Sniffer Active ===");

["strcmp", "strncmp", "memcmp"].forEach(function(funcName) {
    var addr = Module.findExportByName(null, funcName);
    if (addr) {
        Interceptor.attach(addr, {
            onEnter: function(args) {
                try {
                    var s1 = Memory.readUtf8String(args[0]);
                    var s2 = Memory.readUtf8String(args[1]);
                    if (s1 && s2 && s1.length > 2 && s2.length > 2 && s1 !== s2) {
                        if (s1.indexOf("flag") !== -1 || s2.indexOf("flag") !== -1 ||
                            s1.indexOf("FLAG") !== -1 || s2.indexOf("FLAG") !== -1 ||
                            s1.indexOf("HackToday") !== -1 || s2.indexOf("HackToday") !== -1 ||
                            s1.indexOf("{") !== -1 || s2.indexOf("{") !== -1) {
                            console.log("\\n[🚩 BINGO Native " + funcName + "]");
                            console.log("   Arg1 (Expected/Input): " + s1);
                            console.log("   Arg2 (Input/Expected): " + s2);
                        }
                    }
                } catch(e) {}
            }
        });
    }
});
""",

    "05_Dynamic_DEX_Memory_Dumper": """/*
 * [DEX DUMPER] Dump In-Memory Loaded DEX Files (Unpacker)
 * Mendump DEX dari RAM ke /data/local/tmp/dumped_*.dex
 */
Java.perform(function() {
    console.log("[*] === In-Memory DEX Dumper Active ===");

    try {
        var InMemoryDexClassLoader = Java.use("dalvik.system.InMemoryDexClassLoader");
        InMemoryDexClassLoader.$init.overload('java.nio.ByteBuffer', 'java.lang.ClassLoader').implementation = function(buffer, loader) {
            console.log("[+] Intercepted InMemoryDexClassLoader! Dumping DEX buffer...");
            try {
                var FileOutputStream = Java.use("java.io.FileOutputStream");
                var dumpPath = "/data/local/tmp/dumped_" + Date.now() + ".dex";
                var fos = FileOutputStream.$new(dumpPath);
                var channel = fos.getChannel();
                channel.write(buffer);
                fos.close();
                console.log("\\n[🚩 BINGO] DEX berhasil didump ke: " + dumpPath);
                console.log("   Tarik ke PC dengan: adb pull " + dumpPath + " .");
            } catch(err) {
                console.log("[-] Gagal menulis DEX: " + err);
            }
            return this.$init(buffer, loader);
        };
    } catch(e) {}
});
""",

    "06_Universal_SSL_And_Root_Bypass": """/*
 * [UNIVERSAL BYPASS] Root Detection + SSL Pinning All-in-One
 */
Java.perform(function() {
    console.log("[*] === Root & SSL Pinning Bypass Active ===");

    // 1. Root bypass
    try {
        var File = Java.use("java.io.File");
        File.exists.implementation = function() {
            var path = this.getAbsolutePath();
            if (path.indexOf("su") !== -1 || path.indexOf("magisk") !== -1 || path.indexOf("Superuser") !== -1) {
                return false;
            }
            return this.exists();
        };
    } catch(e) {}

    // 2. TrustManager SSL bypass
    try {
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
            console.log("[+] SSLContext.init intercepted! Permissive TrustManager diterapkan.");
            SSLContext_init.call(this, km, TrustManagers, sr);
        };
    } catch(e) {}
});
""",

    "07_Custom_Call_Template": """/*
 * [CUSTOM CALL TEMPLATE] Edit nama class & method sesuai temuan di JADX!
 */
Java.perform(function() {
    console.log("[*] Menjalankan custom hook...");

    // Contoh 1: Panggil Static Method dengan Argument
    // var Cls = Java.use("com.target.package.MainActivity");
    // Cls.get_flag(4919);

    // Contoh 2: Ubah Nilai Variable Static
    // var Checker = Java.use("com.target.package.Checker");
    // Checker.code.value = 512;

    // Contoh 3: Hook Return Value Method Spesifik
    // Cls.isFlagValid.implementation = function(input) {
    //     console.log("isFlagValid dipanggil dengan input: " + input);
    //     return true;
    // };
});
"""
}



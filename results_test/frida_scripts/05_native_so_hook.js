console.log("[*] Attaching to native exports in libnative.so...");
["strcmp", "strncmp", "memcmp"].forEach(function(funcName) {
    var addr = Module.findExportByName(null, funcName);
    if (addr) {
        Interceptor.attach(addr, {
            onEnter: function(args) {
                try {
                    var s1 = Memory.readUtf8String(args[0]);
                    var s2 = Memory.readUtf8String(args[1]);
                    if (s1 && s2 && (s1.includes("flag") || s2.includes("flag") || s1.includes("FLAG") || s2.includes("FLAG") || s1.includes("HackToday") || s2.includes("HackToday") || s1.includes("FRIDA") || s2.includes("FRIDA"))) {
                        console.log("[BINGO strcmp] Arg1: " + s1 + " | Arg2: " + s2);
                    }
                } catch(e) {}
            }
        });
    }
});
Java.perform(function() {
    console.log("[*] Modifying fields on class: com.hacktoday.challenge05.MainActivity");
    try {
        var target = Java.use("com.hacktoday.challenge05.MainActivity");
        var fields = ["code", "is_admin", "isAdmin", "flag", "unlocked", "score", "token", "pass"];
        for (var i = 0; i < fields.length; i++) {
            var f = fields[i];
            try {
                if (target[f] !== undefined) {
                    target[f].value = 512;
                    console.log("[+] Set static field " + f + " = 512");
                }
            } catch(e) {}
        }

        try {
            for (var k = 0; k < 256; k++) {
                target.increase();
            }
            console.log("[+] Called increase() 256 times");
        } catch(e) {}
    } catch(e) {
        console.log("[-] Error: " + e);
    }
});
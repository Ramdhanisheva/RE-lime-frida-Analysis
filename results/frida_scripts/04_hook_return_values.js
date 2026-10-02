Java.perform(function() {
    console.log("[*] Hooking validation methods in com.hacktoday.challenge05.MainActivity...");
    var target = Java.use("com.hacktoday.challenge05.MainActivity");
    var hook_candidates = ["check", "verify", "validate", "isFlagValid", "checkPassword", "cmpstr", "check_flag"];
    
    hook_candidates.forEach(function(mName) {
        try {
            if (target[mName]) {
                target[mName].implementation = function() {
                    console.log("[+] Method " + mName + " intercepted! Forcing return 1 / true.");
                    return 1;
                };
                console.log("[*] Successfully hooked " + mName);
            }
        } catch(e) {}
    });
});
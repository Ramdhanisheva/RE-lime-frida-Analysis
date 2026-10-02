Java.performNow(function() {
    console.log("[*] Searching for existing instances of com.hacktoday.challenge05.MainActivity...");
    Java.choose("com.hacktoday.challenge05.MainActivity", {
        onMatch: function(instance) {
            console.log("[+] Instance found: " + instance);
            var methods = ["get_flag", "flag", "get_flag", "getFlag", "check", "verify"];
            for (var i = 0; i < methods.length; i++) {
                var m = methods[i];
                try {
                    var res = instance[m]();
                    console.log("[+] Called " + m + "() -> " + res);
                } catch(e) {
                    try {
                        var res = instance[m](1337);
                        console.log("[+] Called " + m + "(1337) -> " + res);
                    } catch(e2) {}
                }
            }
        },
        onComplete: function() {
            console.log("[*] Java.choose scan completed.");
        }
    });
});
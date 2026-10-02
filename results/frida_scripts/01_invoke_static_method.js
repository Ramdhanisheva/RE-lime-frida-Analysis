Java.perform(function() {
    console.log("[*] Calling static method: get_flag");
    try {
        var act = Java.use("com.hacktoday.challenge05.MainActivity");
        try {
            var res = act.get_flag();
            console.log("[+] Result: " + res);
        } catch(e) {
            var candidates = [4919, 1337, 1234, 1, 0];
            for (var i = 0; i < candidates.length; i++) {
                try {
                    var res = act.get_flag(candidates[i]);
                    console.log("[+] Success with arg (" + candidates[i] + "): " + res);
                    break;
                } catch(err) {}
            }
        }
    } catch(e) {
        console.log("[-] Error: " + e);
    }
});
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
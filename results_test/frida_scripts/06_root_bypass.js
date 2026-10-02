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
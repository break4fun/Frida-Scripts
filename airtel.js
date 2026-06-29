/*
 * Airtel Africa Selfcare <(latest) — Clean Root / Dev / Anti-Frida Bypass
 * Package: com.airtel.africa.selfcare
 *
 */

Java.perform(function () {
    console.log("[*] bypass loading...");

    // 1. app root check: com.airtel.africa.selfcare.utils.x.l()
    try {
        Java.use("com.airtel.africa.selfcare.utils.x").l.overload().implementation = function () {
            return false;
        };
    } catch (e) { }

    // 2. rootbeer native
    try {
        Java.use("com.scottyab.rootbeer.RootBeerNative").checkForRoot.overload("[Ljava.lang.Object;").implementation = function () {
            return 0;
        };
    } catch (e) { }
    
    // 3. developer options (Settings.Global / Secure / System)
    var devKeys = ["development_settings_enabled", "adb_enabled", "debugger_connected", "debug_app", "development_settings_enabled"];
    ["android.provider.Settings$Global", "android.provider.Settings$Secure", "android.provider.Settings$System"].forEach(function (clsName) {
        try {
            var cls = Java.use(clsName);
            cls.getInt.overload("android.content.ContentResolver", "java.lang.String", "int").implementation = function (res, key, def) {
                if (devKeys.indexOf(key) !== -1) {
                    console.log("[+] " + clsName + ".getInt(" + key + ") -> 0");
                    return 0;
                }
                return this.getInt(res, key, def);
            };
        } catch (e) { }
    });

    // 4. shared prefs
    try {
        Java.use("android.content.SharedPreferences").getBoolean.overload("java.lang.String", "boolean").implementation = function (key, def) {
            if (key === "usb_debugging_consent_status") return false;
            return this.getBoolean(key, def);
        };
    } catch (e) { }

    // 5. anti-debug
    try {
        var Debug = Java.use("android.os.Debug");
        Debug.isDebuggerConnected.implementation = function () { return false; };
        Debug.waitingForDebugger.implementation = function () { return false; };
    } catch (e) { }

    // 6. anti-frida: Runtime.exec("ps") -> return "id"
    try {
        var Runtime = Java.use("java.lang.Runtime");
        Runtime.exec.overload("java.lang.String").implementation = function (cmd) {
            if (cmd === "ps" || cmd.startsWith("ps ")) {
                console.log("[+] Runtime.exec('ps') neutered");
                return this.exec("id");
            }
            return this.exec(cmd);
        };
        Runtime.exec.overload("[Ljava.lang.String;").implementation = function (cmdArray) {
            if (cmdArray.length > 0 && cmdArray[0].value === "ps") {
                console.log("[+] Runtime.exec(['ps',...]) neutered");
                return this.exec(Java.array("java.lang.String", ["id"]));
            }
            return this.exec(cmdArray);
        };
    } catch (e) { }

    // 7. anti-frida: ProcessBuilder ps -> id
    try {
        var ProcessBuilder = Java.use("java.lang.ProcessBuilder");
        ProcessBuilder.start.implementation = function () {
            var cmdList = this.command();
            if (cmdList) {
                var cmdStr = cmdList.toString();
                if (cmdStr.indexOf("ps") !== -1) {
                    console.log("[+] ProcessBuilder ps neutered");
                    var Arrays = Java.use("java.util.Arrays");
                    this.command(Arrays.asList(Java.array("java.lang.String", ["id"])));
                }
            }
            return this.start();
        };
    } catch (e) { }

    // 8. anti-frida: Socket connect to localhost:27042
    try {
        var Socket = Java.use("java.net.Socket");
        var InetSocketAddress = Java.use("java.net.InetSocketAddress");
        Socket.connect.overload("java.net.SocketAddress", "int").implementation = function (addr, timeout) {
            var isa = Java.cast(addr, InetSocketAddress);
            var port = isa.getPort();
            var host = "";
            try { host = isa.getHostString(); } catch (e1) { host = isa.getHostName(); }
            if ((host === "127.0.0.1" || host === "localhost") && port === 27042) {
                console.log("[+] Socket.connect(" + host + ":" + port + ") blocked");
                throw Java.use("java.io.IOException").$new("Connection refused");
            }
            return this.connect(addr, timeout);
        };
    } catch (e) { }

    // 9. emulator bypass: intercept String.contains() checks
    //     Build.MANUFACTURER/MODEL/PRODUCT checks call String.contains()
    // We only block specific emulator identifiers without spoofing Build.
    try {
        var StringCls = Java.use("java.lang.String");
        var emuIndicators = ["Genymotion", "google_sdk", "Emulator", "sdk_gphone", "sdk_gphone_x86_64", 
                            "sdk_gphone64_x86_64", "Android SDK built for x86", "nox", "Bluestacks", 
                            "generic", "unknown", "goldfish", "ranchu", "vbox86"];
        StringCls.contains.overload("java.lang.CharSequence").implementation = function (seq) {
            var s = seq.toString();
            for (var i = 0; i < emuIndicators.length; i++) {
                if (s === emuIndicators[i]) {
                    console.log("[+] String.contains('" + s + "') -> false");
                    return false;
                }
            }
            return this.contains(seq);
        };
    } catch (e) { }

    // 10.FALLBACK: catch db.a.intercept() security kill
    // If ALL ELSE fails and db.a still throws, catch it and proceed.
    // NOTE: this skips auth-token header injection, so API calls may fail,
    // but at least the app won't crash and you can debug further.
    try {
        var DbA = Java.use("db.a");
        var origIntercept = DbA.intercept.bind(DbA);
        DbA.intercept.implementation = function (chain) {
            try {
                // Try the original interceptor (auth tokens + checks)
                return this.intercept(chain);
            } catch (ex) {
                var msg = "";
                try { msg = ex.getMessage(); } catch (e2) { }
                if (msg.indexOf("Security violation") !== -1 || msg.indexOf("Frida") !== -1 || msg.indexOf("Debugger") !== -1) {
                    console.log("[+] db.a security kill caught, emergency bypass");
                    return chain.proceed(chain.request());
                }
                throw ex;
            }
        };
    } catch (e) { }

    // 11. certificate pinning bypass — OkHttp3 (obfuscated Pk.*)
    //
    // The app hard-codes ~15 sha256 pins in NetworkConstants and builds
    // CertificatePinner via the obfuscated OkHttp3 builder (Pk.i$a).
    // Primary hook: neuter the builder so pins are never added.
    // Fallback hook: if check() is somehow reached, make it a no-op.
    //
    try {
        // Pk.i$a  == okhttp3.CertificatePinner.Builder
        // a(String,[String]) == add(String pattern, String... pins)
        var PinnerBuilder = Java.use("Pk.i$a");
        PinnerBuilder.a.overload("java.lang.String", "[Ljava.lang.String;").implementation = function (pattern, pins) {
            console.log("[+] CertificatePinner.Builder.add(" + pattern + ") -> neutered");
            return; // drop the pin
        };
    } catch (e) {
        console.log("[!] CertificatePinner.Builder hook failed: " + e);
    }

    try {
        // Pk.i  == okhttp3.CertificatePinner
        // a(String,Function0) == internal check(hostname, cleanedPeerCertificatesFn)
        var CertPinner = Java.use("Pk.i");
        CertPinner.a.overload("java.lang.String", "kotlin.jvm.functions.Function0").implementation = function (hostname, fn) {
            console.log("[+] CertificatePinner.check(" + hostname + ") -> bypassed");
            return; // void
        };
    } catch (e) {
        console.log("[!] CertificatePinner.check hook failed: " + e);
    }

    // 12. generic trust manager bypass (covers non-OkHttp SSL paths)
    try {
        var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
        var SSLContext = Java.use("javax.net.ssl.SSLContext");
        var TrustManager = Java.registerClass({
            name: "com.airtel.africa.selfcare.bypass.TrustManager",
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: function (chain, authType) {},
                checkServerTrusted: function (chain, authType) {},
                getAcceptedIssuers: function () { return []; }
            }
        });
        SSLContext.init.overload(
            "[Ljavax/net/ssl/KeyManager;",
            "[Ljavax/net/ssl/TrustManager;",
            "java.security.SecureRandom"
        ).implementation = function (km, tm, random) {
            console.log("[+] SSLContext.init() hooked");
            this.init(km, [TrustManager.$new()], random);
        };
    } catch (e) { }

    // 13. hostname verifier bypass (OkHttp internal OkHostnameVerifier)
    try {
        // dl.d == okhttp3.internal.tls.OkHostnameVerifier
        Java.use("dl.d").verify.overload("java.lang.String", "javax.net.ssl.SSLSession").implementation = function (host, session) {
            console.log("[+] OkHostnameVerifier.verify(" + host + ") -> true");
            return true;
        };
    } catch (e) { }

    // 14. webview ssl bypass (proceed on all ssl errors)
    try {
        var WebViewClient = Java.use("android.webkit.WebViewClient");
        WebViewClient.onReceivedSslError.overload(
            "android.webkit.WebView",
            "android.webkit.SslErrorHandler",
            "android.net.http.SslError"
        ).implementation = function (view, handler, error) {
            console.log("[+] WebViewClient.onReceivedSslError -> proceed");
            handler.proceed();
        };
    } catch (e) { }
    

    console.log("[*] Airtel bypass loaded!");
});

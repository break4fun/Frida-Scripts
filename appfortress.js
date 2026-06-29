/*
 * AppFortress + VPN/Proxy/Root bypass
 * Tested on the latest versions of appfortress. 
 */

Java.perform(function () {
    console.log("[*] bypass hooks loading...");

    // vpn bypass
    try {
        var NetworkCapabilities = Java.use("android.net.NetworkCapabilities");
        NetworkCapabilities.hasTransport.overload('int').implementation = function (type) {
            // TRANSPORT_VPN == 4
            if (type === 4) {
                // console.log("[*] NetworkCapabilities.hasTransport(VPN) -> false");
                return false;
            }
            return this.hasTransport(type);
        };
        console.log("[+] NetworkCapabilities.hasTransport() hooked");
    } catch (e) {
        console.log("[-] NetworkCapabilities hook failed: " + e);
    }

    try {
        var NetworkInterface = Java.use("java.net.NetworkInterface");
        NetworkInterface.getName.implementation = function () {
            var name = this.getName();
            if (name !== null && name.match(/tun|tap|ppp|l2tp|ipsec/i)) {
                // console.log("[*] Spoofing interface name: " + name + " -> eth0");
                return "eth0";
            }
            return name;
        };
        console.log("[+] NetworkInterface.getName() hooked");
    } catch (e) {
        console.log("[-] NetworkInterface hook failed: " + e);
    }

    // (com.app.fortress) - main Flutter security gate
    try {
        var Fortress = Java.use("com.app.fortress.AppFortressPlugin");

        // Top-level booleans that Flutter calls via MethodChannel 
        Fortress.isHookingDetected.implementation = function () {
            console.log("[*] AppFortress.isHookingDetected() -> false");
            return false;
        };

        Fortress.isVpnActive.implementation = function () {
            console.log("[*] AppFortress.isVpnActive() -> false");
            return false;
        };

        Fortress.isRooted.implementation = function () {
            console.log("[*] AppFortress.isRooted() -> false");
            return false;
        };

        Fortress.isDebuggerAttached.implementation = function () {
            console.log("[*] AppFortress.isDebuggerAttached() -> false");
            return false;
        };

        Fortress.isEmulator.implementation = function () {
            console.log("[*] AppFortress.isEmulator() -> false");
            return false;
        };

        Fortress.isProxyEnabled.implementation = function () {
            console.log("[*] AppFortress.isProxyEnabled() -> false");
            return false;
        };

        Fortress.isProxyOrMitmToolsInstalled.implementation = function () {
            // console.log("[*] AppFortress.isProxyOrMitmToolsInstalled() -> false");
            return false;
        };

        Fortress.isFromTrustedInstallSource.implementation = function () {
            console.log("[*] AppFortress.isFromTrustedInstallSource() -> true");
            return true;
        };

        
        Fortress.checkFrida.implementation = function () { return false; };
        Fortress.checkXposed.implementation = function () { return false; };
        Fortress.checkSubstrate.implementation = function () { return false; };
        Fortress.checkMagiskHide.implementation = function () { return false; };

        Fortress.checkSuBinary.implementation = function () { return false; };
        Fortress.checkRootApps.implementation = function () { return false; };
        Fortress.checkMagisk.implementation = function () { return false; };
        Fortress.checkKernelSU.implementation = function () { return false; };
        Fortress.checkTestKeys.implementation = function () { return false; };
        Fortress.checkRootCloaking.implementation = function () { return false; };

        Fortress.checkEmulatorHardwareFiles.implementation = function () { return false; };
        Fortress.checkQemuProperties.implementation = function () { return false; };

        Fortress.isDebuggable.implementation = function () { return false; };
        Fortress.isBeingTraced.implementation = function () { return false; };
        Fortress.checkJdwpThread.implementation = function () { return false; };

        Fortress.checkProxyAppsInstalled.implementation = function () { return false; };
        Fortress.checkMitmToolsInstalled.implementation = function () { return false; };
        Fortress.checkAndroidProxyApi.implementation = function () { return false; };
        Fortress.checkJavaSystemProxy.implementation = function () { return false; };
        Fortress.checkLinkPropertiesProxy.implementation = function () { return false; };
        Fortress.checkSettingsProxy.implementation = function () { return false; };
        Fortress.checkProxySelectorApi.implementation = function () { return false; };
        Fortress.checkSystemPropertiesProxy.implementation = function () { return false; };

        Fortress.checkBusyBox.implementation = function () { return false; };
        Fortress.checkRWSystem.implementation = function () { return false; };
        Fortress.checkMapsForStrings.implementation = function (list) { return false; };
        Fortress.checkPort.implementation = function (port) { return false; };

        console.log("[+] AppFortressPlugin fully hooked");
    } catch (e) {
        console.log("[-] AppFortressPlugin hook failed: " + e);
    }

    // vpn detectors
    try {
        var ConnMon = Java.use("com.example.connectivity_monitor.ConnectivityMonitorPlugin");
        ConnMon.isVpnActive.implementation = function () {
            console.log("[*] ConnectivityMonitor.isVpnActive() -> false");
            return false;
        };
        console.log("[+] ConnectivityMonitorPlugin hooked");
    } catch (e) {
        console.log("[-] ConnectivityMonitorPlugin hook failed: " + e);
    }

    try {
        var DeviceIntegrity = Java.use("com.rayole.offerpro.sdk.DeviceIntegrity");
        DeviceIntegrity.isVpnActive.overload('android.content.Context').implementation = function (ctx) {
            console.log("[*] DeviceIntegrity.isVpnActive() -> false");
            return false;
        };
        console.log("[+] DeviceIntegrity hooked");
    } catch (e) {
        console.log("[-] DeviceIntegrity hook failed: " + e);
    }

    // If the native library is present, force the JNI anti-tamper exports to 0.
    try {
        var module = Process.findModuleByName("libapp_fortress_native.so");
        if (module) {
            var targets = ["nativeIsHooked", "nativeIsRooted", "nativeIsDebuggerAttached", "nativeIsEmulator"];
            module.enumerateExports().forEach(function (exp) {
                targets.forEach(function (t) {
                    if (exp.name.indexOf(t) !== -1) {
                        Interceptor.attach(exp.address, {
                            onLeave: function (retval) {
                                retval.replace(0);
                            }
                        });
                        console.log("[+] Native hook: " + exp.name);
                    }
                });
            });
        }
    } catch (e) {
        console.log("[-] Native hook pass failed (non-fatal): " + e);
    }

    // Hide common Frida artifact strings if anything ever reads /proc/self/maps
    try {
        var BufferedReader = Java.use("java.io.BufferedReader");
        var File = Java.use("java.io.File");

        // Lie about frida-server files on disk
        var fileExists = File.exists.implementation;
        File.exists.implementation = function () {
            var path = this.getAbsolutePath();
            if (path && (
                path.indexOf("frida-server") !== -1 ||
                path.indexOf("re.frida.server") !== -1 ||
                path.indexOf("/data/local/tmp/frida") !== -1 ||
                path.indexOf("/sbin/su") !== -1 ||
                path.indexOf("/system/bin/su") !== -1
            )) {
                return false;
            }
            return this.exists();
        };
    } catch (e) {
        console.log("[-] File.exists hook failed: " + e);
    }

    console.log("[*] All hooks installed.");
});

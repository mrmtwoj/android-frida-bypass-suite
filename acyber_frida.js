'use strict';

var seenAES = {};
var seenSSL = {};

function bytesToHex(arr) {
    var str = '';
    for (var i = 0; i < arr.length; i++) {
        var j = arr[i] < 0 ? arr[i] + 256 : arr[i];
        if (j < 16) str += '0';
        str += j.toString(16);
    }
    return str;
}

var b64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
function bytesToBase64(e) {
    var r = '', a = 0, c = e.length, h, o, t;
    while (a < c) {
        h = 255 & e[a++];
        if (a == c) { r += b64.charAt(h >> 2) + b64.charAt((3 & h) << 4) + '=='; break; }
        o = e[a++];
        if (a == c) { r += b64.charAt(h >> 2) + b64.charAt(((3 & h) << 4) | ((240 & o) >> 4)) + b64.charAt((15 & o) << 2) + '='; break; }
        t = e[a++];
        r += b64.charAt(h >> 2) + b64.charAt(((3 & h) << 4) | ((240 & o) >> 4)) + b64.charAt(((15 & o) << 2) | ((192 & t) >> 6)) + b64.charAt(63 & t);
    }
    return r;
}

function logRoot(api, detail) {
    console.log('[ROOT] ' + api + (detail ? ' -> ' + detail : ''));
}

function logSSL(fn) {
    if (seenSSL[fn]) return;
    seenSSL[fn] = true;
    console.log('[SSL] bypassed: ' + fn);
}

function logAES(label, value) {
    var key = label + '|' + value;
    if (seenAES[key]) return;
    seenAES[key] = true;
    console.log('[AES] ' + label + ': ' + value);
}

setTimeout(function () {
    Java.perform(function () {

        console.log('===== [1] ROOT DETECTION =====');
        console.log('[ROOT] API structure:');
        console.log('  ApplicationPackageManager.getPackageInfo(String, int)');
        console.log('  java.io.File.exists()');
        console.log('  java.lang.Runtime.exec(String)');
        console.log('  java.lang.Runtime.exec(String[])');
        console.log('  java.lang.Runtime.exec(String, String[])');
        console.log('  java.lang.Runtime.exec(String[], String[])');
        console.log('  java.lang.Runtime.exec(String[], String[], File)');
        console.log('  java.lang.Runtime.exec(String, String[], File)');
        console.log('  java.lang.String.contains(String)');
        console.log('  android.os.SystemProperties.get(String)');
        console.log('  libc.so!fopen');
        console.log('  libc.so!system');
        console.log('  java.io.BufferedReader.readLine()');
        console.log('  java.lang.ProcessBuilder.start()');
        console.log('[ROOT] ----------------------------------------');

        var RootPackages = [
            'com.noshufou.android.su', 'com.noshufou.android.su.elite', 'eu.chainfire.supersu',
            'com.koushikdutta.superuser', 'com.thirdparty.superuser', 'com.yellowes.su',
            'com.koushikdutta.rommanager', 'com.koushikdutta.rommanager.license',
            'com.dimonvideo.luckypatcher', 'com.chelpus.lackypatch',
            'com.ramdroid.appquarantine', 'com.ramdroid.appquarantinepro',
            'com.devadvance.rootcloak', 'com.devadvance.rootcloakplus',
            'de.robv.android.xposed.installer', 'com.saurik.substrate',
            'com.zachspong.temprootremovejb', 'com.amphoras.hidemyroot',
            'com.amphoras.hidemyrootadfree', 'com.formyhm.hiderootPremium',
            'com.formyhm.hideroot', 'me.phh.superuser', 'eu.chainfire.supersu.pro',
            'com.kingouser.com'
        ];
        var RootBinaries = ['su', 'busybox', 'supersu', 'Superuser.apk', 'KingoUser.apk', 'SuperSu.apk'];
        var RootProperties = {
            'ro.build.selinux': '1', 'ro.debuggable': '0',
            'service.adb.root': '0', 'ro.secure': '1'
        };
        var RootPropertiesKeys = Object.keys(RootProperties);

        try {
            var PM = Java.use('android.app.ApplicationPackageManager');
            PM.getPackageInfo.overload('java.lang.String', 'int').implementation = function (pname, flags) {
                if (RootPackages.indexOf(pname) > -1) {
                    logRoot('ApplicationPackageManager.getPackageInfo(String, int)', pname);
                    pname = 'set.package.name.to.a.fake.one.so.we.can.bypass.it';
                }
                return this.getPackageInfo.call(this, pname, flags);
            };
        } catch (e) { console.log('[ROOT] getPackageInfo fail: ' + e.message); }

        try {
            var NF = Java.use('java.io.File');
            NF.exists.implementation = function () {
                var name = NF.getName.call(this);
                if (RootBinaries.indexOf(name) > -1) { logRoot('java.io.File.exists()', name); return false; }
                return this.exists.call(this);
            };
        } catch (e) { console.log('[ROOT] File.exists fail: ' + e.message); }

        try {
            var RT = Java.use('java.lang.Runtime');
            var e0 = RT.exec.overload('[Ljava.lang.String;');
            var e1 = RT.exec.overload('java.lang.String');
            var e2 = RT.exec.overload('java.lang.String', '[Ljava.lang.String;');
            var e3 = RT.exec.overload('[Ljava.lang.String;', '[Ljava.lang.String;');
            var e4 = RT.exec.overload('[Ljava.lang.String;', '[Ljava.lang.String;', 'java.io.File');
            var e5 = RT.exec.overload('java.lang.String', '[Ljava.lang.String;', 'java.io.File');
            var block = function (c) {
                return c.indexOf('getprop') != -1 || c == 'mount' || c.indexOf('build.prop') != -1 || c == 'id' || c == 'sh' || c == 'su';
            };
            e5.implementation = function (cmd, env, dir) {
                if (block(cmd)) { logRoot('Runtime.exec(String, String[], File)', cmd); return e1.call(this, 'grep'); }
                return e5.call(this, cmd, env, dir);
            };
            e4.implementation = function (arr, env, file) {
                for (var i = 0; i < arr.length; i++) if (block(arr[i])) { logRoot('Runtime.exec(String[], String[], File)', arr[i]); return e1.call(this, 'grep'); }
                return e4.call(this, arr, env, file);
            };
            e3.implementation = function (arr, envp) {
                for (var i = 0; i < arr.length; i++) if (block(arr[i])) { logRoot('Runtime.exec(String[], String[])', arr[i]); return e1.call(this, 'grep'); }
                return e3.call(this, arr, envp);
            };
            e2.implementation = function (cmd, env) {
                if (block(cmd)) { logRoot('Runtime.exec(String, String[])', cmd); return e1.call(this, 'grep'); }
                return e2.call(this, cmd, env);
            };
            e0.implementation = function (arr) {
                for (var i = 0; i < arr.length; i++) if (block(arr[i])) { logRoot('Runtime.exec(String[])', arr[i]); return e1.call(this, 'grep'); }
                return e0.call(this, arr);
            };
            e1.implementation = function (cmd) {
                if (block(cmd)) { logRoot('Runtime.exec(String)', cmd); return e1.call(this, 'grep'); }
                return e1.call(this, cmd);
            };
        } catch (e) { console.log('[ROOT] Runtime.exec fail: ' + e.message); }

        try {
            var S = Java.use('java.lang.String');
            S.contains.implementation = function (n) {
                if (n == 'test-keys') { logRoot('String.contains(String)', 'test-keys'); return false; }
                return this.contains.call(this, n);
            };
        } catch (e) { console.log('[ROOT] String.contains fail: ' + e.message); }

        try {
            var SP = Java.use('android.os.SystemProperties');
            var g = SP.get.overload('java.lang.String');
            g.implementation = function (n) {
                if (RootPropertiesKeys.indexOf(n) != -1) { logRoot('SystemProperties.get(String)', n); return RootProperties[n]; }
                return this.get.call(this, n);
            };
        } catch (e) { console.log('[ROOT] SystemProperties.get fail: ' + e.message); }

        try {
            var fopen = Module.findExportByName('libc.so', 'fopen');
            if (fopen) Interceptor.attach(fopen, {
                onEnter: function (a) {
                    var p = Memory.readCString(a[0]).split('/');
                    var n = p[p.length - 1];
                    if (RootBinaries.indexOf(n) > -1) { logRoot('libc.so!fopen', n); Memory.writeUtf8String(a[0], '/notexists'); }
                }
            });
        } catch (e) { console.log('[ROOT] fopen fail: ' + e.message); }

        try {
            var sysfn = Module.findExportByName('libc.so', 'system');
            if (sysfn) Interceptor.attach(sysfn, {
                onEnter: function (a) {
                    var c = Memory.readCString(a[0]);
                    if (c.indexOf('getprop') != -1 || c == 'mount' || c.indexOf('build.prop') != -1 || c == 'id' || c == 'su') {
                        logRoot('libc.so!system', c);
                        Memory.writeUtf8String(a[0], 'grep');
                    }
                }
            });
        } catch (e) { console.log('[ROOT] system fail: ' + e.message); }

        try {
            var BR = Java.use('java.io.BufferedReader');
            BR.readLine.overload().implementation = function () {
                var t = this.readLine.call(this);
                if (t !== null && t.indexOf('ro.build.tags=test-keys') > -1) {
                    logRoot('BufferedReader.readLine()', 'test-keys');
                    t = t.replace('ro.build.tags=test-keys', 'ro.build.tags=release-keys');
                }
                return t;
            };
        } catch (e) { console.log('[ROOT] BufferedReader fail: ' + e.message); }

        try {
            var PB = Java.use('java.lang.ProcessBuilder');
            PB.start.implementation = function () {
                var c = this.command.call(this);
                for (var i = 0; i < c.size(); i++) {
                    var t = c.get(i).toString();
                    if (t.indexOf('getprop') != -1 || t.indexOf('mount') != -1 || t.indexOf('build.prop') != -1 || t.indexOf('id') != -1 || t == 'su') {
                        logRoot('ProcessBuilder.start()', t);
                        this.command.call(this, ['grep']);
                        break;
                    }
                }
                return this.start.call(this);
            };
        } catch (e) { console.log('[ROOT] ProcessBuilder fail: ' + e.message); }

        console.log('===== [2] AES TOKEN HOOK =====');

        try {
            var SKS = Java.use('javax.crypto.spec.SecretKeySpec');
            SKS.$init.overload('[B', 'java.lang.String').implementation = function (k, alg) {
                var r = this.$init(k, alg);
                logAES('SecretKeySpec', 'hex=' + bytesToHex(k) + ' b64=' + bytesToBase64(k));
                return r;
            };
        } catch (e) { console.log('[AES] SecretKeySpec fail: ' + e.message); }

        try {
            var IVS = Java.use('javax.crypto.spec.IvParameterSpec');
            IVS.$init.overload('[B').implementation = function (iv) {
                var r = this.$init(iv);
                logAES('IvParameterSpec', 'hex=' + bytesToHex(iv) + ' b64=' + bytesToBase64(iv));
                return r;
            };
        } catch (e) { console.log('[AES] IvParameterSpec fail: ' + e.message); }

        try {
            var C = Java.use('javax.crypto.Cipher');
            C.getInstance.overload('java.lang.String').implementation = function (t) {
                logAES('Cipher.getInstance', t);
                return this.getInstance(t);
            };
            C.init.overload('int', 'java.security.Key', 'java.security.spec.AlgorithmParameterSpec').implementation = function (mode, key, iv) {
                var r = this.init(mode, key, iv);
                logAES('Cipher.init mode', String(mode));
                return r;
            };
            C.doFinal.overload('[B').implementation = function (x) {
                var r = this.doFinal.overload('[B').call(this, x);
                try { logAES('doFinal output', 'b64=' + bytesToBase64(r)); } catch (e) {}
                logAES('doFinal input', 'b64=' + bytesToBase64(x));
                return r;
            };
        } catch (e) { console.log('[AES] Cipher fail: ' + e.message); }

        console.log('===== [3] SSL SPOOFING =====');

        try {
            var X509 = Java.use('javax.net.ssl.X509TrustManager');
            var CTX = Java.use('javax.net.ssl.SSLContext');
            var TM = Java.registerClass({
                name: 'dev.bypass.TM',
                implements: [X509],
                methods: {
                    checkClientTrusted: function () {},
                    checkServerTrusted: function () {},
                    getAcceptedIssuers: function () { return []; }
                }
            });
            var TMs = [TM.$new()];
            var ctxInit = CTX.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom');
            ctxInit.implementation = function (km, tm, sr) {
                logSSL('javax.net.ssl.SSLContext.init');
                return ctxInit.call(this, km, TMs, sr);
            };
        } catch (e) {}

        try {
            var H = Java.use('javax.net.ssl.HttpsURLConnection');
            H.setDefaultHostnameVerifier.implementation = function () { logSSL('HttpsURLConnection.setDefaultHostnameVerifier'); };
            H.setSSLSocketFactory.implementation = function () { logSSL('HttpsURLConnection.setSSLSocketFactory'); };
            H.setHostnameVerifier.implementation = function () { logSSL('HttpsURLConnection.setHostnameVerifier'); };
        } catch (e) {}

        try {
            var TMI = Java.use('com.android.org.conscrypt.TrustManagerImpl');
            TMI.verifyChain.implementation = function (uc) {
                logSSL('com.android.org.conscrypt.TrustManagerImpl.verifyChain');
                return uc;
            };
        } catch (e) {}

        try {
            var TMI2 = Java.use('com.android.org.conscrypt.TrustManagerImpl');
            TMI2.checkTrustedRecursive.implementation = function () {
                logSSL('com.android.org.conscrypt.TrustManagerImpl.checkTrustedRecursive');
                return Java.use('java.util.ArrayList').$new();
            };
        } catch (e) {}

        try {
            var OSS = Java.use('com.android.org.conscrypt.OpenSSLSocketImpl');
            OSS.verifyCertificateChain.implementation = function () {
                logSSL('com.android.org.conscrypt.OpenSSLSocketImpl.verifyCertificateChain');
            };
        } catch (e) {}

        try {
            var CP = Java.use('okhttp3.CertificatePinner');
            CP.check.overload('java.lang.String', 'java.util.List').implementation = function () {
                logSSL('okhttp3.CertificatePinner.check(String, List)');
            };
        } catch (e) {}

        try {
            var CP2 = Java.use('okhttp3.CertificatePinner');
            CP2.check.overload('java.lang.String', '[Ljava.security.cert.Certificate;').implementation = function () {
                logSSL('okhttp3.CertificatePinner.check(String, Certificate[])');
            };
        } catch (e) {}

        try {
            var CP3 = Java.use('okhttp3.CertificatePinner');
            CP3['check$okhttp'].implementation = function () {
                logSSL('okhttp3.CertificatePinner.check$okhttp');
            };
        } catch (e) {}

        try {
            var TK = Java.use('com.datatheorem.android.trustkit.pinning.OkHostnameVerifier');
            TK.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation = function () { logSSL('Trustkit.OkHostnameVerifier.verify(SSLSession)'); return true; };
        } catch (e) {}

        try {
            var TK2 = Java.use('com.datatheorem.android.trustkit.pinning.OkHostnameVerifier');
            TK2.verify.overload('java.lang.String', 'java.security.cert.X509Certificate').implementation = function () { logSSL('Trustkit.OkHostnameVerifier.verify(X509Certificate)'); return true; };
        } catch (e) {}

        try {
            var TKP = Java.use('com.datatheorem.android.trustkit.pinning.PinningTrustManager');
            TKP.checkServerTrusted.implementation = function () { logSSL('Trustkit.PinningTrustManager.checkServerTrusted'); };
        } catch (e) {}

        try {
            var APP = Java.use('appcelerator.https.PinningTrustManager');
            APP.checkServerTrusted.implementation = function () { logSSL('appcelerator.https.PinningTrustManager.checkServerTrusted'); };
        } catch (e) {}

        try {
            var WVC = Java.use('android.webkit.WebViewClient');
            WVC.onReceivedSslError.implementation = function (wv, h, err) {
                logSSL('android.webkit.WebViewClient.onReceivedSslError');
                h.proceed();
            };
        } catch (e) {}

        console.log('===== [READY] =====');
    });
}, 0);

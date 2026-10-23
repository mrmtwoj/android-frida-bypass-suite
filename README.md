# 🛡️ android-frida-bypass-suite

> **Frida toolkit for Android penetration testing — Root bypass + SSL pinning bypass + AES key hook, plus a filterable companion forward proxy.**

<p align="center">
  <img src="https://img.shields.io/badge/Frida-✔-red?style=flat-square&logo=frida" />
  <img src="https://img.shields.io/badge/Platform-Android-3DDC84?style=flat-square&logo=android" />
  <img src="https://img.shields.io/badge/Python-3.x-3776AB?style=flat-square&logo=python" />
  <img src="https://img.shields.io/badge/Burp_Suite-Ready-orange?style=flat-square" />
  <img src="https://img.shields.io/badge/License-MIT-blue?style=flat-square" />
  <img src="https://img.shields.io/badge/Author-mrmtwoj-blueviolet?style=flat-square" />
  <img src="https://img.shields.io/badge/Website-acyber.ir-purple?style=flat-square" />
</p>

<p align="center">
  <a href="https://acyber.ir">
    <img src="https://img.shields.io/badge/🌐_acyber.ir-Visit-9b59b6?style=for-the-badge" />
  </a>
  <a href="https://github.com/mrmtwoj">
    <img src="https://img.shields.io/badge/👤_mrmtwoj-GitHub-181717?style=for-the-badge&logo=github" />
  </a>
</p>

---


## 📌 About

This repository provides a comprehensive **Frida script** for Android application security testing, along with a lightweight **Python forward proxy**. Together they deliver three bypass modules plus a traffic control layer:

| File | Purpose |
|------|---------|
| 🥷 **`acyber_frida.js`** → Root Detection Bypass | Bypass root checks at Java and Native (libc) level |
| 🔐 **`acyber_frida.js`** → AES Token Hook | Capture AES keys, IVs, and `Cipher` input/output |
| 🌐 **`acyber_frida.js`** → SSL Pinning Bypass | Bypass OkHttp, TrustKit, Conscrypt, and WebView pinning |
| 🛰️ **`acyber_server_proxy.py`** → Companion Proxy | Forward proxy with protocol/domain filters + live logging |

Output is designed to work smoothly alongside **Burp Suite**, **adb reverse**, and the **Companion Proxy**, exposing cryptographic material while traffic is being intercepted.

---

## ✨ Features

- ✅ Root bypass at **14 distinct points** (Java + Native)
- ✅ Full AES lifecycle hooks (`SecretKeySpec`, `IvParameterSpec`, `Cipher`)
- ✅ Covers **10+ SSL pinning libraries** (OkHttp, TrustKit, Conscrypt, WebView, Appcelerator)
- ✅ Deduplicated logs via `seenAES` / `seenSSL`
- ✅ HEX and Base64 output for keys
- ✅ Python forward proxy with **protocol filter**, **domain allow/block list**, and **live logging**
- ✅ Compatible with **Android 5 → 14**
- ✅ No app modification required — Frida injection only

---

## ⚙️ Requirements

| Tool | Recommended | Install |
|------|-------------|---------|
| `frida` + `frida-tools` | ≥ 16.x | `pip install frida-tools` |
| `frida-server` (arm64) | Same version as frida | [Releases](https://github.com/frida/frida/releases) |
| `adb` | ≥ 1.0.41 | Android SDK Platform Tools |
| **Python** | ≥ 3.8 | To run `acyber_server_proxy.py` |
| **Burp Suite** | Community or Pro | [portswigger.net](https://portswigger.net/burp) |
| Rooted device | — | Or emulator with `frida-server` |

---

## 🚀 Step-by-Step Setup

### 1️⃣ Start frida-server on the device

```bash
adb push frida-server /data/local/tmp/
adb shell "chmod 755 /data/local/tmp/frida-server"
adb shell "/data/local/tmp/frida-server &"
```

### 2️⃣ Set a global HTTP proxy

```bash
adb shell settings put global http_proxy 192.168.1.10:8080
```

> 🔁 To remove: `adb shell settings put global http_proxy :0`

### 3️⃣ Reverse tunnel for Frida

```bash
adb reverse tcp:3333 tcp:9090
```

### 4️⃣ Prepare Burp Suite

1. **Proxy → Options → Proxy Listeners** → listener on `0.0.0.0:8080`
2. On device: browser → `http://burp` → download CA
3. **Settings → Security → Install from storage → CA Certificate**
4. For Android 7+ apps with `targetSdk ≥ 24`, either use **this script's SSL module** or push the CA into `/system/etc/security/cacerts`

### 5️⃣ Inject the script into the target app

Three common ways to inject `acyber_frida.js`:

**a) Spawn by package name (most common):**
```bash
frida -U -f com.target.app -l acyber_frida.js --no-pause
```

**b) Attach to a running process (`-p`):**
```bash
# Find the PID first
frida-ps -U | grep com.target.app

# Attach by PID or process name
frida -U -l acyber_frida.js -p 12345
# or
frida -U -l acyber_frida.js -p com.target.app
```

**c) Spawn without pause (inject at boot):**
```bash
frida -U -f com.target.app -l acyber_frida.js
```

> 💡 `-f` vs `-p`:
> - `-f <package>` → spawns a new process and injects at boot (recommended for SSL bypass, must be active before the first handshake).
> - `-p <pid|name>` → attaches to a running process (fast debugging, late hooks).

---

## 🧠 Key Parts of `acyber_frida.js`

### 🥷 Module 1 — Root Detection Bypass

Helpers:
- **`logRoot(api, detail)`** — central log for every root check
- **`RootPackages[]`** — 24 root manager packages (SuperSU, Magisk, Xposed, …)
- **`RootBinaries[]`** — suspicious binaries: `su`, `busybox`, `supersu`, …
- **`RootProperties{}`** — spoofed property values

Java-level hooks:

| Class | Method | Behavior |
|-------|--------|----------|
| `ApplicationPackageManager` | `getPackageInfo` | Replace package name with a fake one |
| `java.io.File` | `exists` | Return `false` for root binaries |
| `Runtime` | `exec` × 6 overloads | Block `su`, `id`, `mount`, `getprop` |
| `SystemProperties` | `get` | Return safe values |
| `String` | `contains` | `test-keys` → `false` |
| `BufferedReader` | `readLine` | `test-keys` → `release-keys` |
| `ProcessBuilder` | `start` | Replace command with `grep` |

Native (libc) hooks:
- **`fopen`** → overwrite path with `Memory.writeUtf8String` to `/notexists`
- **`system`** → replace dangerous command with `grep`

### 🔐 Module 2 — AES Token Hook

Helpers:
- **`bytesToHex(arr)`** — byte array → HEX
- **`bytesToBase64(arr)`** — byte array → Base64
- **`logAES(label, value)`** — deduplicated logging (via `seenAES`)

Hooks:

| Class | Hook point | Captured data |
|-------|------------|---------------|
| `SecretKeySpec` | `$init` | **AES key** (HEX + Base64) |
| `IvParameterSpec` | `$init` | **IV** (HEX + Base64) |
| `Cipher` | `getInstance` | Transformation (e.g., `AES/CBC/PKCS5Padding`) |
| `Cipher` | `init` | mode (ENCRYPT / DECRYPT) |
| `Cipher` | `doFinal` | Input and output as Base64 |

### 🌐 Module 3 — SSL Pinning Bypass

Core: **`Java.registerClass`** creates an open `X509TrustManager`, then injects it into `SSLContext.init`.

Additional hooks:
- `HttpsURLConnection.setDefaultHostnameVerifier` / `setSSLSocketFactory` / `setHostnameVerifier`
- `com.android.org.conscrypt.TrustManagerImpl.verifyChain` and `checkTrustedRecursive`
- `com.android.org.conscrypt.OpenSSLSocketImpl.verifyCertificateChain`
- **OkHttp**: all three `CertificatePinner.check(...)` overloads + `check$okhttp`
- **TrustKit**: `OkHostnameVerifier.verify(SSLSession/X509)` + `PinningTrustManager.checkServerTrusted`
- **Appcelerator**: `PinningTrustManager.checkServerTrusted`
- **WebView**: `WebViewClient.onReceivedSslError` → `handler.proceed()`

---

## 🛰️ Module 4 — Companion Proxy (`acyber_server_proxy.py`)

A **lightweight forward proxy** with protocol and domain filtering that can run alongside Burp or replace it. Live timestamped logs are printed to the terminal.

### Usage

```bash
# Default: 127.0.0.1:5090, everything allowed
python acyber_server_proxy.py

# Custom host / port
python acyber_server_proxy.py --host 127.0.0.1 --port 8080

# Only allow HTTPS (HTTP returns 403)
python acyber_server_proxy.py --protocol https

# Only HTTPS + these domains
python acyber_server_proxy.py --protocol https --allow-domain "*.github.com,example.com"

# Block ads / trackers (wildcards supported)
python acyber_server_proxy.py --block-domain "*.doubleclick.net,*.ads.example,facebook.com"

# Bind on a LAN interface with a whitelist
python acyber_server_proxy.py --host 0.0.0.0 --port 5090 --allow-domain "*.wikipedia.org"
```

### Sample log output

```text
[14:22:01] Proxy listening on 127.0.0.1:5090
[14:22:01] Protocol filter : all
[14:22:03] [HTTP]         GET http://example.com:80/  <- 127.0.0.1
[14:22:05] [HTTPS]        github.com:443  <- 127.0.0.1
[14:22:07] [DENY-DOMAIN]  HTTP   ads.foo.com/x  <- 127.0.0.1
[14:22:09] [DENY-PROTO]   HTTPS  bank.com:443  <- 127.0.0.1
```

### CLI options

| Option | Default | Description |
|--------|---------|-------------|
| `--host` | `127.0.0.1` | Bind address |
| `--port` | `5090` | Bind port |
| `--protocol` | `all` | `all` / `http` / `https` |
| `--allow-domain` | empty | Comma-separated whitelist, wildcards allowed (`*.example.com`) |
| `--block-domain` | empty | Comma-separated blacklist, wildcards allowed |

### Combined with Frida + Burp

```bash
# Terminal 1 — proxy
python acyber_server_proxy.py --host 0.0.0.0 --port 5090

# Terminal 2 — Frida
frida -U -f com.target.app -l acyber_frida.js --no-pause

# Terminal 3 — point the device at the proxy
adb shell settings put global http_proxy 192.168.1.10:5090

# To chain with Burp:
#   Burp Listener on 8080 → acyber_server_proxy.py on 5090 → device to 5090
#   (or reverse the chain depending on your scenario)
```

---

## 🧪 Sample Frida Output

```text
===== [1] ROOT DETECTION =====
[ROOT] ApplicationPackageManager.getPackageInfo(String, int) -> eu.chainfire.supersu
[ROOT] java.io.File.exists() -> su
[ROOT] Runtime.exec(String) -> getprop
[ROOT] libc.so!system -> su

===== [2] AES TOKEN HOOK =====
[AES] SecretKeySpec: hex=8f2a...c1 b64=jyqu...wQ==
[AES] IvParameterSpec: hex=0001...ff b64=AAH.../w==
[AES] Cipher.getInstance: AES/CBC/PKCS5Padding
[AES] Cipher.init mode -> 1
[AES] doFinal input: b64=U2FsdGVk...
[AES] doFinal output: b64=c2VjcmV0...

===== [3] SSL SPOOFING =====
[SSL] bypassed: javax.net.ssl.SSLContext.init
[SSL] bypassed: okhttp3.CertificatePinner.check(String, List)
[SSL] bypassed: android.webkit.WebViewClient.onReceivedSslError

===== [READY] =====
```

---

## 🧹 Cleanup

```bash
adb shell settings put global http_proxy :0
adb shell "pkill frida-server"
```

And if you installed a CA, remove it from **Settings → Security → Trusted credentials → User**.

---

### 📰 ACyber Sentinel — Cybersecurity News

Stay updated with the latest threat reports, vulnerability disclosures, and industry news from the ACyber Sentinel portal:

| Language | Link |
|----------|------|
| 🇬🇧 English | [news.acyber.ir/?lang=en](https://news.acyber.ir/?lang=en) |
| 🇮🇷 فارسی | [news.acyber.ir/?lang=fa](https://news.acyber.ir/?lang=fa) |
| 🇸🇦 العربية | [news.acyber.ir/?lang=ar](https://news.acyber.ir/?lang=ar) |
| 🇷🇺 Русский | [news.acyber.ir/?lang=ru](https://news.acyber.ir/?lang=ru) |
| 🇨🇳 中文 | [news.acyber.ir/?lang=zh](https://news.acyber.ir/?lang=zh) |
| 🇻🇦 Latina | [news.acyber.ir/?lang=la](https://news.acyber.ir/?lang=la) |
---

## ⚠️ Disclaimer

This project is intended for **education**, **security research**, and **legal penetration testing** on applications you own or are authorized in writing to test.  
Using these tools against third-party applications without permission violates their terms of service and applicable law.  
The author assumes no liability for any misuse.

---

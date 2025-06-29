import re
from pathlib import Path

# ----------------------------
# Pentest / Security Smells
# ----------------------------
SECURITY_SMELLS_PATTERNS = {
    # Java security smells
    "Insecure WebView (Java)": re.compile(r'setJavaScriptEnabled\s*\(\s*true\s*\)', re.IGNORECASE),
    "Weak Crypto - ECB (Java)": re.compile(r'AES\/ECB', re.IGNORECASE),
    "Weak Hashing - MD5 (Java)": re.compile(r'MessageDigest\.getInstance\(\s*"MD5"\s*\)'),
    "Hardcoded Key (Java)": re.compile(r'(?i)(api[-_]?key|secret|token)\s*=\s*["\'].*["\']'),
    "Verbose Logging (Java)": re.compile(r'Log\.(d|v|i|w|e)\s*\(', re.IGNORECASE),
    "Insecure Storage (Java)": re.compile(r'getSharedPreferences\s*\(.*MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE', re.IGNORECASE),
    "Insecure HTTP Usage (Java)": re.compile(r'http://[^\s"\']+', re.IGNORECASE),
    "Hardcoded Credentials (Java)": re.compile(r'(?i)(username|password)\s*=\s*["\'].*["\']'),
    "Insecure SSL - AllowAllHostnameVerifier (Java)": re.compile(r'AllowAllHostnameVerifier', re.IGNORECASE),
    "Improper Certificate Validation (Java)": re.compile(r'TrustAllCerts|X509TrustManager|checkClientTrusted|checkServerTrusted', re.IGNORECASE),
    "Insecure Random (Java)": re.compile(r'new\s+Random\s*\(\s*\)', re.IGNORECASE),
    "WebView File Access (Java)": re.compile(r'setAllowFileAccess\s*\(\s*true\s*\)', re.IGNORECASE),
    "External Storage Write (Java)": re.compile(r'Environment\.getExternalStorageDirectory', re.IGNORECASE),

    # Smali security smells
    "Insecure WebView (Smali)": re.compile(r'invoke-virtual \{[vp0-9, ]*\}, Landroid/webkit/WebSettings;->setJavaScriptEnabled\(Z\)'),
    "Weak Crypto - ECB (Smali)": re.compile(r'const-string [vp0-9]+, "AES/ECB"'),
    "Weak Hashing - MD5 (Smali)": re.compile(r'const-string [vp0-9]+, "MD5"'),
    "Hardcoded Key (Smali)": re.compile(r'(?i)const-string [vp0-9]+, "(api[-_]?key|secret|token)[^"]+"'),
    "Verbose Logging (Smali)": re.compile(r'invoke-static \{[vp0-9, ]*\}, Landroid/util/Log;->(d|v|i|w|e)\('),
    "Insecure HTTP Usage (Smali)": re.compile(r'const-string [vp0-9]+, "http://'),
    "Hardcoded Credentials (Smali)": re.compile(r'(?i)const-string [vp0-9]+, "(username|password)[^"]*"'),
    "Insecure SSL - TrustAllCerts (Smali)": re.compile(r'const-string [vp0-9]+, "TrustAllCerts"'),
    "External Storage Write (Smali)": re.compile(r'Landroid/os/Environment;->getExternalStorageDirectory\(\)'),
    "Insecure Random (Smali)": re.compile(r'new-instance [vp0-9]+, Ljava/util/Random;'),
    
}

# ----------------------------
# Malware Patterns
# ----------------------------
MALWARE_PATTERNS = {
    # Java malware patterns
    "Dynamic Code Loading - DexClassLoader (Java)": re.compile(r'new\s+DexClassLoader\s*\(', re.IGNORECASE),
    "Dynamic Code Loading - PathClassLoader (Java)": re.compile(r'new\s+PathClassLoader\s*\(', re.IGNORECASE),
    "Native Library Load (Java)": re.compile(r'System\.loadLibrary\s*\(\s*".*"\s*\)', re.IGNORECASE),
    "Native Code Execution - System.load (Java)": re.compile(r'System\.load\s*\(\s*".*"\s*\)', re.IGNORECASE),
    "Command Execution (Java)": re.compile(r'Runtime\.getRuntime\(\)\.exec\s*\(', re.IGNORECASE),
    "Emulator Detection (Java)": re.compile(r'Build\.FINGERPRINT.*generic|Build\.MODEL.*Emulator|Build\.MANUFACTURER.*Genymotion', re.IGNORECASE),
    "Root Detection (Java)": re.compile(r'\/system\/bin\/su|\/system\/xbin\/su|\/system\/app\/Superuser\.apk', re.IGNORECASE),
    "Debugger Detection (Java)": re.compile(r'Debug\.isDebuggerConnected\s*\(\s*\)', re.IGNORECASE),
    "Class Loader Obfuscation (Java)": re.compile(r'loadClass\s*\(\s*.*\)', re.IGNORECASE),
    "Encrypted Payload Handling (Java)": re.compile(r'AES\/CBC|Base64\.decode', re.IGNORECASE),
    "Reflection (Java)": re.compile(r'Class\.forName\s*\(\s*".*"\s*\)', re.IGNORECASE),

    # Smali malware patterns
    "Dynamic Code Loading - DexClassLoader (Smali)": re.compile(r'new-instance [vp0-9]+, Ldalvik/system/DexClassLoader;'),
    "Dynamic Code Loading - PathClassLoader (Smali)": re.compile(r'new-instance [vp0-9]+, Ldalvik/system/PathClassLoader;'),
    "Native Library Load (Smali)": re.compile(r'invoke-static \{[vp0-9, ]*\}, Ljava/lang/System;->loadLibrary'),
    "Native Code Execution - System.load (Smali)": re.compile(r'invoke-static \{[vp0-9, ]*\}, Ljava/lang/System;->load'),
    "Command Execution (Smali)": re.compile(r'invoke-virtual \{[vp0-9, ]*\}, Ljava/lang/Runtime;->exec'),
    "Reflection Abuse (Smali)": re.compile(r'invoke-virtual \{[vp0-9, ]*\}, Ljava/lang/Class;->getMethod'),
    "Debugger Detection (Smali)": re.compile(r'invoke-static \{[vp0-9]*\}, Landroid/os/Debug;->isDebuggerConnected\(\)Z'),
    "Emulator Detection (Smali)": re.compile(r'const-string [vp0-9]+, ".*genymotion|goldfish|Emulator|Android SDK built for x86"'),
    "Root Detection (Smali)": re.compile(r'const-string [vp0-9]+, ".*\/system\/bin\/su|\/system\/xbin\/su|Superuser\.apk"'),
    "Base64 Decode (Smali)": re.compile(r'invoke-static \{[vp0-9, ]*\}, Landroid/util/Base64;->decode'),
    "Reflection (Smali)": re.compile(r'const-string [vp0-9]+, "java\.lang\.Class"'),
}

# ----------------------------
# Scanner (accepts which pattern set to use)
# ----------------------------
def scan_java_code(code_dir: str, pattern_set="security"):
    findings = []

    PATTERNS = SECURITY_SMELLS_PATTERNS if pattern_set == "security" else MALWARE_PATTERNS

    for code_file in Path(code_dir).rglob("*.*"):
        if code_file.suffix not in [".java", ".smali"]:
            continue

        print(f"[DEBUG] Scanning file: {code_file}")
        try:
            content = code_file.read_text(encoding="utf-8", errors="ignore")
            for name, pattern in PATTERNS.items():
                for match in pattern.finditer(content):
                    findings.append({
                        "file": str(code_file),
                        "issue": name,
                        "snippet": match.group(0).strip()
                    })
        except Exception as e:
            print(f"[-] Error reading {code_file}: {e}")

    print(f"[DEBUG] Total suspicious findings: {len(findings)}")
    return findings

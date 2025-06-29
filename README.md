# 🛡️ DroidSecGPT: Android Malware & Pentest AI Toolkit

DroidSecGPT is an advanced, AI-augmented Android malware analysis and pentesting framework designed to automate static code review, YARA pattern matching, malware classification, native binary analysis, and AI-powered vulnerability explanation.

---

## 🚀 Features

- ✅ **Modular Analyzer**: Choose between Pentest or Malware analysis mode.
- 🔍 **YARA Pattern Matching**: Scans Java, Smali, and ELF binaries using extensive custom rules.
- 🧠 **Gemini 1.5 Integration**: Explains flagged code like a malware analyst using LLM reasoning.
- 📂 **APK Decompilation**: Automatic source extraction via APKTool and AXML parser.
- 🛠️ **Native Library Analysis**:
  - ELF `.so` extraction and scanning
  - Dangerous function detection (`strcpy`, `system`, etc.)
  - Gemini-assisted native malware analysis
- 🧪 **Static Code Smell Detection**:
  - Java & Smali security smells (e.g., insecure crypto, WebView exposure)
- ⚙️ **Tool Integration Ready**:
  - Quark-Engine (optional)
  - FlowDroid static taint analysis (optional)
- 📊 **Beautiful Markdown Reports** with:
  - File path
  - Code snippets
  - Severity and classification
  - LLM-generated descriptions and remediation steps

---

## 🧰 Toolkit Structure

```
tools/
├── __init__.py
├── README.md
├── strings.exe
├── apktool/                 # APK decompilation tool
│   └── apktool.jar          # (or .bat if needed)
├── androguard/              # Manifest + permissions extraction
│   └── androguard_scripts/
├── jadx/                    # Java code decompiler
│   └── jadx-cli.jar
├── flowdroid/               # Taint analysis
│   ├── flowdroid.jar
│   ├── SourcesAndSinks.txt
│   └── platform-dir/        # Optional platform APIs if needed
├── mobsf/                   # Static analyzer
│   ├── api.py
│   └── mobsf.py
├── quark/                   # Rule-based Android analyzer
│   ├── runner.py
│   └── data/
├── Yara_rules/              # YARA signatures only
│   ├── android_rules.yar
│   ├── rule_1.yar
│   └── rule_2.yar
```

---

## ⚡ Quick Start

### 1. 🔧 Install Requirements

```bash
pip install -r requirements.txt
```

### 2. 🧪 Run the Toolkit

```bash
python main.py SampleAPK.apk
```

You’ll be prompted to choose:

```
1. Complete Comprehensive Scan
2. Pentest Analysis
3. Malware Analysis
4. Flowdroid Analysis
5. Yara Malware Analysis
```

Choose a mode, then provide the APK to scan.

---

## 🔍 YARA Rule Coverage

Custom YARA rules match:
- Java API misuse (e.g., `WebView.loadUrl`, `DexClassLoader`)
- Smali backdoors and obfuscation strings
- ELF `.so` injection, shell usage, privilege escalation patterns
- Encrypted C2 strings, native root exploits

View/edit in: `tools/yara_rules/android_malware_rules.yar`

---

## 🧠 Gemini-Enhanced Reasoning

For every YARA or smell match, Gemini is called to:

- Explain the vulnerability in human terms
- Assign risk severity
- Suggest real-world mitigation (with Java code if needed)
- Support ELF binary analysis via `strings` dump

You can toggle Gemini per module.

---

## 📄 Example Report Snippet

```markdown
## 🔎 YARA Scan Results
- File: java_code/sources/com/app/MainActivity.java
  - Matched Rules: Android_WebView_JS_Enabled

## 🤖 Gemini Review
Vulnerability: WebView with JavaScript Enabled  
Severity: HIGH  
Description: This allows XSS via untrusted content...  
Mitigation: Disable JS or restrict content loading...  
```

---

## 📦 Optional Enhancements

- ✅ [ ] Integrate MobSF via API for hybrid scanning
- ✅ [ ] Add VirusTotal API hash matching
- ✅ [ ] Dynamic analysis plugin (via sandboxed emulator)
- ✅ [ ] PDF export for audit-friendly reports

---

## 🤝 Contributing

Pull requests, new YARA rules, and plugins are welcome! Open an issue or fork and submit a PR.

---

## 🛡️ Disclaimer

DroidSecGPT is for **educational and security research purposes only**. Do not use it against applications you do not own or have permission to audit.

---

## 📬 Contact

Created by [@DEVizzi](https://github.com/DEVizzi)  
GitHub: https://github.com/DEVizzi/DroidSecGPT

---

## 🏷️ Tags

`android-security` · `malware-analysis` · `yara` · `gemini` · `smali` · `static-analysis` · `apk` · `reverse-engineering` · `ai-malware-detection`

---

## 🖥️ Example Run (Windows)

```bash
Microsoft Windows [Version 10.0.22631.5472]
(c) Microsoft Corporation. All rights reserved.

C:\Users\IzazUlHaque\OneDrive - Black Duck Software\Desktop>cd DroidSecGPT

C:\Users\IzazUlHaque\OneDrive - Black Duck Software\Desktop\DroidSecGPT>python main.py InsecureBankv2.apk

== Select Analysis Type ==
1. Complete Comprehensive Scan
2. Pentest Analysis
3. Malware Analysis
4. Flowdroid Analysis
5. Yara Malware Analysis
Enter choice (1 or 2): 1

[+] Selected: Pentest Analysis (Code, FlowDroid, Yara)
[+] Decompiling APK using apktool...
[+] APK decompiled to: tmp_apktool
[+] Extracting manifest info using Androguard...
[+] Sending manifest info to Gemini 1.5 Flash...
[*] Cleaning existing java_code directory...
[+] Decompiling code using JADX...
[+] Java source extracted to: java_code
[+] Scanning Java/Smali code for patterns (security)...
[DEBUG] Scanning file: java_code\sources\com\example\SomeClass.java
...
[DEBUG] Total suspicious findings: 693
[+] Sending code-level issues to Gemini for analysis...
[*] Running FlowDroid...
[FlowDroid] STDOUT:
...
[main] INFO soot.jimple.infoflow.android.SetupApplication - Found 0 leaks

[*] Running YARA scan...

🧠 YARA Rules in Use:
 - Android_DexClassLoader_Load
 - Android_SystemLoadLibrary
 - Android_Base64_AES_CBC
 - Android_Root_Su_Binary
 - Android_Emulator_Detection
 - Android_Debugger_Detection
 - Android_Hardcoded_Command
 - Dendroid_OR_RAT_Signature
 - HackingTeam_Android_RAT
 - Malware_Suspicious_Packer
 - Android_Joker_Malware
 - Android_Anubis_Banking_Trojan
 - Android_DroidJack_RAT
 - Android_Dendroid_RAT
 - Android_HummingBad_Rootkit
 - Android_Obfuscation_ShortNames
 - Android_EncryptedStrings_Used
 - Android_DynamicCode_Loading
 - Android_AntiEmulator_Java
 - Android_AntiDebug_Native

[*] Scanning for native libraries (.so)...

[✓] Report saved to reports\InsecureBankv2_report.md
```


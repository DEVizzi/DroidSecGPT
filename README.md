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
DroidSecGPT/
├── main.py                 # Entry point: Select mode, run all tools
├── code_analyzer.py        # Pattern-based security & malware smell engine
├── yara_runner.py          # YARA compilation and directory matcher
├── gemini_runner.py        # Gemini 1.5 Flash LLM analysis engine
├── tools/
│   ├── strings.exe         # Binary string extraction (for native libs)
│   └── yara_rules/
│       └── android_malware_rules.yar
├── java_code/              # Decompiled Java source
├── smali_code/             # Decompiled Smali source
├── native_libs/            # Extracted .so binaries
├── tmp_apktool/            # APKTool working folder
└── reports/                # Analysis output
```

---

## ⚡ Quick Start

### 1. 🔧 Install Requirements

```bash
pip install -r requirements.txt
```

### 2. 🧪 Run the Toolkit

```bash
python main.py
```

You’ll be prompted to choose:

```
1) Pentest Analysis
2) Malware Analysis
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

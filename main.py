import os
import subprocess
import sys
import shutil
import json
import zipfile
from pathlib import Path
import tempfile
import re
from tools.androguard.androguard_wrapper import extract_manifest_info
from llm.gemini_runner import analyze_manifest_with_gemini, analyze_code_snippets_with_gemini
from analysis.code_analyzer import scan_java_code
from analysis.yara_runner import load_yara_rules, run_yara_on_directory

from analysis.mobsf_runner import run_mobsf
from analysis.quark_runner import run_quark
from analysis.flowdroid_runner import run_flowdroid

# Configure paths
APKTOOL_PATH = str(Path("tools/apktool/apktool.bat").resolve())
JADX_PATH = str(Path("tools/jadx/jadx.bat").resolve())
JAVA_CODE_DIR = str(Path("java_code").resolve())
SO_EXTRACT_DIR = "native_libs"

def extract_so_files(apk_path, output_dir):
    os.makedirs(output_dir, exist_ok=True)
    extracted_files = []
    with zipfile.ZipFile(apk_path, 'r') as zip_ref:
        for file in zip_ref.namelist():
            if file.startswith("lib/") and file.endswith(".so"):
                so_path = Path(output_dir) / Path(file).name
                with open(so_path, "wb") as f:
                    f.write(zip_ref.read(file))
                extracted_files.append(str(so_path))
    return extracted_files

def decompile_apk(apk_path: str, output_dir: str):
    print(f"[+] Decompiling APK using apktool...")
    result = subprocess.run(
        [APKTOOL_PATH, "d", apk_path, "-f", "-o", output_dir],
        capture_output=True,
        text=True,
        shell=True
    )
    if result.returncode != 0:
        print("[-] Apktool failed:", result.stderr)
        sys.exit(1)
    print("[+] APK decompiled to:", output_dir)

def decompile_java(apk_path: str, output_dir: str):
    print("[*] Cleaning existing java_code directory...")
    if os.path.exists(output_dir):
        shutil.rmtree(output_dir)
    os.makedirs(output_dir)

    print("[+] Decompiling code using JADX...")
    result = subprocess.run(
        ["tools\\jadx\\bin\\jadx.bat", "-d", output_dir, apk_path],
        capture_output=True,
        text=True,
        shell=True
    )

    if result.returncode != 0:
        print("[-] JADX failed:")
        print(result.stderr)
        sys.exit(1)
    print(f"[+] Java source extracted to: {output_dir}")

def run_analysis(apk_path: str, selected_tools, pattern_set="security"):
    output_dir = "java_code"
    used_existing_java_code = False
    used_existing_apktool = False

    full_report = ""

    # --- TOOL 1: Gemini Analysis ---
    if "1" in selected_tools:
        if not used_existing_apktool:
            decompile_apk(apk_path, "tmp_apktool")
            used_existing_apktool = True

        print("[+] Extracting manifest info using Androguard...")
        manifest_data = extract_manifest_info(apk_path)

        print("[+] Sending manifest info to Gemini 1.5 Flash...")
        manifest_report = analyze_manifest_with_gemini(manifest_data)

        if not used_existing_java_code:
            decompile_java(apk_path, output_dir)
            used_existing_java_code = True

        print(f"[+] Scanning Java/Smali code for patterns ({pattern_set})...")
        findings = scan_java_code(output_dir, pattern_set=pattern_set)

        print("[+] Sending code-level issues to Gemini for analysis...")
        code_report = analyze_code_snippets_with_gemini(findings)

        full_report += manifest_report + "\n\n" + code_report
    else:
        full_report += "## 📄 Gemini Analysis Skipped\nUser did not select Gemini analysis.\n"

    # --- TOOL 2: Quark ---
    if "2" in selected_tools:
        try:
            print("[*] Running Quark-Engine...")
            full_report += "\n\n" + run_quark(apk_path)
        except Exception as e:
            full_report += f"\n\n## ❌ Quark-Engine Failed\nError: {str(e)}"
    else:
        full_report += "\n\n## ⚠ Quark-Engine Skipped\nUser did not select Quark-Engine."

    # --- TOOL 3: FlowDroid ---
    if "3" in selected_tools:
        try:
            print("[*] Running FlowDroid...")
            flowdroid_report, flowdroid_leaks = run_flowdroid(apk_path)
            full_report += "\n\n" + flowdroid_report

            if flowdroid_leaks:
                print("\n[?] FlowDroid detected data leaks.")
                print("Do you want to perform a full Gemini-assisted analysis of the leak source code?")
                print("1. Yes - Decompile and analyze surrounding Java code for each leak")
                print("2. No - Just include the FlowDroid summary in the report")
                user_choice = input("Enter choice (1 or 2): ").strip()

                if user_choice == "1":
                    if not used_existing_java_code:
                        decompile_java(apk_path, JAVA_CODE_DIR)
                        used_existing_java_code = True

                    print("[*] Locating source files and extracting method code for each leak...")
                    gemini_prompts = []

                    def find_java_file_by_class(class_name):
                        expected_filename = class_name.split(".")[-1] + ".java"
                        for root, _, files in os.walk(JAVA_CODE_DIR):
                            for file in files:
                                if file == expected_filename:
                                    return os.path.join(root, file)
                        return None

                    def extract_method_from_code(code, method_name):
                        pattern = re.compile(rf"(public|private|protected)?\s+[\w<>\[\]]+\s+{re.escape(method_name)}\s*\(.*?\)\s*\{{", re.MULTILINE)
                        lines = code.splitlines()
                        for i, line in enumerate(lines):
                            if pattern.search(line):
                                snippet_lines = lines[i:i+40]
                                return "\n".join(snippet_lines)
                        return None

                    print(f"[DEBUG] Processing {len(flowdroid_leaks)} FlowDroid leaks...")

                    for i, leak in enumerate(flowdroid_leaks):
                        print(f"\n[*] Analyzing leak #{i + 1}...")

                        if not isinstance(leak, dict):
                            print(f"[WARN] Skipping invalid leak #{i}: {leak}")
                            continue
                        if "method" not in leak or "sink" not in leak:
                            print(f"[WARN] Leak #{i} missing required keys. Skipping...")
                            continue

                        class_name = leak["method"].split(":")[0].strip()
                        method_name = leak["method"].split(":")[1].strip().split("(")[0].strip()
                        print(f"[INFO] Looking for class: {class_name}, method: {method_name}")

                        java_file_path = find_java_file_by_class(class_name)
                        if not java_file_path:
                            print(f"[WARN] Java file for class {class_name} not found.")
                            continue

                        with open(java_file_path, "r", encoding="utf-8") as f:
                            code = f.read()

                        method_snippet = extract_method_from_code(code, method_name)
                        if not method_snippet:
                            print(f"[WARN] Method '{method_name}' not found in {java_file_path}")
                            continue

                        sources = leak.get("sources")
                        if isinstance(sources, list) and sources:
                            sources_str = ", ".join(sources)
                        elif isinstance(sources, str) and sources.strip():
                            sources_str = sources.strip()
                        else:
                            sources_str = "None"

                        print(f"[INFO] Preparing Gemini prompt for method '{method_name}'...")

                        prompt = f"""Please analyze the following Android Java method for security vulnerabilities.

**🔍 Leak Details**
- **Sink**: {leak.get('sink', 'N/A')}
- **Method**: {leak.get('method', 'N/A')}
- **Sources**: {sources_str}

**📄 Java Code Context**
```java
{method_snippet}


Is this vulnerable? If so, explain the risk and suggest remediations."""

                        gemini_prompts.append({
                            "file": java_file_path,
                            "issue": f"Sink: {leak.get('sink', 'N/A')}, Sources: {sources_str}",
                            "snippet": method_snippet
                        })

                    if gemini_prompts:
                        print(f"[+] Sending {len(gemini_prompts)} prompt(s) to Gemini for final analysis...")
                        print(f"\n-->{gemini_prompts}")
                        gemini_response = analyze_code_snippets_with_gemini(gemini_prompts)
                        print("[✓] Gemini analysis complete.")
                        full_report += "\n\n## 🤖 Gemini Final Verdict on FlowDroid Leaks\n" + gemini_response
                    else:
                        print("[!] No valid prompts generated for Gemini.")
                        full_report += "\n\n## ⚠ Gemini Leak Analysis Skipped\nNo Java code matched the FlowDroid leaks."


#---------------------------------------
        except Exception as e:
            print(f"[!] FlowDroid failed: {e}")
            flowdroid_report = f"\n\n## ❌ FlowDroid Failed\nError: {str(e)}"
            flowdroid_leaks = []
            full_report += flowdroid_report
    else:
        full_report += "\n\n## ⚠ FlowDroid Skipped\nUser did not select FlowDroid."

    
    # --- TOOL 4: YARA ---
    if "4" in selected_tools:
        yara_rules_path = "tools/yara_rules/android_malware_rules.yar"
        if Path(yara_rules_path).exists():
            try:
                print("[*] Running YARA scan...")
                yara_rules = load_yara_rules(yara_rules_path)
                yara_matches = run_yara_on_directory(yara_rules, output_dir)
                if yara_matches:
                    full_report += "\n\n## 🔎 YARA Scan Results\n"
                    for match in yara_matches:
                        full_report += f"- **File**: `{match['file']}`\n  - **Matched Rules**: {', '.join(match['matches'])}\n"
                        try:
                            with open(match['file'], 'r', encoding='utf-8', errors='ignore') as f:
                                file_content = f.read()

                            gemini_result = analyze_code_snippets_with_gemini([
                                {
                                    "file": match['file'],
                                    "issue": ', '.join(match['matches']),
                                    "snippet": file_content[:8000]  # limit for Gemini prompt
                                }
                            ])

                            full_report += f"\n### 🤖 Gemini Malware Review\n{gemini_result}\n"

                        except Exception as e:
                            full_report += f"\n❌ Gemini analysis failed for `{match['file']}`: {e}\n"
                else:
                    full_report += "\n\n## ✅ YARA Scan: No matches found"
            except Exception as e:
                full_report += f"\n\n## ❌ YARA Scan Failed\nError: {str(e)}"
        else:
            full_report += "\n\n## ⚠ YARA Scan Skipped\nNo rules file found at `yara_rules/`."

    # --- TOOL 5: Native Binary Analysis (.so) ---
    print("\n[*] Scanning for native libraries (.so)...")
    so_files = extract_so_files(apk_path, SO_EXTRACT_DIR)

    if so_files:
        print(f"[!] Found {len(so_files)} native libraries:")
        for so in so_files:
            print(" -", so)

        choice = input("⚠️  Do you want to analyze these .so files for vulnerabilities with Gemini? (y/n): ").strip().lower()
        if choice == "y":
            from llm.gemini_runner import analyze_native_so_with_gemini  # make sure this exists

            seen = set()
            for so_file in so_files:
                name = Path(so_file).name
                if name in seen:
                    continue
                seen.add(name)

                print(f"\n[*] Running Gemini on {so_file} ...")
                try:
                    strings_path = os.path.join("tools", "strings.exe")
                    strings_out = subprocess.check_output([strings_path, so_file], text=True, errors='ignore')
                    result = analyze_native_so_with_gemini(so_file, strings_out[:8000])
                    full_report += f"\n\n## 🔬 Native Binary Analysis - {name}\n{result}\n"
                except FileNotFoundError:
                    full_report += f"\n\n## ❌ Native Analysis Failed: 'tools/strings.exe' not found.\n"
                except Exception as e:
                    full_report += f"\n\n## ❌ Failed Native Analysis for {so_file}: {e}\n"
        elif so_files:
            full_report += "\n\n## ⚠ Native Analysis Skipped by User\n"
    else:
        full_report += "\n\n## ✅ No Native Libraries Found in APK\n"

    # 5. Save
    report_path = Path("reports") / f"{Path(apk_path).stem}_report.md"
    Path("reports").mkdir(exist_ok=True)
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(full_report)

    print(f"\n[✓] Report saved to {report_path}")



if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python main.py path/to/app.apk")
        sys.exit(1)

    apk_file = sys.argv[1]
    if not os.path.isfile(apk_file):
        print(f"[-] File not found: {apk_file}")
        sys.exit(1)

    print("\n== Select Analysis Type ==")
    print("1. Complete Comprehensive Scan")
    print("2. Pentest Analysis")
    print("3. Malware Analysis")
    print("4. Flowdroid Analysis")
    print("5. Yara Malware Analysis")
    
    analysis_choice = input("Enter choice (1 or 2): ").strip()

    if analysis_choice == "1":
        selected_tools = ["1", "3", "4",]  # Code + FlowDroid + Yara
        pattern_set = "security"
        print("\n[+] Selected: Pentest Analysis (Code, FlowDroid, Yara)")
    elif analysis_choice == "2":
        selected_tools = ["1", "3"]  # Code + Flowdroid
        pattern_set = "security"
        print("\n[+] Selected: Malware Analysis (Code, Flowdroid)")
    elif analysis_choice == "3":
        selected_tools = ["1","4"]  # Code + Yara
        pattern_set = "malware"
        print("\n[+] Selected: Malware Analysis (Code, Yara)")
    elif analysis_choice == "4":
        selected_tools = ["3"]  # Flowdrid
        pattern_set = "security"
        print("\n[+] Selected: Malware Analysis (Flowdroid)")
    elif analysis_choice == "5":
        selected_tools = ["4"]  # Yara
        pattern_set = "malware"
        print("\n[+] Selected: Malware Analysis (Yara)")    
    else:
        print("[-] Invalid choice. Exiting.")
        sys.exit(1)

    run_analysis(apk_file, selected_tools, pattern_set)

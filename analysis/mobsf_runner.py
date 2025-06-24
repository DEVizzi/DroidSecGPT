import requests
import time
import os
import subprocess
from dotenv import load_dotenv
import pathlib

load_dotenv()

api_key = os.getenv("MOBSF_API_KEY")

def is_mobsf_running(url: str = "http://localhost:8000") -> bool:
    try:
        res = requests.get(url)
        return res.status_code == 200
    except:
        return False

def start_mobsf_server(bat_path="tools/mobsf/run.bat"):
    print("[*] MobSF not running. Attempting to start using run.bat...")
    try:
        os.environ["MOBSF_DISABLE_AUTHENTICATION"] = "1"

        # Resolve absolute path
        bat_abs_path = str(pathlib.Path(bat_path).resolve())

        # Confirm the file exists
        if not os.path.isfile(bat_abs_path):
            print(f"[!] run.bat not found at: {bat_abs_path}")
            return False

        subprocess.Popen(f'"{bat_abs_path}"', cwd=str(pathlib.Path(bat_path).parent.resolve()), shell=True)

        for i in range(10):
            time.sleep(5)
            if is_mobsf_running():
                print("[✓] MobSF started successfully.")
                return True
            print(f"[*] Waiting for MobSF to start... ({i+1}/10)")

    except Exception as e:
        print(f"[!] Failed to start MobSF: {e}")
    return False

def run_mobsf(apk_path: str, api_key: str = None, mobsf_url: str = "http://localhost:8000") -> str:
    if not api_key:
        print("[-] MobSF API key is not set. Skipping MobSF scan.")
        return "❌ MobSF API key not provided."

    if not is_mobsf_running(mobsf_url):
        os.environ["MOBSF_DISABLE_AUTHENTICATION"] = "1"
        if not start_mobsf_server():
            return "❌ MobSF failed to start."

    try:
        print("[MobSF] Uploading APK...")
        upload_url = f"{mobsf_url}/api/v1/upload"
        headers = {
            "Authorization": api_key,
        }
        # Ensure APK file exists
        if not os.path.isfile(apk_path):
            return f"❌ APK file does not exist: {apk_path}"

        print(f"[MobSF] Waiting 5s for MobSF to stabilize before upload...")
        time.sleep(5)
        print(f"[MobSF] Uploading APK from: {apk_path}")
        with open(apk_path, "rb") as f:
            files = {
                "file": (os.path.basename(apk_path), f, "application/octet-stream")
            }
            upload_res = requests.post(upload_url, headers=headers, files=files)
        if upload_res.status_code != 200:
            print(f"[MobSF] Upload failed with status {upload_res.status_code}: {upload_res.text}")
        upload_data = upload_res.json()

        scan_hash = upload_data.get("hash")
        file_name = upload_data.get("file_name")
        if not scan_hash:
            return "❌ Failed to get scan hash from MobSF upload."

        print("[MobSF] Triggering static analysis...")
        scan_url = f"{mobsf_url}/api/v1/scan"
        scan_payload = {
            "scan_type": "apk",
            "file_name": file_name,
            "hash": scan_hash
        }
        scan_res = requests.post(scan_url, headers=headers, json=scan_payload)
        scan_res.raise_for_status()

        print("[MobSF] Fetching report...")
        time.sleep(5)  # Wait before fetching the report
        report_url = f"{mobsf_url}/api/v1/report_json"
        report_payload = {"hash": scan_hash}
        report_res = requests.post(report_url, headers=headers, json=report_payload)
        report_res.raise_for_status()
        report_data = report_res.json()

        findings = report_data.get("code_analysis", [])
        summary = "## 🔍 MobSF Code Analysis Report\n"
        if not findings:
            summary += "No issues found in code analysis."
        else:
            for item in findings:
                summary += f"\n- **{item.get('title')}**: {item.get('description')} (Severity: {item.get('severity')})"

        return summary

    except Exception as e:
        return f"❌ MobSF integration error: {str(e)}"

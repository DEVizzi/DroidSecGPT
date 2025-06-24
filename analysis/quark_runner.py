import subprocess
import os

def run_quark(apk_path: str) -> str:
    try:
        print("[*] Running Quark-Engine...")

        # Construct the command properly
        cmd = ["quark", "--apk", apk_path, "--output", "quark_result.json"]
        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.returncode != 0:
            return f"[✘] Quark failed:\n{result.stderr}"

        # Check if output was generated
        if not os.path.exists("quark_result.json"):
            return "[✘] Quark scan did not produce output."

        # Read and summarize
        with open("quark_result.json", "r", encoding="utf-8") as f:
            json_output = f.read()

        return "## 🐍 Quark-Engine Report\nQuark-Engine completed.\nOutput saved to `quark_result.json`."

    except Exception as e:
        return f"[✘] Quark error: {e}"

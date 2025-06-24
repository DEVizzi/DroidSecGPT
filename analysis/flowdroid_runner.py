import os
import subprocess
import re
import json

def extract_flowdroid_leaks(stderr_output):
    """
    Parses FlowDroid stderr output and extracts structured leak information.
    Returns a tuple: (leaks_markdown, leaks_json)
    """
    lines = stderr_output.splitlines()
    leaks = []
    current_leak = {}

    for i, line in enumerate(lines):
        if "The sink" in line and "was called with values from the following sources" in line:
            match_method = re.search(r"in method <(.*?)>", line)
            current_leak = {
                "sink": line.split("The sink")[1].split("was called")[0].strip(),
                "method": match_method.group(1).strip() if match_method else "Unknown",
                "sources": []
            }
            j = i + 1
            while j < len(lines) and lines[j].strip().startswith("-"):
                source_line = lines[j].strip().lstrip("- ").strip()
                current_leak["sources"].append(source_line)
                j += 1
            leaks.append(current_leak)

    # Markdown summary
    markdown = "## ✅ FlowDroid Leaks Summary\n"
    if not leaks:
        markdown += "\nNo leaks found.\n"
    for idx, leak in enumerate(leaks, 1):
        markdown += f"\n### 🔓 Leak {idx}\n"
        markdown += f"- **Sink:** `{leak['sink']}`\n"
        markdown += f"- **Method:** `{leak['method']}`\n"
        if leak["sources"]:
            markdown += "- **Sources:**\n"
            for src in leak["sources"]:
                markdown += f"  - `{src}`\n"
        else:
            markdown += "- **Sources:** None found\n"

    return markdown, leaks


def run_flowdroid(apk_path: str):
    """
    Runs FlowDroid on the APK and returns a tuple: (markdown_report, list_of_leaks)
    """
    try:
        android_jar_path = os.getenv("ANDROID_SDK_PATH", r"C:\Users\IzazUlHaque\AppData\Local\Android\Sdk\platforms")
        flowdroid_jar = os.path.join("tools", "flowdroid", "flowdroid.jar")
        sources_sinks_file = os.path.join("tools", "flowdroid", "SourcesAndSinks.txt")

        if not os.path.isfile(flowdroid_jar):
            return "❌ FlowDroid jar not found.", []

        if not os.path.isfile(sources_sinks_file):
            return "❌ SourcesAndSinks.txt not found.", []

        if not os.path.isdir(android_jar_path):
            return f"❌ Invalid Android SDK platform path: {android_jar_path}", []

        cmd = [
            "java", "-jar", flowdroid_jar,
            "-a", apk_path,
            "-p", android_jar_path,
            "-s", sources_sinks_file
        ]

        print(f"[FlowDroid] Running: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

        print("[FlowDroid] STDOUT:")
        print(result.stdout)
        print("[FlowDroid] STDERR:")
        print(result.stderr)

        if result.returncode != 0:
            return (
                f"## ❌ FlowDroid Error\n"
                f"**Exit Code**: {result.returncode}\n\n"
                f"**Standard Error**:\n```\n{result.stderr[:3000]}\n```\n"
                f"**Standard Output (if any)**:\n```\n{result.stdout[:3000]}\n```",
                []
            )

        # Extract structured results
        markdown, leaks = extract_flowdroid_leaks(result.stderr)

        return markdown, leaks

    except Exception as e:
        return f"❌ FlowDroid Exception: {str(e)}", []

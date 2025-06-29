import os
import json
import re
import google.generativeai as genai
from dotenv import load_dotenv
from collections import defaultdict

load_dotenv()
genai.configure(api_key=os.getenv("GEMINI_API_KEY"))

def analyze_native_so_with_gemini(filename: str, extracted_strings: str) -> str:
    prompt = f"""
You are a native malware analyst. The following ELF (.so) library was extracted from an Android APK.

It may contain native backdoors, command injection, root access payloads, or system calls.

Here are the extracted `strings` from the binary:
{extracted_strings}
Please explain:
- Any suspicious behavior or intent
- What type of malware this could be
- Risk level
- What parts of the binary are most suspicious
"""

    model = genai.GenerativeModel("gemini-1.5-flash")
    response = model.generate_content(prompt)
    return response.text

def analyze_manifest_with_gemini(manifest_info: dict) -> str:
    manifest_json = json.dumps(manifest_info, indent=2)

    prompt = f"""
    You are a mobile security expert.
    Analyze the following Android app manifest data and list any potential security vulnerabilities, their severity (Low/Medium/High), and how to fix them.

    Manifest Info (JSON):
    {manifest_json}

    Respond in a clear and readable format.
    """

    model = genai.GenerativeModel("gemini-1.5-flash")
    response = model.generate_content(prompt)
    return response.text

def analyze_code_snippets_with_gemini(findings: list) -> str:
    if not findings:
        return "### Code Analysis Findings\n" + "_"*34 + "\n\nNo code-level issues detected via static patterns.\n" + "="*60 + "\n"

    grouped = defaultdict(list)
    for f in findings:
        grouped[f["issue"]].append(f)

    formatted = "### Code Analysis Findings\n" + "_"*34 + "\n\n"
    group_count = 1

    for issue, group in grouped.items():
        representative_examples = group[:5]

        formatted += f"{group_count}. Vulnerability Type: {issue}\n"
        formatted += f"Total Occurrences: {len(group)}"
        if len(group) > 5:
            formatted += " (showing 5 examples)"
        formatted += "\n\n"

        for idx, entry in enumerate(representative_examples, 1):
            formatted += f"Example {idx}:\n"
            formatted += f"File: {entry['file']}\n"
            formatted += f"Code Snippet:\n```\n{entry['snippet']}\n```\n"

        analysis_prompt = f"""You are a mobile security expert. Analyze this Android code pattern and explain:
- Vulnerability name
- Severity (Low/Medium/High)
- Description
- Mitigation Strategy

Issue Type: {issue}
Example Code:
{representative_examples[0]['snippet']}
"""

        model = genai.GenerativeModel("gemini-1.5-flash")
        response = model.generate_content(analysis_prompt)
        raw = response.text

        # Extract details using more forgiving regex or fallback to general sections
        vul = re.search(r"(?i)vulnerability[:\s\-]+(.+?)\n", raw)
        sev = re.search(r"(?i)severity[:\s\-]+(.+?)\n", raw)
        desc_match = re.search(r"(?i)description[:\s\-]+([\s\S]+?)(?=\n\s*mitigation|\Z)", raw)
        mit_match = re.search(r"(?i)mitigation strategy[:\s\-]+([\s\S]+?)(?=\n\s*[A-Z]|\Z)", raw)

        description = desc_match.group(1).strip() if desc_match else 'No description provided by LLM.'
        mitigation = mit_match.group(1).strip() if mit_match else 'No mitigation steps suggested.'

        formatted += f"Vulnerability: {vul.group(1).strip() if vul else 'Not specified'}\n"
        formatted += f"Severity: {sev.group(1).strip() if sev else 'Unknown'}\n"
        formatted += f"Description: {description}\n"
        formatted += f"Mitigation Strategy: {mitigation}\n"

        formatted += "\n" + "-"*60 + "\n\n"
        group_count += 1

    formatted += "="*60 + "\n"
    return formatted

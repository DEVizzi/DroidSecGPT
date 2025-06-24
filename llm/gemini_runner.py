import os
import json
import re
import google.generativeai as genai
from dotenv import load_dotenv
from collections import defaultdict

load_dotenv()
genai.configure(api_key=os.getenv("GEMINI_API_KEY"))

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

    # Group findings by issue
    grouped = defaultdict(list)
    for f in findings:
        grouped[f["issue"]].append(f)

    formatted = "### Code Analysis Findings\n" + "_"*34 + "\n\n"
    group_count = 1

    for issue, group in grouped.items():
        representative_examples = group[:5]

        formatted += f"{group_count}. Vulnerability Type: {issue}\n"
        formatted += f"Total Occurrences: {len(group)} (showing 5 examples)\n\n"

        for idx, entry in enumerate(representative_examples, 1):
            formatted += f"Example {idx}:\n"
            formatted += f"File: {entry['file']}\n"
            formatted += f"Code Snippet:\n```\n{entry['snippet']}\n```\n"

        # Build a prompt with just one example for Gemini to analyze the group
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

        # Extract details using regex
        vul = re.search(r"(?i)vulnerability[:\s\-]+(.+)", raw)
        sev = re.search(r"(?i)severity[:\s\-]+(.+)", raw)
        desc = re.search(r"(?i)description[:\s\-]+(.+)", raw)
        mit = re.search(r"(?i)mitigation strategy[:\s\-]+(.+)", raw)

        if vul:
            formatted += f"Vulnerability: {vul.group(1).strip()}\n"
        if sev:
            formatted += f"Severity: {sev.group(1).strip()}\n"
        if desc:
            formatted += f"Description: {desc.group(1).strip()}\n"
        if mit:
            formatted += f"Mitigation Strategy: {mit.group(1).strip()}\n"

        formatted += "\n" + "-"*60 + "\n\n"
        group_count += 1

    formatted += "="*60 + "\n"
    return formatted

import yara
from pathlib import Path

def load_yara_rules(rules_path: str) -> yara.Rules:
    # Print rule names manually by parsing the .yar file
    print("\n🧠 YARA Rules in Use:")
    with open(rules_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line.startswith("rule "):
                rule_name = line.split()[1]
                print(f" - {rule_name}")

    # Compile and return the rules
    rules = yara.compile(filepath=rules_path)
    return rules

def run_yara_on_directory(rules: yara.Rules, directory: str):
    matches = []
    for file in Path(directory).rglob("*"):
        if file.is_file():
            try:
                with open(file, "rb") as f:
                    data = f.read()
                    result = rules.match(data=data)
                    if result:
                        matches.append({
                            "file": str(file),
                            "matches": [str(r) for r in result]
                        })
            except Exception as e:
                print(f"[YARA] Error scanning {file}: {e}")
    return matches

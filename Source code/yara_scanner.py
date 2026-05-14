try:
    import yara
    _YARA_AVAILABLE = True
except Exception:
    yara = None
    _YARA_AVAILABLE = False

import os

class YaraScanner:
    def __init__(self, rules_dir):
        self.rules_dir = rules_dir
        self.rules = None
        self.load_rules()

    def load_rules(self):
        rule_files = {}
        if not os.path.exists(self.rules_dir):
            os.makedirs(self.rules_dir)
            
        for root, _, files in os.walk(self.rules_dir):
            for file in files:
                if file.endswith(".yar") or file.endswith(".yara"):
                    rule_path = os.path.join(root, file)
                    # Use the filename as the namespace
                    namespace = os.path.splitext(file)[0]
                    rule_files[namespace] = rule_path

        if rule_files and _YARA_AVAILABLE:
            try:
                self.rules = yara.compile(filepaths=rule_files)
            except Exception as e:
                print(f"Error compiling YARA rules: {e}")
        elif rule_files and not _YARA_AVAILABLE:
            print("YARA library not available; skipping rule compilation.")
        else:
            print("No YARA rules found.")

    def scan(self, file_path):
        if not self.rules:
            return {
                "matches_count": 0,
                "matches": [],
                "info": "No YARA rules loaded"
            }

        matches = self.rules.match(file_path)
        matching_rules = []
        for match in matches:
            matching_rules.append({
                "rule": match.rule,
                "namespace": match.namespace,
                "tags": match.tags,
                "meta": match.meta
            })
        
        return {
            "matches_count": len(matching_rules),
            "matches": matching_rules
        }

"""
Guardian Detection Rules Engine
Loads YAML rules and evaluates events against them.
"""
import os
import yaml

RULES_DIR = os.path.join(os.path.dirname(__file__), "rules")

DEFAULT_RULES = [
    {
        "id": "PROC-001",
        "name": "Suspicious PowerShell",
        "description": "PowerShell with encoded command or download cradle",
        "severity": "high",
        "match": {"type": "process_new", "name": {"contains": "powershell"}},
        "pattern": ["-enc", "-e ", "bypass", "hidden", "downloadstring", "iex", "frombase64"],
    },
    {
        "id": "PROC-002",
        "name": "Known Attack Tool",
        "description": "Process name matches known adversarial tooling",
        "severity": "high",
        "match": {"type": "process_new"},
        "keywords": ["mimikatz", "lazagne", "bloodhound", "psexec", "crackmapexec",
                    "evil-winrm", "chisel", "ligolo", "ngrok"],
    },
    {
        "id": "PROC-003",
        "name": "File Download via CLI",
        "description": "Process making outbound file download using CLI tools",
        "severity": "medium",
        "match": {"type": "process_new", "name": {"in": ["curl", "wget", "certutil", "bitsadmin"]}},
    },
    {
        "id": "FILE-001",
        "name": "New File in Temp",
        "description": "New file created in temporary directory",
        "severity": "medium",
        "match": {"type": "file_new"},
        "paths": ["/tmp", "/var/tmp", "Downloads"],
    },
]


def load_rules():
    rules = []
    if os.path.isdir(RULES_DIR):
        for fname in sorted(os.listdir(RULES_DIR)):
            if fname.endswith((".yml", ".yaml")):
                with open(os.path.join(RULES_DIR, fname)) as f:
                    rules.extend(yaml.safe_load(f) or [])
    rules.extend(DEFAULT_RULES)
    return rules


def evaluate_events(events, rules=None):
    if rules is None:
        rules = load_rules()
    alerts = []
    for event in events:
        for rule in rules:
            if _matches(event, rule):
                alerts.append({
                    "rule_id": rule["id"],
                    "rule_name": rule["name"],
                    "severity": rule.get("severity", "medium"),
                    "event": event,
                    "time": event.get("time", ""),
                })
    return alerts


def _matches(event, rule):
    match = rule.get("match", {})
    for key, condition in match.items():
        val = event.get(key, "")
        if isinstance(condition, dict):
            if "contains" in condition and condition["contains"].lower() not in str(val).lower():
                return False
            if "in" in condition and str(val).lower() not in [s.lower() for s in condition["in"]]:
                return False
        elif val != condition:
            return False
    cmdline = (event.get("cmdline") or "").lower()
    for pattern in rule.get("pattern", []):
        if pattern.lower() in cmdline:
            return True
    name = (event.get("name") or "").lower()
    for kw in rule.get("keywords", []):
        if kw.lower() in name:
            return True
    if "paths" in rule:
        path = event.get("path", "")
        for p in rule["paths"]:
            if p.lower() in path.lower():
                return True
    return True

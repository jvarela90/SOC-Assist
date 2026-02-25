"""
SOC Assist — MITRE ATT&CK Mapping Service (#37)
Maps scoring modules and active hard rules to relevant ATT&CK techniques.
"""

# Technique catalog: id → {name, tactic, url}
_TECHNIQUES: dict[str, dict] = {
    # Initial Access
    "T1566":     {"name": "Phishing",                      "tactic": "Initial Access",   "color": "danger"},
    "T1566.001": {"name": "Spearphishing Attachment",       "tactic": "Initial Access",   "color": "danger"},
    "T1566.002": {"name": "Spearphishing Link",             "tactic": "Initial Access",   "color": "danger"},
    "T1190":     {"name": "Exploit Public-Facing App",      "tactic": "Initial Access",   "color": "danger"},
    "T1078":     {"name": "Valid Accounts",                 "tactic": "Initial Access",   "color": "warning"},
    "T1133":     {"name": "External Remote Services",       "tactic": "Initial Access",   "color": "warning"},
    # Execution
    "T1059":     {"name": "Command and Scripting Interpreter", "tactic": "Execution",     "color": "danger"},
    "T1059.001": {"name": "PowerShell",                     "tactic": "Execution",        "color": "danger"},
    "T1059.003": {"name": "Windows Command Shell",          "tactic": "Execution",        "color": "warning"},
    "T1204":     {"name": "User Execution",                 "tactic": "Execution",        "color": "warning"},
    # Persistence
    "T1053":     {"name": "Scheduled Task/Job",             "tactic": "Persistence",      "color": "warning"},
    "T1547":     {"name": "Boot/Logon Autostart Execution", "tactic": "Persistence",      "color": "warning"},
    "T1136":     {"name": "Create Account",                 "tactic": "Persistence",      "color": "warning"},
    # Privilege Escalation
    "T1068":     {"name": "Exploitation for Privilege Escalation", "tactic": "Privilege Escalation", "color": "danger"},
    "T1055":     {"name": "Process Injection",              "tactic": "Privilege Escalation", "color": "danger"},
    # Defense Evasion
    "T1036":     {"name": "Masquerading",                   "tactic": "Defense Evasion",  "color": "warning"},
    "T1562":     {"name": "Impair Defenses",                "tactic": "Defense Evasion",  "color": "danger"},
    "T1070":     {"name": "Indicator Removal",              "tactic": "Defense Evasion",  "color": "warning"},
    # Credential Access
    "T1003":     {"name": "OS Credential Dumping",          "tactic": "Credential Access","color": "danger"},
    "T1110":     {"name": "Brute Force",                    "tactic": "Credential Access","color": "warning"},
    "T1555":     {"name": "Credentials from Password Stores","tactic": "Credential Access","color": "danger"},
    # Discovery
    "T1082":     {"name": "System Information Discovery",   "tactic": "Discovery",        "color": "info"},
    "T1046":     {"name": "Network Service Scanning",       "tactic": "Discovery",        "color": "info"},
    "T1083":     {"name": "File and Directory Discovery",   "tactic": "Discovery",        "color": "info"},
    # Lateral Movement
    "T1021":     {"name": "Remote Services",                "tactic": "Lateral Movement", "color": "danger"},
    "T1021.001": {"name": "Remote Desktop Protocol",        "tactic": "Lateral Movement", "color": "danger"},
    "T1570":     {"name": "Lateral Tool Transfer",          "tactic": "Lateral Movement", "color": "warning"},
    # Collection
    "T1005":     {"name": "Data from Local System",         "tactic": "Collection",       "color": "warning"},
    "T1039":     {"name": "Data from Network Shared Drive", "tactic": "Collection",       "color": "warning"},
    "T1560":     {"name": "Archive Collected Data",         "tactic": "Collection",       "color": "warning"},
    # Exfiltration
    "T1048":     {"name": "Exfiltration Over Alt Protocol", "tactic": "Exfiltration",     "color": "danger"},
    "T1041":     {"name": "Exfiltration Over C2 Channel",   "tactic": "Exfiltration",     "color": "danger"},
    "T1567":     {"name": "Exfiltration to Web Service",    "tactic": "Exfiltration",     "color": "danger"},
    # Command and Control
    "T1071":     {"name": "Application Layer Protocol",     "tactic": "Command & Control","color": "warning"},
    "T1095":     {"name": "Non-Application Layer Protocol", "tactic": "Command & Control","color": "warning"},
    "T1572":     {"name": "Protocol Tunneling",             "tactic": "Command & Control","color": "danger"},
    # Impact
    "T1486":     {"name": "Data Encrypted for Impact",      "tactic": "Impact",           "color": "danger"},
    "T1490":     {"name": "Inhibit System Recovery",        "tactic": "Impact",           "color": "danger"},
    "T1485":     {"name": "Data Destruction",               "tactic": "Impact",           "color": "danger"},
    "T1489":     {"name": "Service Stop",                   "tactic": "Impact",           "color": "warning"},
    "T1498":     {"name": "Network Denial of Service",      "tactic": "Impact",           "color": "warning"},
}

# Map module IDs to relevant technique IDs (when module has significant score)
_MODULE_TECHNIQUES: dict[str, list[str]] = {
    "network":        ["T1071", "T1046", "T1095", "T1572", "T1498"],
    "endpoint":       ["T1059", "T1055", "T1082", "T1547", "T1036"],
    "identity":       ["T1078", "T1110", "T1003", "T1136", "T1555"],
    "malware":        ["T1059.001", "T1486", "T1055", "T1562", "T1490"],
    "data":           ["T1005", "T1039", "T1560", "T1048", "T1041"],
    "access":         ["T1133", "T1021", "T1021.001", "T1078", "T1190"],
    "lateral":        ["T1021", "T1570", "T1570", "T1039", "T1082"],
    "persistence":    ["T1053", "T1547", "T1136", "T1078"],
    "exfiltration":   ["T1048", "T1041", "T1567", "T1560"],
    "impact":         ["T1486", "T1485", "T1490", "T1489"],
    "email":          ["T1566", "T1566.001", "T1566.002", "T1204"],
}

# Map hard rule IDs to technique IDs (exact matches)
_RULE_TECHNIQUES: dict[str, list[str]] = {
    "ransomware_detected":    ["T1486", "T1490", "T1059", "T1562"],
    "data_exfil_confirmed":   ["T1048", "T1041", "T1567", "T1005"],
    "admin_compromise":       ["T1078", "T1003", "T1136", "T1055"],
    "lateral_movement":       ["T1021", "T1021.001", "T1570"],
    "malware_execution":      ["T1059", "T1204", "T1547", "T1055"],
    "credential_dump":        ["T1003", "T1555", "T1110"],
    "c2_communication":       ["T1071", "T1095", "T1572"],
}


def get_techniques_for_incident(
    module_scores: dict[str, float],
    hard_rule_id: str | None,
    min_module_score: float = 5.0,
) -> list[dict]:
    """
    Returns a deduplicated list of relevant ATT&CK techniques for an incident.
    Technique is included if:
      - Its module has score >= min_module_score, OR
      - The incident has a matching hard rule
    """
    seen: set[str] = set()
    result: list[dict] = []

    def _add(tech_id: str):
        if tech_id not in seen and tech_id in _TECHNIQUES:
            seen.add(tech_id)
            result.append({"id": tech_id, **_TECHNIQUES[tech_id]})

    # From hard rule (highest priority)
    if hard_rule_id:
        for rule_key, techs in _RULE_TECHNIQUES.items():
            if rule_key in (hard_rule_id or ""):
                for t in techs:
                    _add(t)

    # From significant modules
    for mod, score in (module_scores or {}).items():
        if score >= min_module_score:
            for t in _MODULE_TECHNIQUES.get(mod, []):
                _add(t)

    # Sort by tactic, then technique ID
    tactic_order = [
        "Initial Access", "Execution", "Persistence", "Privilege Escalation",
        "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
        "Collection", "Command & Control", "Exfiltration", "Impact",
    ]
    result.sort(key=lambda x: (
        tactic_order.index(x["tactic"]) if x["tactic"] in tactic_order else 99,
        x["id"]
    ))
    return result

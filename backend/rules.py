"""
Detection rules for Sysmon events.
Each rule returns a dict with alert metadata or None if the event does not match.
"""
from typing import Optional


RULES = []


def rule(fn):
    """Decorator to register a detection rule."""
    RULES.append(fn)
    return fn


# ---------------------------------------------------------------------------
# Sysmon Event ID reference:
#   1  – Process Create
#   3  – Network Connection
#   7  – Image Loaded (DLL)
#   8  – CreateRemoteThread
#   10 – ProcessAccess
#   11 – FileCreate
#   12/13/14 – Registry events
#   15 – FileCreateStreamHash (ADS)
#   22 – DNS Query
# ---------------------------------------------------------------------------


@rule
def detect_suspicious_powershell(event: dict) -> Optional[dict]:
    """Detect encoded or obfuscated PowerShell execution."""
    if event.get("event_id") != 1:
        return None
    cmd = (event.get("command_line") or "").lower()
    triggers = ["-enc", "-encodedcommand", "iex(", "invoke-expression", "downloadstring"]
    if any(t in cmd for t in triggers) and "powershell" in (event.get("process_name") or "").lower():
        return {
            "severity": "high",
            "rule_name": "Suspicious PowerShell Execution",
            "description": f"Encoded or obfuscated PowerShell detected: {event.get('command_line', '')[:200]}",
            "mitre_tactic": "Execution",
            "mitre_technique": "T1059.001",
        }
    return None


@rule
def detect_lsass_access(event: dict) -> Optional[dict]:
    """Detect credential dumping via LSASS access (Mimikatz style)."""
    if event.get("event_id") != 10:
        return None
    target = (event.get("target_image") or "").lower()
    if "lsass.exe" in target:
        return {
            "severity": "critical",
            "rule_name": "LSASS Memory Access",
            "description": "A process attempted to access LSASS memory – possible credential dumping.",
            "mitre_tactic": "Credential Access",
            "mitre_technique": "T1003.001",
        }
    return None


@rule
def detect_remote_thread_injection(event: dict) -> Optional[dict]:
    """Detect CreateRemoteThread – classic code injection indicator."""
    if event.get("event_id") != 8:
        return None
    return {
        "severity": "high",
        "rule_name": "Remote Thread Injection",
        "description": (
            f"CreateRemoteThread detected. Source: {event.get('source_image', 'unknown')} "
            f"→ Target: {event.get('target_image', 'unknown')}"
        ),
        "mitre_tactic": "Defense Evasion",
        "mitre_technique": "T1055.003",
    }


@rule
def detect_suspicious_network_connection(event: dict) -> Optional[dict]:
    """Flag outbound connections from suspicious processes."""
    if event.get("event_id") != 3:
        return None
    suspicious_procs = ["powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe"]
    proc = (event.get("process_name") or "").lower()
    if any(s in proc for s in suspicious_procs):
        return {
            "severity": "medium",
            "rule_name": "Suspicious Outbound Network Connection",
            "description": (
                f"Network connection from {event.get('process_name', 'unknown')} "
                f"to {event.get('dest_ip', 'unknown')}:{event.get('dest_port', '?')}"
            ),
            "mitre_tactic": "Command and Control",
            "mitre_technique": "T1071",
        }
    return None


@rule
def detect_ads_creation(event: dict) -> Optional[dict]:
    """Detect Alternate Data Stream (ADS) creation – common for hiding payloads."""
    if event.get("event_id") != 15:
        return None
    return {
        "severity": "medium",
        "rule_name": "Alternate Data Stream Created",
        "description": f"ADS file created: {event.get('target_filename', 'unknown')}",
        "mitre_tactic": "Defense Evasion",
        "mitre_technique": "T1564.004",
    }


def evaluate(event: dict) -> list[dict]:
    """Run all rules against a parsed event and return matching alerts."""
    alerts = []
    for rule_fn in RULES:
        result = rule_fn(event)
        if result:
            result["event_id"] = event.get("event_id")
            alerts.append(result)
    return alerts

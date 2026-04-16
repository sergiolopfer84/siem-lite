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


# ===========================================================================
# Windows Security Event Log rules
# Event IDs: 4624 (logon ok), 4625 (logon fail), 4648 (explicit creds),
#            4672 (special privileges), 4720 (user created), 4698 (sched task)
# ===========================================================================

@rule
def detect_failed_logon(event: dict) -> Optional[dict]:
    """Detect failed logon attempts (brute-force indicator)."""
    if event.get("event_id") != 4625:
        return None
    user = event.get("target_user", "unknown")
    ip = event.get("ip_address", "unknown")
    logon_type = event.get("logon_type", "")
    return {
        "severity": "medium",
        "rule_name": "Failed Logon Attempt",
        "description": (
            f"Failed logon for user '{user}' from {ip} "
            f"(Logon Type: {logon_type}). Possible brute-force."
        ),
        "mitre_tactic": "Credential Access",
        "mitre_technique": "T1110",
    }


@rule
def detect_explicit_credentials(event: dict) -> Optional[dict]:
    """Detect logon with explicit credentials – pass-the-hash or lateral movement."""
    if event.get("event_id") != 4648:
        return None
    subject = event.get("subject_user", "unknown")
    target = event.get("target_user", "unknown")
    return {
        "severity": "high",
        "rule_name": "Logon with Explicit Credentials",
        "description": (
            f"User '{subject}' used explicit credentials to log on as '{target}'. "
            "Possible pass-the-hash or lateral movement."
        ),
        "mitre_tactic": "Lateral Movement",
        "mitre_technique": "T1550.002",
    }


@rule
def detect_special_privileges(event: dict) -> Optional[dict]:
    """Detect assignment of sensitive privileges – possible privilege escalation."""
    if event.get("event_id") != 4672:
        return None
    sensitive = ["SeDebugPrivilege", "SeTcbPrivilege", "SeLoadDriverPrivilege",
                 "SeImpersonatePrivilege", "SeCreateTokenPrivilege"]
    privs = event.get("privilege_list", "")
    matched = [p for p in sensitive if p in privs]
    if not matched:
        return None
    user = event.get("subject_user", "unknown")
    return {
        "severity": "high",
        "rule_name": "Sensitive Privileges Assigned",
        "description": (
            f"User '{user}' was assigned sensitive privileges: {', '.join(matched)}. "
            "May indicate privilege escalation."
        ),
        "mitre_tactic": "Privilege Escalation",
        "mitre_technique": "T1134",
    }


@rule
def detect_new_user_created(event: dict) -> Optional[dict]:
    """Detect creation of a new local user account – persistence tactic."""
    if event.get("event_id") != 4720:
        return None
    new_user = event.get("target_user", "unknown")
    creator = event.get("subject_user", "unknown")
    return {
        "severity": "high",
        "rule_name": "New Local User Account Created",
        "description": (
            f"New user account '{new_user}' created by '{creator}'. "
            "Could indicate attacker persistence."
        ),
        "mitre_tactic": "Persistence",
        "mitre_technique": "T1136.001",
    }


@rule
def detect_scheduled_task_created(event: dict) -> Optional[dict]:
    """Detect scheduled task creation – common persistence/execution mechanism."""
    if event.get("event_id") != 4698:
        return None
    task = event.get("task_name", "unknown")
    user = event.get("subject_user", "unknown")
    return {
        "severity": "medium",
        "rule_name": "Scheduled Task Created",
        "description": (
            f"Scheduled task '{task}' created by '{user}'. "
            "Review if this task is expected."
        ),
        "mitre_tactic": "Persistence",
        "mitre_technique": "T1053.005",
    }


# ===========================================================================
# PowerShell Operational Log rules
# Event IDs: 4103 (module logging), 4104 (script block logging)
# ===========================================================================

@rule
def detect_powershell_script_block(event: dict) -> Optional[dict]:
    """Detect suspicious PowerShell script blocks (Event ID 4104)."""
    if event.get("event_id") != 4104:
        return None
    block = (event.get("script_block_text") or "").lower()
    triggers = [
        "invoke-expression", "iex(", "-encodedcommand", "downloadstring",
        "net.webclient", "invoke-webrequest", "bypass", "hidden",
        "frombase64string", "system.reflection.assembly",
    ]
    matched = [t for t in triggers if t in block]
    if not matched:
        return None
    path = event.get("script_path") or "interactive"
    return {
        "severity": "high",
        "rule_name": "Suspicious PowerShell Script Block",
        "description": (
            f"Script block logged from '{path}' contains suspicious patterns: "
            f"{', '.join(matched[:3])}."
        ),
        "mitre_tactic": "Execution",
        "mitre_technique": "T1059.001",
    }


@rule
def detect_powershell_downloader(event: dict) -> Optional[dict]:
    """Detect PowerShell downloading payloads (module logging, Event ID 4103)."""
    if event.get("event_id") != 4103:
        return None
    payload = (event.get("payload") or "").lower()
    download_indicators = ["downloadstring", "downloadfile", "invoke-webrequest", "webclient"]
    if any(d in payload for d in download_indicators):
        return {
            "severity": "high",
            "rule_name": "PowerShell Download Activity",
            "description": "PowerShell module log shows download activity – possible payload staging.",
            "mitre_tactic": "Command and Control",
            "mitre_technique": "T1105",
        }
    return None


def evaluate(event: dict) -> list[dict]:
    """Run all rules against a parsed event and return matching alerts."""
    alerts = []
    for rule_fn in RULES:
        result = rule_fn(event)
        if result:
            result["event_id"] = event.get("event_id")
            alerts.append(result)
    return alerts

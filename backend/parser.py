"""
EVTX parser – converts Windows Event Log (.evtx) files into normalised dicts
using the python-evtx library.
"""
import xml.etree.ElementTree as ET
from typing import Generator
from pathlib import Path

try:
    import Evtx.Evtx as evtx
    import Evtx.Views as e_views
    EVTX_AVAILABLE = True
except ImportError:
    EVTX_AVAILABLE = False

# XML namespace used by Windows Event Log
NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"


def _ns(tag: str) -> str:
    return f"{NS}{tag}"


def _parse_record_xml(xml_str: str) -> dict:
    """Parse a single EVTX record XML string into a normalised dict."""
    try:
        root = ET.fromstring(xml_str)
    except ET.ParseError:
        return {}

    system = root.find(_ns("System"))
    if system is None:
        return {}

    def sys_text(tag: str) -> str:
        el = system.find(_ns(tag))
        return el.text.strip() if el is not None and el.text else ""

    def sys_attr(tag: str, attr: str) -> str:
        el = system.find(_ns(tag))
        return el.attrib.get(attr, "") if el is not None else ""

    event_data = root.find(_ns("EventData"))
    data: dict[str, str] = {}
    if event_data is not None:
        for item in event_data.findall(_ns("Data")):
            name = item.attrib.get("Name", "")
            value = item.text or ""
            if name:
                data[name] = value

    event = {
        "event_id": int(sys_attr("EventID", "") or sys_text("EventID") or 0),
        "timestamp": sys_text("TimeCreated") or sys_attr("TimeCreated", "SystemTime"),
        "source": sys_attr("Provider", "Name"),
        "channel": sys_text("Channel"),
        "computer": sys_text("Computer"),
        "user": sys_attr("Security", "UserID"),
        # Sysmon-specific fields (present only in relevant Event IDs)
        "process_name": data.get("Image", ""),
        "command_line": data.get("CommandLine", ""),
        "parent_process": data.get("ParentImage", ""),
        "dest_ip": data.get("DestinationIp", ""),
        "dest_port": data.get("DestinationPort", ""),
        "target_image": data.get("TargetImage", ""),
        "source_image": data.get("SourceImage", ""),
        "target_filename": data.get("TargetFilename", ""),
        "hashes": data.get("Hashes", ""),
        # Windows Security Log fields
        "subject_user": data.get("SubjectUserName", ""),
        "target_user": data.get("TargetUserName", ""),
        "logon_type": data.get("LogonType", ""),
        "logon_process": data.get("LogonProcessName", ""),
        "workstation": data.get("WorkstationName", ""),
        "ip_address": data.get("IpAddress", ""),
        "failure_reason": data.get("FailureReason", ""),
        "privilege_list": data.get("PrivilegeList", ""),
        "new_process": data.get("NewProcessName", ""),
        "task_name": data.get("TaskName", ""),
        "task_content": data.get("TaskContent", ""),
        # PowerShell Operational fields
        "script_block_text": data.get("ScriptBlockText", ""),
        "script_path": data.get("Path", ""),
        "payload": data.get("Payload", ""),
        "raw_xml": xml_str,
    }
    return event


def parse_evtx_file(file_path: str | Path) -> Generator[dict, None, None]:
    """
    Yield normalised event dicts from an .evtx file.
    Requires python-evtx to be installed.
    """
    if not EVTX_AVAILABLE:
        raise RuntimeError(
            "python-evtx is not installed. Run: pip install python-evtx"
        )

    with evtx.Evtx(str(file_path)) as log:
        for record in log.records():
            try:
                xml_str = record.xml()
                event = _parse_record_xml(xml_str)
                if event:
                    yield event
            except Exception:
                continue


def parse_xml_string(xml_str: str) -> dict:
    """Parse a raw XML string (e.g. from a test fixture) into an event dict."""
    return _parse_record_xml(xml_str)

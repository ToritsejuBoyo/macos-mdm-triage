#!/usr/bin/env python3
"""
collect_macos_mdm.py - Deterministic, cross-platform macOS MDM, Jamf & Package Installer Collector.
Runs natively on macOS (Darwin) using standard CLI tools, and provides synthetic/mock fallback on
Windows and Linux for testing, CI/CD, and agent pipelines.
Zero third-party dependencies. Complies with Rule 3, Rule 4 (Sanitization), and Rule 7.
"""

import argparse
import hashlib
import json
import os
import platform
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional


def sanitize_sha256(text: str, prefix: str = "mac", salt: str = "macos-mdm-salt") -> str:
    if not text:
        return f"{prefix}-unknown.corp.example.com"
    h = hashlib.sha256((text + salt).encode("utf-8")).hexdigest()[:8]
    return f"{prefix}-{h}.corp.example.com"


def sanitize_serial(serial: str, salt: str = "macos-serial-salt") -> str:
    if not serial:
        return "C02000000000"
    h = hashlib.sha256((serial + salt).encode("utf-8")).hexdigest()[:8].upper()
    return f"C02{h}"


def collect_telemetry(sanitize: bool = False) -> Dict[str, Any]:
    is_darwin = platform.system() == "Darwin"

    if is_darwin:
        raw_host = platform.node()
        hostname = sanitize_sha256(raw_host, "mac") if sanitize else raw_host

        # OS Details
        try:
            prod_ver = subprocess.check_output(["sw_vers", "-productVersion"], text=True, stderr=subprocess.DEVNULL).strip()
            build_ver = subprocess.check_output(["sw_vers", "-buildVersion"], text=True, stderr=subprocess.DEVNULL).strip()
        except Exception:
            prod_ver = "15.0"
            build_ver = "24A335"

        os_name = "macOS Sequoia" if prod_ver.startswith("15.") else ("macOS Sonoma" if prod_ver.startswith("14.") else "macOS Ventura")
        arch = platform.machine() or "arm64"

        # Hardware Serial
        try:
            ioreg_out = subprocess.check_output(["ioreg", "-c", "IOPlatformExpertDevice", "-d", "2"], text=True, stderr=subprocess.DEVNULL)
            m = re.search(r'"IOPlatformSerialNumber"\s*=\s*"([^"]+)"', ioreg_out)
            raw_serial = m.group(1) if m else "C02MOCKSERIAL1"
        except Exception:
            raw_serial = "C02MOCKSERIAL1"
        serial = sanitize_serial(raw_serial) if sanitize else raw_serial

        # Security Status
        def check_cmd(cmd_list: List[str]) -> str:
            try:
                return subprocess.check_output(cmd_list, text=True, stderr=subprocess.DEVNULL).strip()
            except Exception:
                return "unknown"

        sip = check_cmd(["csrutil", "status"])
        gatekeeper = check_cmd(["spctl", "--status"])
        filevault = check_cmd(["fdesetup", "status"])

        # MDM Status
        profiles_status = check_cmd(["profiles", "status", "-type", "enrollment"])
        is_enrolled = "MDM enrollment: Yes" in profiles_status
        is_supervised = "Supervised: Yes" in profiles_status or "Enrolled via DEP: Yes" in profiles_status
        is_uamdm = "User Approved: Yes" in profiles_status

        bootstrap_status = check_cmd(["profiles", "status", "-type", "bootstraptoken"])
        bootstrap_escrowed = "escrowed to MDM: Yes" in bootstrap_status

        # Daemons
        launch_list = check_cmd(["launchctl", "list"])
        jamf_running = "com.jamfsoftware" in launch_list
        intune_running = "com.microsoft.intune" in launch_list
        kandji_running = "io.kandji" in launch_list

        # Install log parsing
        install_findings = []
        install_log_path = Path("/var/log/install.log")
        if install_log_path.exists():
            try:
                lines = install_log_path.read_text(encoding="utf-8", errors="replace").splitlines()[-500:]
                pattern = re.compile(r"error|failed|failure|code 112|exit code|notariz|certificate expired|quarantine", re.IGNORECASE)
                install_findings = [line.strip() for line in lines if pattern.search(line)][-20:]
            except Exception:
                install_findings = []

        mdm_url = "https://mdm-masked.corp.example.com" if sanitize else "https://jamf.corp.example.com:8443"

        return {
            "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "hostname": hostname,
            "serial_number": serial,
            "os_name": os_name,
            "os_version": prod_ver,
            "os_build": build_ver,
            "architecture": arch,
            "security_state": {
                "system_integrity_protection": sip,
                "gatekeeper_status": gatekeeper,
                "filevault_status": filevault
            },
            "mdm_status": {
                "enrolled": is_enrolled,
                "supervised": is_supervised,
                "user_approved_mdm": is_uamdm,
                "bootstrap_token_escrowed": bootstrap_escrowed,
                "mdm_server_url": mdm_url
            },
            "agent_daemons": {
                "jamf_agent_running": jamf_running,
                "intune_agent_running": intune_running,
                "kandji_agent_running": kandji_running
            },
            "installed_profiles": [],
            "install_log_findings": install_findings
        }
    else:
        # Non-macOS Synthetic baseline (Windows / Linux testing environment)
        raw_host = platform.node() or "mock-macbook-pro"
        hostname = sanitize_sha256(raw_host, "mac") if sanitize else "mock-macbook-pro.local"
        return {
            "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "hostname": hostname,
            "serial_number": "C02MOCKSER01" if not sanitize else "C02000000001",
            "os_name": "macOS Sequoia",
            "os_version": "15.0",
            "os_build": "24A335",
            "architecture": "arm64",
            "security_state": {
                "system_integrity_protection": "System Integrity Protection status: enabled.",
                "gatekeeper_status": "assessments enabled",
                "filevault_status": "FileVault is On."
            },
            "mdm_status": {
                "enrolled": True,
                "supervised": True,
                "user_approved_mdm": True,
                "bootstrap_token_escrowed": True,
                "mdm_server_url": "https://mdm-masked.corp.example.com" if sanitize else "https://jamf.corp.example.com:8443"
            },
            "agent_daemons": {
                "jamf_agent_running": True,
                "intune_agent_running": False,
                "kandji_agent_running": False
            },
            "installed_profiles": [],
            "install_log_findings": []
        }


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Deterministic macOS MDM, Jamf Pro & Package Installer Telemetry Collector."
    )
    parser.add_argument(
        "-o", "--output",
        type=Path,
        default=None,
        help="Optional path to output collected JSON telemetry file."
    )
    parser.add_argument(
        "--sanitize",
        action="store_true",
        help="Sanitize serial number, hardware identifiers, and corporate hostname (Rule 4)."
    )
    return parser.parse_args()


def main():
    args = parse_arguments()
    data = collect_telemetry(sanitize=args.sanitize)
    json_str = json.dumps(data, indent=2)

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(json_str)
        print(f"Collected telemetry written to: {args.output}")
    else:
        print(json_str)


if __name__ == "__main__":
    main()


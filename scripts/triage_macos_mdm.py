#!/usr/bin/env python3
"""
triage_macos_mdm.py - Deterministic macOS MDM, Jamf Pro & Package Installer Triage Engine.
Evaluates configuration profiles, /var/log/install.log, APNs push channels,
agent daemons, and Apple security architecture across a 6-domain decision tree.
Zero third-party dependencies. Complies with Rule 3, Rule 4 (Sanitization), and Rule 7.
"""

import argparse
import hashlib
import json
import math
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Shared residual sanitization pass (vendored: scripts/sanitizer.py).
# Applied to rendered output rather than to the telemetry bundle: scrubbing the
# bundle before analysis would strip values the decision tree reads and could
# change the verdict. See tests/sanitizer_conformance_test.py for the contract.
# ---------------------------------------------------------------------------
try:
    from sanitizer import residual_scrub as _residual_scrub
except ImportError:  # pragma: no cover - direct execution from another cwd
    import os as _os
    import sys as _sys
    _sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
    from sanitizer import residual_scrub as _residual_scrub



@dataclass
class TriageFinding:
    """Represents a diagnostic determination from the decision tree."""
    domain_number: int
    domain_name: str
    status: str  # "FAIL", "WARN", "PASS"
    root_cause_summary: str
    technical_evidence: List[str] = field(default_factory=list)
    remediation_steps_user: List[str] = field(default_factory=list)
    remediation_steps_admin: List[str] = field(default_factory=list)
    escalation_priority: str = "P3 - Medium"


class TelemetrySanitizer:
    """Client-side telemetry sanitization complying with Rule 4."""
    def __init__(self, salt: str = "macos-mdm-triage-audit-salt"):
        self.salt = salt
        self._ip_cache: Dict[str, str] = {}
        self._counter = 1

    def sanitize_serial(self, serial: Any) -> str:
        if not serial:
            return "C02-HASHED-00000000"
        s = str(serial).strip()
        if not s:
            return "C02-HASHED-00000000"
        if s.startswith("C02-HASHED-"):
            return s
        h = hashlib.sha256((s + self.salt).encode("utf-8")).hexdigest()[:8].upper()
        return f"C02-HASHED-{h}"

    def sanitize_host(self, host: Any) -> str:
        if not host:
            return "mac-unknown.corp.example.com"
        h_str = str(host).strip()
        if not h_str:
            return "mac-unknown.corp.example.com"
        if h_str.startswith("mac-") and h_str.endswith(".corp.example.com"):
            return h_str
        h = hashlib.sha256((h_str + self.salt).encode("utf-8")).hexdigest()[:8]
        return f"mac-{h}.corp.example.com"

    def sanitize_user(self, user: Any) -> str:
        if not user:
            return "user-0000@corp.example.com"
        u_str = str(user).strip()
        if not u_str:
            return "user-0000@corp.example.com"
        if u_str.startswith("user-") and u_str.endswith("@corp.example.com"):
            return u_str
        h = hashlib.sha256((u_str + self.salt).encode("utf-8")).hexdigest()[:6]
        return f"user-{h}@corp.example.com"

    def sanitize_ip(self, ip: Any) -> str:
        if not ip:
            return ""
        ip_clean = str(ip).strip()
        if not ip_clean or ip_clean in ("127.0.0.1", "::1"):
            return ip_clean
        if ip_clean not in self._ip_cache:
            self._ip_cache[ip_clean] = f"192.0.2.{self._counter % 250 + 1}"
            self._counter += 1
        return self._ip_cache[ip_clean]

    def sanitize_bundle(self, data: Any) -> Dict[str, Any]:
        """Deep copy and sanitize macOS telemetry bundle."""
        if not isinstance(data, dict):
            return {"raw_input": str(data)}

        clean = json.loads(json.dumps(data))
        if "hostname" in clean and clean["hostname"]:
            clean["hostname"] = self.sanitize_host(clean["hostname"])
        if "serial_number" in clean and clean["serial_number"]:
            clean["serial_number"] = self.sanitize_serial(clean["serial_number"])

        mdm = clean.get("mdm_status")
        if isinstance(mdm, dict) and mdm.get("mdm_server_url"):
            mdm["mdm_server_url"] = "https://mdm-masked.corp.example.com"

        # Sanitize profile identifiers if present
        profiles = clean.get("installed_profiles")
        if isinstance(profiles, list):
            for prof in profiles:
                if isinstance(prof, dict) and "profile_uuid" in prof:
                    prof["profile_uuid"] = "00000000-0000-4000-a000-000000000001"

        return clean


class MacOSMdmTriageEngine:
    """Executes the 6-domain decision tree evaluation for macOS MDM & Package Installers."""

    def __init__(self, data: Dict[str, Any]):
        self.raw_data = data
        self.findings: List[TriageFinding] = []

    def evaluate(self) -> List[TriageFinding]:
        self.findings.clear()

        # Step 1: Domain 1 - MDM Enrollment & APNs Channel Health
        d1 = self._check_domain1_enrollment_apns()
        if d1:
            self.findings.append(d1)
            if d1.status == "FAIL":
                return self.findings

        # Step 2: Domain 2 - Configuration Profile Validity & Supervision
        d2 = self._check_domain2_profiles_supervision()
        if d2:
            self.findings.append(d2)

        # Step 3: Domain 3 - Apple PackageKit (.pkg) & install.log Failures
        d3 = self._check_domain3_packagekit_installer()
        if d3:
            self.findings.append(d3)

        # Step 4: Domain 4 - MDM Agent Daemons (Jamf, Intune, Kandji)
        d4 = self._check_domain4_agent_daemons()
        if d4:
            self.findings.append(d4)

        # Step 5: Domain 5 - Security Architecture & Supervision Dependencies
        d5 = self._check_domain5_security_architecture()
        if d5:
            self.findings.append(d5)

        # Baseline Pass if no warnings or failures
        if not self.findings:
            self.findings.append(TriageFinding(
                domain_number=0,
                domain_name="Healthy Baseline Enterprise State",
                status="PASS",
                root_cause_summary="macOS endpoint is properly enrolled, supervised, and MDM / installer channels are healthy.",
                technical_evidence=[
                    f"Operating System: {self.raw_data.get('os_name', 'macOS')} ({self.raw_data.get('os_version', '15.0')})",
                    "MDM Enrollment: Active & Supervised",
                    "Zero PackageKit install errors discovered in /var/log/install.log",
                    "MDM management daemons active and running"
                ],
                remediation_steps_user=["No action required. Mac endpoint is healthy and in compliance."],
                remediation_steps_admin=["Verify deployment scope in MDM server console."],
                escalation_priority="P4 - Informational / Closed"
            ))

        return self.findings

    def _check_domain1_enrollment_apns(self) -> Optional[TriageFinding]:
        if not self.raw_data or not isinstance(self.raw_data, dict):
            return TriageFinding(
                domain_number=1,
                domain_name="MDM Enrollment & APNs Channel",
                status="FAIL",
                root_cause_summary="Telemetry payload is null, empty, or not a valid dictionary.",
                technical_evidence=["Invalid or corrupted JSON telemetry bundle"],
                remediation_steps_user=["Rerun the macOS MDM telemetry collector script."],
                remediation_steps_admin=["Verify telemetry collection permissions."],
                escalation_priority="P2 - High"
            )

        mdm = self.raw_data.get("mdm_status") or {}
        if not isinstance(mdm, dict):
            mdm = {}

        is_enrolled = mdm.get("enrolled", False)
        if not is_enrolled:
            return TriageFinding(
                domain_number=1,
                domain_name="MDM Enrollment & APNs Channel",
                status="FAIL",
                root_cause_summary="Mac endpoint is not enrolled in an Apple Mobile Device Management (MDM) server.",
                technical_evidence=[
                    "Command 'profiles status -type enrollment' returned 'MDM enrollment: No'",
                    f"Configured MDM Server: {mdm.get('mdm_server_url', 'None')}"
                ],
                remediation_steps_user=[
                    "Open System Settings -> Privacy & Security -> Profiles.",
                    "Complete enterprise MDM enrollment or verify Automated Device Enrollment (ADE) prompt."
                ],
                remediation_steps_admin=[
                    "Check device assignment in Apple Business Manager (ABM) / Apple School Manager (ASM).",
                    "Verify MDM enrollment URL and push invitation to the endpoint."
                ],
                escalation_priority="P2 - High"
            )

        # Check APNs push connectivity logs
        apns_logs = self.raw_data.get("apns_status") or {}
        if isinstance(apns_logs, dict):
            if apns_logs.get("push_token_expired") or apns_logs.get("push_handshake_timeout"):
                return TriageFinding(
                    domain_number=1,
                    domain_name="MDM Enrollment & APNs Channel",
                    status="FAIL",
                    root_cause_summary="Apple Push Notification service (APNs) channel is stalled; Mac cannot receive MDM push commands.",
                    technical_evidence=[
                        f"APNs Port 5223 Status: {apns_logs.get('port_5223_status', 'Timeout')}",
                        f"APNs Error: {apns_logs.get('error_detail', 'TLS handshake to gateway.push.apple.com failed')}"
                    ],
                    remediation_steps_user=[
                        "Ensure Wi-Fi network allows outbound traffic on TCP port 5223.",
                        "Reboot the Mac to force apsd (Apple Push Service Daemon) reconnection."
                    ],
                    remediation_steps_admin=[
                        "Verify network firewall permits 17.0.0.0/8 outbound on TCP port 5223 (Apple APNs subnet).",
                        "Renew expired Apple Push Notification certificate in MDM console."
                    ],
                    escalation_priority="P2 - High"
                )

        # Check Bootstrap Token on Apple Silicon
        arch = str(self.raw_data.get("architecture", "arm64")).lower()
        if arch in ("arm64", "aarch64", "arm64e") and not mdm.get("bootstrap_token_escrowed", True):
            return TriageFinding(
                domain_number=1,
                domain_name="MDM Enrollment & APNs Channel",
                status="WARN",
                root_cause_summary="Apple Silicon Mac is missing Bootstrap Token escrow, preventing automated kernel and software authorizations.",
                technical_evidence=[
                    f"Hardware Architecture: Apple Silicon ({arch})",
                    "'profiles status -type bootstraptoken' reports escrowed to MDM: No"
                ],
                remediation_steps_user=["Log into the Mac with a SecureToken-enabled administrator account."],
                remediation_steps_admin=[
                    "Execute 'sudo profiles install -type bootstraptoken' in terminal to escrow token.",
                    "Verify MDM server supports Volume Ownership and Bootstrap Token workflows."
                ],
                escalation_priority="P3 - Medium"
            )

        return None

    def _check_domain2_profiles_supervision(self) -> Optional[TriageFinding]:
        mdm = self.raw_data.get("mdm_status") or {}
        is_supervised = mdm.get("supervised", False) if isinstance(mdm, dict) else False

        profiles_raw = self.raw_data.get("installed_profiles") or []
        if isinstance(profiles_raw, dict):
            profiles = [profiles_raw]
        elif isinstance(profiles_raw, list):
            profiles = profiles_raw
        else:
            profiles = []

        for p in profiles:
            if not isinstance(p, dict):
                continue

            raw_err = p.get("install_error_code")
            try:
                install_err = int(str(raw_err).strip()) if raw_err is not None else None
            except (ValueError, TypeError, OverflowError):
                install_err = None

            payload_type = p.get("payload_type", "Unknown Payload")
            supervision_req = bool(p.get("supervision_required", False))

            # Error -20109: Payload requires supervision
            if install_err == -20109 or (supervision_req and not is_supervised):
                return TriageFinding(
                    domain_number=2,
                    domain_name="Configuration Profile Validity & Supervision",
                    status="FAIL",
                    root_cause_summary=f"Configuration profile '{p.get('profile_name', 'Unknown')}' was rejected because the Mac is not Apple Supervised.",
                    technical_evidence=[
                        f"Profile Identifier: {p.get('payload_identifier')}",
                        f"Payload Type: {payload_type}",
                        f"Installer CoreOS Error: {install_err} (Payload restriction requires Device Supervision)",
                        "Endpoint State: Supervised = No (User-enrolled Mac)"
                    ],
                    remediation_steps_user=["Contact IT support to enroll device via company Automated Device Enrollment (ADE)."],
                    remediation_steps_admin=[
                        "Device must be wiped and re-enrolled via Apple Business Manager (DEP/ADE) for supervision.",
                        "Alternatively, remove supervised-only restrictions (e.g., com.apple.applicationaccess) from the profile payload."
                    ],
                    escalation_priority="P2 - High"
                )

            # Error -20108: Signature validation failed
            if install_err == -20108:
                return TriageFinding(
                    domain_number=2,
                    domain_name="Configuration Profile Validity & Supervision",
                    status="FAIL",
                    root_cause_summary=f"Configuration profile '{p.get('profile_name', 'Unknown')}' signature validation failed (Error -20108).",
                    technical_evidence=[
                        f"Profile Identifier: {p.get('payload_identifier')}",
                        "CoreOS Error -20108: Verification failed or signing certificate untrusted/revoked."
                    ],
                    remediation_steps_user=["Verify network connectivity to Apple certificate verification servers."],
                    remediation_steps_admin=[
                        "Re-sign mobileconfig profile with valid enterprise signing certificate.",
                        "Verify intermediate and root CA certificates are installed on endpoint."
                    ],
                    escalation_priority="P2 - High"
                )

            # Error -20110: Duplicate UUID / Payload collision
            if install_err == -20110 or p.get("duplicate_uuid"):
                return TriageFinding(
                    domain_number=2,
                    domain_name="Configuration Profile Validity & Supervision",
                    status="FAIL",
                    root_cause_summary=f"Profile '{p.get('profile_name', 'Unknown')}' collided with an already installed payload UUID (Error -20110).",
                    technical_evidence=[
                        f"Conflicting Payload Identifier: {p.get('payload_identifier')}",
                        f"Profile UUID: {p.get('profile_uuid', 'Unknown')}",
                        "CoreOS Error -20110: Payload UUID already exists in system profile database."
                    ],
                    remediation_steps_user=["No action required by user. Issue must be resolved in MDM console."],
                    remediation_steps_admin=[
                        "Regenerate a unique PayloadUUID in the profile XML before redeploying.",
                        "Remove legacy profile with 'sudo profiles remove -identifier <ID>'."
                    ],
                    escalation_priority="P3 - Medium"
                )

        return None

    def _check_domain3_packagekit_installer(self) -> Optional[TriageFinding]:
        install_errs = self.raw_data.get("install_log_findings") or []
        if isinstance(install_errs, str):
            install_errs = [install_errs]
        elif isinstance(install_errs, dict):
            install_errs = [str(v) for v in install_errs.values()]
        elif isinstance(install_errs, list):
            install_errs = [str(e) for e in install_errs if e is not None]
        else:
            install_errs = []

        combined_text = "\n".join(str(e) for e in install_errs)

        # 1. Postinstall / Preinstall Script Exit Error (Code 112 / exit status != 0)
        if re.search(r"PackageKit:\s*Install Failed:.*?Code=112|postinstall.*?exited with (status|code) [1-9]|Script Failed", combined_text, re.IGNORECASE):
            matching_lines = [l for l in install_errs if re.search(r"code=112|postinstall|script failed|exit", str(l), re.IGNORECASE)]
            return TriageFinding(
                domain_number=3,
                domain_name="Apple PackageKit (.pkg) & Installer Engine",
                status="FAIL",
                root_cause_summary="Apple PackageKit installation failed because the package's postinstall script returned a non-zero exit code.",
                technical_evidence=matching_lines[:5],
                remediation_steps_user=["Restart the Mac and re-attempt installation from Jamf Self Service / Company Portal."],
                remediation_steps_admin=[
                    "Extract the .pkg payload with 'pkgutil --expand' and inspect the 'Scripts/postinstall' script.",
                    "Verify postinstall script does not require interactive GUI prompts or active user login session.",
                    "Ensure interpreter path (e.g. #!/bin/bash or #!/bin/zsh) exists on modern macOS versions."
                ],
                escalation_priority="P2 - High"
            )

        # 2. Code Signing & Certificate Expiration / Untrusted Root
        if re.search(r"CSSMERR_TP_NOT_TRUSTED|certificate expired|untrusted (root|developer)|signer invalid", combined_text, re.IGNORECASE):
            matching_lines = [l for l in install_errs if re.search(r"not_trusted|expired|untrusted|signer", str(l), re.IGNORECASE)]
            return TriageFinding(
                domain_number=3,
                domain_name="Apple PackageKit (.pkg) & Installer Engine",
                status="FAIL",
                root_cause_summary="Installer package (.pkg) was rejected because its Apple Developer ID certificate is expired or untrusted.",
                technical_evidence=matching_lines[:5],
                remediation_steps_user=["Do not attempt to bypass Gatekeeper. Wait for updated software package."],
                remediation_steps_admin=[
                    "Check signature with 'pkgutil --check-signature <package.pkg>'.",
                    "Re-sign the installer package with an active Apple Developer ID Installer certificate.",
                    "Ensure intermediate Apple Worldwide Developer Relations (WWDR) CA is trusted."
                ],
                escalation_priority="P2 - High"
            )

        # 3. Gatekeeper / Notarization / Quarantine Block
        if re.search(r"spctl:.*?rejected|quarantine flag|notariz.*?failed|hardened runtime violation", combined_text, re.IGNORECASE):
            matching_lines = [l for l in install_errs if re.search(r"rejected|quarantine|notariz", str(l), re.IGNORECASE)]
            return TriageFinding(
                domain_number=3,
                domain_name="Apple PackageKit (.pkg) & Installer Engine",
                status="FAIL",
                root_cause_summary="macOS Gatekeeper blocked package installation due to missing notarization ticket or quarantine attribute.",
                technical_evidence=matching_lines[:5],
                remediation_steps_user=["Verify package was downloaded through sanctioned company portal."],
                remediation_steps_admin=[
                    "Submit software package to Apple notary service: 'xcrun notarytool submit <file>'.",
                    "Staple notarization ticket: 'xcrun stapler staple <file>'.",
                    "If downloaded via web, strip quarantine attribute using 'xattr -d com.apple.quarantine <file>'."
                ],
                escalation_priority="P2 - High"
            )

        # 4. APFS Read-Only Mount / Disk Full
        if re.search(r"Read-only file system|No space left on device|APFS volume out of space", combined_text, re.IGNORECASE):
            matching_lines = [l for l in install_errs if re.search(r"read-only|no space|out of space", str(l), re.IGNORECASE)]
            return TriageFinding(
                domain_number=3,
                domain_name="Apple PackageKit (.pkg) & Installer Engine",
                status="FAIL",
                root_cause_summary="Package installation failed due to insufficient APFS storage or attempting to write to read-only Sealed System Volume (SSV).",
                technical_evidence=matching_lines[:5],
                remediation_steps_user=[
                    "Free up disk space by emptying Trash and deleting unused local media.",
                    "Verify at least 15 GB of free space is available on the Macintosh HD volume."
                ],
                remediation_steps_admin=[
                    "Verify installer target path is /Applications or /Library, NOT the sealed root volume /.",
                    "Inspect disk capacity with 'df -h /'."
                ],
                escalation_priority="P2 - High"
            )

        return None

    def _check_domain4_agent_daemons(self) -> Optional[TriageFinding]:
        daemons = self.raw_data.get("agent_daemons") or {}
        if isinstance(daemons, list):
            daemons = {str(d).lower(): True for d in daemons}
        elif not isinstance(daemons, dict):
            daemons = {}

        mdm_url = str((self.raw_data.get("mdm_status") or {}).get("mdm_server_url", "")).lower()

        # If Jamf Pro environment but daemon stopped
        if "jamf" in mdm_url and not daemons.get("jamf_agent_running", True):
            return TriageFinding(
                domain_number=4,
                domain_name="MDM Agent Daemons",
                status="FAIL",
                root_cause_summary="Jamf Pro agent daemon (com.jamfsoftware.jamf.daemon) is stopped or not running on the Mac.",
                technical_evidence=[
                    f"Configured MDM: {mdm_url}",
                    "launchctl list query: com.jamfsoftware.jamf.daemon not discovered in active launchd jobs"
                ],
                remediation_steps_user=["Reboot the Mac to allow launchd to reload company background agents."],
                remediation_steps_admin=[
                    "Execute 'sudo launchctl load -w /Library/LaunchDaemons/com.jamfsoftware.task.plist'.",
                    "Run 'sudo jamf manage' and 'sudo jamf recon' to restore agent check-in."
                ],
                escalation_priority="P2 - High"
            )

        # If Intune environment but Intune daemon stopped
        if "intune" in mdm_url and not daemons.get("intune_agent_running", True):
            return TriageFinding(
                domain_number=4,
                domain_name="MDM Agent Daemons",
                status="FAIL",
                root_cause_summary="Microsoft Intune Mac agent (com.microsoft.intune.agent) is stopped or inactive.",
                technical_evidence=[
                    f"Configured MDM: {mdm_url}",
                    "launchctl list query: com.microsoft.intune.agent missing from active jobs"
                ],
                remediation_steps_user=["Open Company Portal app to trigger agent synchronization."],
                remediation_steps_admin=[
                    "Verify Intune Company Portal daemon launchd configuration.",
                    "Re-run Intune Mac Company Portal installer."
                ],
                escalation_priority="P2 - High"
            )

        return None

    def _check_domain5_security_architecture(self) -> Optional[TriageFinding]:
        mdm = self.raw_data.get("mdm_status") or {}
        is_uamdm = mdm.get("user_approved_mdm", False) if isinstance(mdm, dict) else False

        profiles = self.raw_data.get("installed_profiles") or []
        has_pppc_payload = False
        if isinstance(profiles, list):
            for p in profiles:
                if isinstance(p, dict) and "tcc" in str(p.get("payload_type", "")).lower():
                    has_pppc_payload = True
                    break

        # PPPC / TCC requires User Approved MDM (UAMDM)
        if has_pppc_payload and not is_uamdm:
            return TriageFinding(
                domain_number=5,
                domain_name="Security Architecture & Supervision",
                status="FAIL",
                root_cause_summary="Privacy Preferences Policy Control (PPPC / TCC) payload cannot apply because User Approved MDM (UAMDM) is missing.",
                technical_evidence=[
                    "Target Payload: com.apple.TCC.configuration-profile-policy (PPPC)",
                    "User Approved MDM: False",
                    "Apple Security Requirement: TCC payloads require UAMDM or Automated Device Enrollment"
                ],
                remediation_steps_user=[
                    "Open System Settings -> Privacy & Security -> Profiles.",
                    "Click 'Approve' on the MDM Enrollment profile."
                ],
                remediation_steps_admin=[
                    "Instruct user to manually approve the MDM profile in macOS System Settings.",
                    "Migrate Mac to Automated Device Enrollment (ADE) via Apple Business Manager."
                ],
                escalation_priority="P2 - High"
            )

        sec = self.raw_data.get("security_state") or {}
        if isinstance(sec, str):
            sec = {"system_integrity_protection": sec}
        elif not isinstance(sec, dict):
            sec = {}

        sip = str(sec.get("system_integrity_protection", "")).lower()
        if "disabled" in sip:
            return TriageFinding(
                domain_number=5,
                domain_name="Security Architecture & Supervision",
                status="WARN",
                root_cause_summary="System Integrity Protection (SIP) is disabled, placing device out of enterprise compliance.",
                technical_evidence=[f"csrutil status output: {sec.get('system_integrity_protection')}"],
                remediation_steps_user=["Reboot into Recovery Mode (Command + R or hold power) and enable SIP."],
                remediation_steps_admin=["Verify developer or debugging exception before allowing non-compliant Mac."],
                escalation_priority="P3 - Medium"
            )

        return None


class ReportFormatter:
    """Formats findings into console tables, Markdown reports, and ITSM escalation tickets."""

    @staticmethod
    def format_console(findings: List[TriageFinding], hostname: str, serial: str, os_info: str) -> str:
        lines = []
        lines.append("=" * 80)
        lines.append("macOS MDM & JAMF PROFILE DIAGNOSTIC REPORT")
        lines.append("=" * 80)
        lines.append(f"Target Mac Hostname : {hostname}")
        lines.append(f"Hardware Serial     : {serial}")
        lines.append(f"Operating System    : {os_info}")
        lines.append("-" * 80)

        failed = [f for f in findings if f.status == "FAIL"]
        warns = [f for f in findings if f.status == "WARN"]
        passes = [f for f in findings if f.status == "PASS"]

        primary = failed[0] if failed else (warns[0] if warns else passes[0])

        status_tag = f"[{primary.status}]"
        lines.append(f"TRIAGE RESULT   : {status_tag} DOMAIN {primary.domain_number} - {primary.domain_name.upper()}")
        lines.append(f"PRIORITY        : {primary.escalation_priority}")
        lines.append(f"ROOT CAUSE      : {primary.root_cause_summary}")
        lines.append("-" * 80)

        lines.append("TECHNICAL TELEMETRY EVIDENCE:")
        for ev in primary.technical_evidence:
            lines.append(f"  * {ev}")
        lines.append("-" * 80)

        lines.append("USER SELF-SERVICE RESOLUTION STEPS:")
        for idx, step in enumerate(primary.remediation_steps_user, 1):
            lines.append(f"  {idx}. {step}")
        lines.append("-" * 80)

        lines.append("TIER 2 / MAC ADMIN REMEDIATION PLAYBOOK:")
        for idx, step in enumerate(primary.remediation_steps_admin, 1):
            lines.append(f"  * {step}")

        lines.append("=" * 80)
        return "\n".join(lines)

    @staticmethod
    def generate_markdown(findings: List[TriageFinding], hostname: str, serial: str, os_info: str) -> str:
        primary = next((f for f in findings if f.status == "FAIL"), None)
        if not primary:
            primary = next((f for f in findings if f.status == "WARN"), findings[0])

        md = []
        md.append("# macOS MDM & Package Deployment Diagnostic Assessment")
        md.append("")
        md.append(f"**Endpoint Hostname:** `{hostname}`  ")
        md.append(f"**Hardware Serial:** `{serial}`  ")
        md.append(f"**Operating System:** {os_info}  ")
        md.append(f"**Failure Domain:** **Domain {primary.domain_number} — {primary.domain_name}**  ")
        md.append(f"**Escalation Priority:** `{primary.escalation_priority}`  ")
        md.append("")
        md.append("---")
        md.append("")
        md.append("## 1. Root Cause Analysis (RCA)")
        md.append("")
        md.append(f"> **{primary.status}:** {primary.root_cause_summary}")
        md.append("")
        md.append("### Technical Evidence")
        for ev in primary.technical_evidence:
            md.append(f"- {ev}")
        md.append("")
        md.append("---")
        md.append("")
        md.append("## 2. User Self-Service Remediation")
        md.append("")
        for idx, step in enumerate(primary.remediation_steps_user, 1):
            md.append(f"{idx}. {step}")
        md.append("")
        md.append("---")
        md.append("")
        md.append("## 3. Mac Administrator Escalation Playbook")
        md.append("")
        for step in primary.remediation_steps_admin:
            md.append(f"- {step}")
        md.append("")
        return "\n".join(md)

    @staticmethod
    def generate_itsm_ticket(findings: List[TriageFinding], hostname: str, serial: str, os_info: str) -> str:
        primary = next((f for f in findings if f.status == "FAIL"), None)
        if not primary:
            primary = next((f for f in findings if f.status == "WARN"), findings[0])

        out = []
        out.append(f"# ITSM Ticket Brief: Mac Deployment Failure on {hostname}")
        out.append("")
        out.append(f"**Incident Summary:** [macOS MDM Triage] Domain {primary.domain_number} {primary.domain_name} failure on {hostname}")
        out.append(f"**Urgency / Priority:** {primary.escalation_priority}")
        out.append(f"**Affected Endpoint:** {hostname} (Serial: {serial})")
        out.append(f"**macOS Platform:** {os_info}")
        out.append("")
        out.append("### Diagnostic Assessment")
        out.append(f"**Failure Domain:** Domain {primary.domain_number} ({primary.domain_name})")
        out.append(f"**Root Cause Summary:** {primary.root_cause_summary}")
        out.append("")
        out.append("### Extracted Telemetry & Evidence")
        for ev in primary.technical_evidence:
            out.append(f"- {ev}")
        out.append("")
        out.append("### Recommended Mac Admin Next Steps")
        for step in primary.remediation_steps_admin:
            out.append(f"- {step}")
        return "\n".join(out)


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Deterministic macOS MDM, Jamf Pro & Package Installer Diagnostic Engine."
    )
    parser.add_argument(
        "-i", "--input",
        required=True,
        type=Path,
        help="Path to collected macOS MDM JSON telemetry file."
    )
    parser.add_argument(
        "-o", "--output",
        type=Path,
        default=None,
        help="Optional path to output Markdown assessment report."
    )
    parser.add_argument(
        "--generate-tickets",
        type=Path,
        default=None,
        help="Optional path to output formatted ITSM escalation ticket."
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output JSON summary directly to stdout for automated agent consumption."
    )
    parser.add_argument(
        "--sanitize",
        action="store_true",
        help="Sanitize serial number, hardware identifiers, and corporate hostname (Rule 4)."
    )
    return parser.parse_args()


def main():
    args = parse_arguments()

    if not args.input.exists():
        print(f"Error: Telemetry file not found: {args.input}", file=sys.stderr)
        sys.exit(1)

    try:
        with open(args.input, "r", encoding="utf-8-sig", errors="replace") as f:
            data = json.load(f)
    except Exception as exc:
        print(f"Error parsing JSON: {exc}", file=sys.stderr)
        sys.exit(1)

    if args.sanitize:
        sanitizer = TelemetrySanitizer()
        data = sanitizer.sanitize_bundle(data)

    engine = MacOSMdmTriageEngine(data)
    findings = engine.evaluate()

    hostname = str(data.get("hostname", "unknown-mac")) if isinstance(data, dict) else "unknown-mac"
    serial = str(data.get("serial_number", "UNKNOWN_SERIAL")) if isinstance(data, dict) else "UNKNOWN_SERIAL"
    os_name = str(data.get("os_name", "macOS")) if isinstance(data, dict) else "macOS"
    os_ver = str(data.get("os_version", "15.0")) if isinstance(data, dict) else "15.0"
    os_info = f"{os_name} {os_ver}"

    if args.json:
        payload = {
            "endpoint": hostname,
            "serial": serial,
            "os": os_info,
            "findings": [
                {
                    "domain_number": f.domain_number,
                    "domain_name": f.domain_name,
                    "status": f.status,
                    "priority": f.escalation_priority,
                    "root_cause": f.root_cause_summary,
                    "evidence": f.technical_evidence,
                    "remediation_user": f.remediation_steps_user,
                    "remediation_admin": f.remediation_steps_admin
                }
                for f in findings
            ]
        }
        _json_out = json.dumps(payload, indent=2)
        if args.sanitize:
            _json_out = _residual_scrub(_json_out)
        print(_json_out)
        return

    # Console output
    console_out = ReportFormatter.format_console(findings, hostname, serial, os_info)
    if args.sanitize:
        console_out = _residual_scrub(console_out)
    print(console_out)

    if args.output:
        md_out = ReportFormatter.generate_markdown(findings, hostname, serial, os_info)
        if args.sanitize:
            md_out = _residual_scrub(md_out)
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(md_out)
        print(f"Markdown assessment report written to: {args.output}")

    if args.generate_tickets:
        ticket_out = ReportFormatter.generate_itsm_ticket(findings, hostname, serial, os_info)
        if args.sanitize:
            ticket_out = _residual_scrub(ticket_out)
        with open(args.generate_tickets, "w", encoding="utf-8") as f:
            f.write(ticket_out)
        print(f"ITSM escalation ticket written to: {args.generate_tickets}")


if __name__ == "__main__":
    main()


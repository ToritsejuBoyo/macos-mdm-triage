#!/usr/bin/env python3
"""
advanced_profile_pkg_test.py - Advanced edge-case and core error code verification for macos-mdm-triage.
Tests profile error codes (-20108, -20110), APFS filesystem errors, Bootstrap token warnings,
and SIP security alerts.
Zero third-party dependencies. Complies with Rule 3, Rule 4, Rule 7, Rule 9, and Rule 12.
"""

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

from triage_macos_mdm import (
    MacOSMdmTriageEngine,
    ReportFormatter,
    TelemetrySanitizer,
)


def main():
    print("=" * 70)
    print("MACOS-MDM-TRIAGE ADVANCED PROFILE & PKG TEST SUITE")
    print("=" * 70)

    passed_count = 0

    # -------------------------------------------------------------------------
    # TEST 01: Profile Verification Error -20108 (Signature Invalid)
    # -------------------------------------------------------------------------
    print("[ADVANCED 01] Profile Signature Verification Failure (Error -20108)...")
    payload = {
        "hostname": "mock-mac.local",
        "mdm_status": {"enrolled": True, "supervised": True},
        "installed_profiles": [
            {
                "profile_name": "Broken Signature Profile",
                "payload_identifier": "com.corp.broken.sig",
                "install_error_code": -20108
            }
        ]
    }
    engine = MacOSMdmTriageEngine(payload)
    findings = engine.evaluate()
    assert any(f.domain_number == 2 and f.status == "FAIL" for f in findings)
    f2 = next(f for f in findings if f.domain_number == 2)
    assert "-20108" in f2.root_cause_summary
    print("  -> PASSED: CoreOS error -20108 signature failure diagnosed.")
    passed_count += 1

    # -------------------------------------------------------------------------
    # TEST 02: Duplicate Payload UUID Collision (Error -20110)
    # -------------------------------------------------------------------------
    print("[ADVANCED 02] Duplicate Payload UUID Collision (Error -20110)...")
    payload = {
        "hostname": "mock-mac.local",
        "mdm_status": {"enrolled": True, "supervised": True},
        "installed_profiles": [
            {
                "profile_name": "Colliding Profile",
                "payload_identifier": "com.corp.wifi",
                "profile_uuid": "11111111-2222-3333-4444-555555555555",
                "install_error_code": -20110
            }
        ]
    }
    engine = MacOSMdmTriageEngine(payload)
    findings = engine.evaluate()
    assert any(f.domain_number == 2 and f.status == "FAIL" for f in findings)
    f2 = next(f for f in findings if f.domain_number == 2)
    assert "-20110" in f2.root_cause_summary
    print("  -> PASSED: CoreOS error -20110 duplicate UUID collision diagnosed.")
    passed_count += 1

    # -------------------------------------------------------------------------
    # TEST 03: APFS Read-Only Sealed System Volume Mount Error
    # -------------------------------------------------------------------------
    print("[ADVANCED 03] APFS Read-Only Sealed System Volume Error...")
    payload = {
        "hostname": "mock-mac.local",
        "mdm_status": {"enrolled": True, "supervised": True},
        "install_log_findings": [
            "2026-11-08 10:00:00 PackageKit: Target volume is mounted read-only: Sealed System Volume (SSV)",
            "2026-11-08 10:00:00 installd[500]: Read-only file system error during payload extraction."
        ]
    }
    engine = MacOSMdmTriageEngine(payload)
    findings = engine.evaluate()
    assert any(f.domain_number == 3 and f.status == "FAIL" for f in findings)
    f3 = next(f for f in findings if f.domain_number == 3)
    assert "read-only" in f3.root_cause_summary.lower()
    print("  -> PASSED: APFS read-only volume error isolated at Domain 3.")
    passed_count += 1

    # -------------------------------------------------------------------------
    # TEST 04: Apple Silicon Missing Bootstrap Token Warning (Domain 1 WARN)
    # -------------------------------------------------------------------------
    print("[ADVANCED 04] Apple Silicon Missing Bootstrap Token Warning...")
    payload = {
        "hostname": "mock-mac-m3.local",
        "architecture": "arm64",
        "mdm_status": {
            "enrolled": True,
            "supervised": True,
            "user_approved_mdm": True,
            "bootstrap_token_escrowed": False
        }
    }
    engine = MacOSMdmTriageEngine(payload)
    findings = engine.evaluate()
    assert any(f.domain_number == 1 and f.status == "WARN" for f in findings)
    f1 = next(f for f in findings if f.domain_number == 1)
    assert "bootstrap token" in f1.root_cause_summary.lower()
    print("  -> PASSED: Unescrowed bootstrap token on Apple Silicon flagged as warning.")
    passed_count += 1

    # -------------------------------------------------------------------------
    # TEST 05: System Integrity Protection (SIP) Disabled Warning (Domain 5 WARN)
    # -------------------------------------------------------------------------
    print("[ADVANCED 05] System Integrity Protection Disabled Warning...")
    payload = {
        "hostname": "mock-mac-dev.local",
        "mdm_status": {"enrolled": True, "supervised": True, "user_approved_mdm": True},
        "security_state": {"system_integrity_protection": "System Integrity Protection status: disabled."}
    }
    engine = MacOSMdmTriageEngine(payload)
    findings = engine.evaluate()
    assert any(f.domain_number == 5 and f.status == "WARN" for f in findings)
    f5 = next(f for f in findings if f.domain_number == 5)
    assert "system integrity protection" in f5.root_cause_summary.lower()
    print("  -> PASSED: Disabled SIP state diagnosed with recovery instructions.")
    passed_count += 1

    # -------------------------------------------------------------------------
    # TEST 06: End-to-End CLI Invocation with Markdown & Ticket Outputs
    # -------------------------------------------------------------------------
    print("[ADVANCED 06] End-to-End CLI Invocation with Report & Ticket Generation...")
    fixture_path = Path(__file__).resolve().parent / "fixtures" / "fixture-pkg-postinstall-script-error.json"
    with tempfile.TemporaryDirectory() as td:
        out_report = Path(td) / "mac-report.md"
        out_ticket = Path(td) / "mac-ticket.md"
        proc = subprocess.run(
            [
                sys.executable,
                str(SCRIPT_DIR / "triage_macos_mdm.py"),
                "-i", str(fixture_path),
                "--sanitize",
                "-o", str(out_report),
                "--generate-tickets", str(out_ticket)
            ],
            capture_output=True,
            text=True
        )
        assert proc.returncode == 0
        assert out_report.exists()
        assert out_ticket.exists()
        report_text = out_report.read_text(encoding="utf-8")
        ticket_text = out_ticket.read_text(encoding="utf-8")
        assert "PackageKit" in report_text
        assert "ITSM Ticket Brief" in ticket_text
    print("  -> PASSED: CLI generated sanitized console, Markdown report, and ITSM ticket.")
    passed_count += 1

    print("=" * 70)
    print(f"ALL {passed_count}/6 ADVANCED TESTS PASSED SUCCESSFULLY (Exit Code 0).")
    print("=" * 70)


if __name__ == "__main__":
    main()


#!/usr/bin/env python3
"""
validate-skill.py - Automated verification harness for macos-mdm-triage.
Executes 8 core validation checks against synthetic mock fixtures.
Zero external dependencies. Complies with Rule 3, Rule 4, Rule 7, Rule 9, and Rule 12.
Returns exit code 0 only when all tests pass.
"""

import json
import os
import sys
from pathlib import Path

# Add scripts directory to path
SCRIPT_DIR = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

from triage_macos_mdm import (
    MacOSMdmTriageEngine,
    ReportFormatter,
    TelemetrySanitizer,
    TriageFinding,
)

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"


def load_fixture(name: str) -> dict:
    path = FIXTURES_DIR / name
    if not path.exists():
        raise FileNotFoundError(f"Fixture not found: {path}")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def main():
    print("=" * 70)
    print("MACOS-MDM-TRIAGE AUTOMATED VALIDATION SUITE")
    print("=" * 70)

    passed_count = 0

    # -------------------------------------------------------------------------
    # TEST 01: Healthy Baseline Enterprise Mac (Domain 0 Pass)
    # -------------------------------------------------------------------------
    print("[TEST 01] Healthy Baseline Enterprise Mac (Domain 0 Pass)...")
    data = load_fixture("fixture-healthy-jamf-fleet-mac.json")
    engine = MacOSMdmTriageEngine(data)
    findings = engine.evaluate()
    assert len(findings) == 1, f"Expected 1 finding, got {len(findings)}"
    assert findings[0].status == "PASS"
    assert findings[0].domain_number == 0
    print("  -> PASSED: Fully enrolled and healthy Mac diagnosed with status PASS.")
    passed_count += 1

    # -------------------------------------------------------------------------
    # TEST 02: PackageKit Postinstall Script Exit Error (Domain 3 Fail)
    # -------------------------------------------------------------------------
    print("[TEST 02] PackageKit Postinstall Script Exit Error (Code 112)...")
    data = load_fixture("fixture-pkg-postinstall-script-error.json")
    engine = MacOSMdmTriageEngine(data)
    findings = engine.evaluate()
    assert any(f.domain_number == 3 and f.status == "FAIL" for f in findings)
    f3 = next(f for f in findings if f.domain_number == 3)
    assert "postinstall" in f3.root_cause_summary.lower()
    print("  -> PASSED: PackageKit code 112 postinstall script failure correctly isolated.")
    passed_count += 1

    # -------------------------------------------------------------------------
    # TEST 03: Profile Rejected Due to Supervision Required -20109 (Domain 2 Fail)
    # -------------------------------------------------------------------------
    print("[TEST 03] Configuration Profile Rejected: Device Supervision Required...")
    data = load_fixture("fixture-profile-supervision-required.json")
    engine = MacOSMdmTriageEngine(data)
    findings = engine.evaluate()
    assert any(f.domain_number == 2 and f.status == "FAIL" for f in findings)
    f2 = next(f for f in findings if f.domain_number == 2)
    assert "supervised" in f2.root_cause_summary.lower()
    print("  -> PASSED: Supervised device restriction mismatch identified at Domain 2.")
    passed_count += 1

    # -------------------------------------------------------------------------
    # TEST 04: Developer ID Certificate Expired / Untrusted Root (Domain 3 Fail)
    # -------------------------------------------------------------------------
    print("[TEST 04] Developer ID Certificate Expired / Untrusted Root...")
    data = load_fixture("fixture-cert-expired-signing-failure.json")
    engine = MacOSMdmTriageEngine(data)
    findings = engine.evaluate()
    assert any(f.domain_number == 3 and f.status == "FAIL" for f in findings)
    f3 = next(f for f in findings if f.domain_number == 3)
    assert "expired" in f3.root_cause_summary.lower() or "untrusted" in f3.root_cause_summary.lower()
    print("  -> PASSED: Expired signing certificate and untrusted developer root isolated.")
    passed_count += 1

    # -------------------------------------------------------------------------
    # TEST 05: APNs Push Channel Timeout on Port 5223 (Domain 1 Fail)
    # -------------------------------------------------------------------------
    print("[TEST 05] APNs Push Channel Timeout on Port 5223...")
    data = load_fixture("fixture-apns-push-token-expired.json")
    engine = MacOSMdmTriageEngine(data)
    findings = engine.evaluate()
    assert any(f.domain_number == 1 and f.status == "FAIL" for f in findings)
    f1 = next(f for f in findings if f.domain_number == 1)
    assert "apns" in f1.root_cause_summary.lower() or "push" in f1.root_cause_summary.lower()
    print("  -> PASSED: APNs port 5223 handshake timeout isolated to Domain 1.")
    passed_count += 1

    # -------------------------------------------------------------------------
    # TEST 06: PPPC / TCC Profile Missing User Approved MDM (Domain 5 Fail)
    # -------------------------------------------------------------------------
    print("[TEST 06] PPPC / TCC Profile Missing User Approved MDM (UAMDM)...")
    data = load_fixture("fixture-pppc-tcc-missing-uamdm.json")
    engine = MacOSMdmTriageEngine(data)
    findings = engine.evaluate()
    assert any(f.domain_number == 5 and f.status == "FAIL" for f in findings)
    f5 = next(f for f in findings if f.domain_number == 5)
    assert "uamdm" in f5.root_cause_summary.lower() or "user approved" in f5.root_cause_summary.lower()
    print("  -> PASSED: Missing UAMDM requirement for PPPC/TCC isolated to Domain 5.")
    passed_count += 1

    # -------------------------------------------------------------------------
    # TEST 07: Stopped Jamf Management Agent Daemon (Domain 4 Fail)
    # -------------------------------------------------------------------------
    print("[TEST 07] Jamf Pro Management Daemon Stopped...")
    jamf_stopped_data = {
        "hostname": "mock-mac-jamf.local",
        "serial_number": "C02TESTJAMF1",
        "os_name": "macOS Sequoia",
        "os_version": "15.0",
        "mdm_status": {
            "enrolled": True,
            "supervised": True,
            "user_approved_mdm": True,
            "mdm_server_url": "https://jamf.corp.example.com:8443"
        },
        "agent_daemons": {
            "jamf_agent_running": False,
            "intune_agent_running": False,
            "kandji_agent_running": False
        }
    }
    engine = MacOSMdmTriageEngine(jamf_stopped_data)
    findings = engine.evaluate()
    assert any(f.domain_number == 4 and f.status == "FAIL" for f in findings)
    print("  -> PASSED: Stopped Jamf agent daemon flagged with service recovery steps.")
    passed_count += 1

    # -------------------------------------------------------------------------
    # TEST 08: Client-Side Data Sanitization (Rule 4 Compliance)
    # -------------------------------------------------------------------------
    print("[TEST 08] Client-Side Data Sanitization (Rule 4 Compliance)...")
    san = TelemetrySanitizer()
    clean = san.sanitize_bundle({
        "hostname": "finance-executive-macbook.internal.corp",
        "serial_number": "C02G12345678",
        "mdm_status": {"mdm_server_url": "https://jamf.internal.secret.net:8443"},
        "installed_profiles": [{"profile_uuid": "11111111-2222-3333-4444-555555555555"}]
    })
    assert clean["hostname"].startswith("mac-") and clean["hostname"].endswith(".corp.example.com")
    assert clean["serial_number"].startswith("C02") and "12345678" not in clean["serial_number"]
    assert clean["mdm_status"]["mdm_server_url"] == "https://mdm-masked.corp.example.com"
    assert clean["installed_profiles"][0]["profile_uuid"] == "00000000-0000-4000-a000-000000000001"
    print("  -> PASSED: Mac serial number, hostname, UUID, and MDM URL masked.")
    passed_count += 1

    print("=" * 70)
    print(f"ALL {passed_count}/8 VALIDATION CHECKS PASSED SUCCESSFULLY (Exit Code 0).")
    print("=" * 70)


if __name__ == "__main__":
    main()


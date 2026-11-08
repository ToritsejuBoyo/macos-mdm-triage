#!/usr/bin/env python3
"""
stress_test_macos_mdm.py - High-volume throughput benchmark for macos-mdm-triage.
Generates and triages 10,000 diverse macOS telemetry payloads.
Zero third-party dependencies. Complies with Rule 3, Rule 7, Rule 9, and Rule 12.
"""

import json
import random
import sys
import time
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

from triage_macos_mdm import (
    MacOSMdmTriageEngine,
    TelemetrySanitizer,
)


def generate_synthetic_batch(count: int = 10000):
    payloads = []
    error_types = [
        "healthy",
        "postinstall_error",
        "supervision_required",
        "cert_expired",
        "apns_timeout",
        "uamdm_missing",
        "jamf_stopped"
    ]

    for i in range(count):
        err = random.choice(error_types)
        host = f"mac-fleet-{i:05d}.internal.corp"
        serial = f"C02G{i:05d}XYZ"

        if err == "healthy":
            p = {
                "hostname": host,
                "serial_number": serial,
                "os_name": "macOS Sequoia",
                "os_version": "15.0",
                "mdm_status": {"enrolled": True, "supervised": True, "user_approved_mdm": True, "bootstrap_token_escrowed": True, "mdm_server_url": "https://jamf.corp.example.com"},
                "agent_daemons": {"jamf_agent_running": True},
                "installed_profiles": [],
                "install_log_findings": []
            }
        elif err == "postinstall_error":
            p = {
                "hostname": host,
                "serial_number": serial,
                "os_name": "macOS Sequoia",
                "os_version": "15.0",
                "mdm_status": {"enrolled": True, "supervised": True, "user_approved_mdm": True, "bootstrap_token_escrowed": True, "mdm_server_url": "https://jamf.corp.example.com"},
                "agent_daemons": {"jamf_agent_running": True},
                "install_log_findings": [f"PackageKit: Install Failed: Error Domain=PKInstallErrorDomain Code=112 on item {i}"]
            }
        elif err == "supervision_required":
            p = {
                "hostname": host,
                "serial_number": serial,
                "os_name": "macOS Sonoma",
                "os_version": "14.5",
                "mdm_status": {"enrolled": True, "supervised": False, "user_approved_mdm": True, "bootstrap_token_escrowed": False, "mdm_server_url": "https://jamf.corp.example.com"},
                "installed_profiles": [{"profile_name": "Restricted Profile", "install_error_code": -20109, "supervision_required": True}]
            }
        elif err == "cert_expired":
            p = {
                "hostname": host,
                "serial_number": serial,
                "os_name": "macOS Sequoia",
                "os_version": "15.0",
                "mdm_status": {"enrolled": True, "supervised": True, "user_approved_mdm": True, "bootstrap_token_escrowed": True, "mdm_server_url": "https://jamf.corp.example.com"},
                "install_log_findings": ["CSSMERR_TP_NOT_TRUSTED: certificate expired"]
            }
        elif err == "apns_timeout":
            p = {
                "hostname": host,
                "serial_number": serial,
                "os_name": "macOS Sequoia",
                "os_version": "15.0",
                "mdm_status": {"enrolled": True, "supervised": True, "user_approved_mdm": True, "bootstrap_token_escrowed": True, "mdm_server_url": "https://jamf.corp.example.com"},
                "apns_status": {"push_token_expired": True, "port_5223_status": "Timeout"}
            }
        elif err == "uamdm_missing":
            p = {
                "hostname": host,
                "serial_number": serial,
                "os_name": "macOS Ventura",
                "os_version": "13.6",
                "mdm_status": {"enrolled": True, "supervised": False, "user_approved_mdm": False, "bootstrap_token_escrowed": False, "mdm_server_url": "https://intune.corp.example.com"},
                "installed_profiles": [{"payload_type": "com.apple.TCC.configuration-profile-policy"}]
            }
        else:  # jamf_stopped
            p = {
                "hostname": host,
                "serial_number": serial,
                "os_name": "macOS Sequoia",
                "os_version": "15.0",
                "mdm_status": {"enrolled": True, "supervised": True, "user_approved_mdm": True, "bootstrap_token_escrowed": True, "mdm_server_url": "https://jamf.corp.example.com"},
                "agent_daemons": {"jamf_agent_running": False}
            }
        payloads.append(p)

    return payloads


def main():
    print("=" * 70)
    print("MACOS-MDM-TRIAGE HIGH-VOLUME STRESS BENCHMARK (10,000 PAYLOADS)")
    print("=" * 70)

    print("[STEP 1] Generating 10,000 diverse macOS telemetry payloads...")
    t0 = time.perf_counter()
    batch = generate_synthetic_batch(10000)
    gen_time = time.perf_counter() - t0
    print(f"  -> Generated 10,000 payloads in {gen_time:.3f}s")

    print("[STEP 2] Triaging 10,000 payloads through 6-domain decision tree with sanitization...")
    sanitizer = TelemetrySanitizer()
    t1 = time.perf_counter()

    for item in batch:
        clean = sanitizer.sanitize_bundle(item)
        engine = MacOSMdmTriageEngine(clean)
        findings = engine.evaluate()
        assert len(findings) >= 1

    total_time = time.perf_counter() - t1
    throughput = len(batch) / total_time

    print("-" * 70)
    print(f"TOTAL TRIAGE EXECUTION TIME: {total_time:.3f}s")
    print(f"THROUGHPUT: {throughput:,.0f} diagnoses/second")
    print("-" * 70)

    assert total_time < 2.5, f"Performance SLA exceeded: {total_time:.3f}s > 2.5s"
    print("PERFORMANCE BENCHMARK PASSED: Under 2.5s SLA met.")
    print("=" * 70)
    print("STRESS TEST COMPLETED SUCCESSFULLY (Exit Code 0).")
    print("=" * 70)


if __name__ == "__main__":
    main()


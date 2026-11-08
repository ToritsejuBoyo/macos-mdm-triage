#!/usr/bin/env python3
"""
generate-fixtures.py - Generates 6 obvious synthetic mock fixtures for macos-mdm-triage.
All fixtures strictly use synthetic mock identifiers complying with Rule 9.
"""

import json
from pathlib import Path

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "tests" / "fixtures"
FIXTURES_DIR.mkdir(parents=True, exist_ok=True)

# 1. PackageKit Postinstall Script Exit Error (Code 112)
f1 = {
    "timestamp_utc": "2026-11-08T12:00:00Z",
    "hostname": "mock-macbook-pro-01.local",
    "serial_number": "C02TESTPKG01",
    "os_name": "macOS Sequoia",
    "os_version": "15.0.1",
    "os_build": "24A348",
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
        "mdm_server_url": "https://jamf.synthetic-corp.local:8443"
    },
    "agent_daemons": {
        "jamf_agent_running": True,
        "intune_agent_running": False,
        "kandji_agent_running": False
    },
    "installed_profiles": [],
    "install_log_findings": [
        "2026-11-08 11:58:12+0000 installd[820]: PackageKit: Executing script './postinstall' in /private/tmp/PKInstallSandbox.001",
        "2026-11-08 11:58:13+0000 installd[820]: ./postinstall: line 42: /usr/local/bin/custom_agent: No such file or directory",
        "2026-11-08 11:58:13+0000 installd[820]: PackageKit: postinstall exited with status 1",
        "2026-11-08 11:58:13+0000 installd[820]: PackageKit: Install Failed: Error Domain=PKInstallErrorDomain Code=112 \"An error occurred while running scripts from the package \u201cCorpSecurityAgent.pkg\u201d.\"",
        "2026-11-08 11:58:13+0000 installer[780]: Install failed: The Installer encountered an error that caused the installation to fail."
    ]
}

# 2. Configuration Profile Rejected: Device Supervision Required (-20109)
f2 = {
    "timestamp_utc": "2026-11-08T12:05:00Z",
    "hostname": "mock-mac-byod-02.local",
    "serial_number": "C02TESTBYOD2",
    "os_name": "macOS Sonoma",
    "os_version": "14.5",
    "os_build": "23F79",
    "architecture": "arm64",
    "security_state": {
        "system_integrity_protection": "System Integrity Protection status: enabled.",
        "gatekeeper_status": "assessments enabled",
        "filevault_status": "FileVault is On."
    },
    "mdm_status": {
        "enrolled": True,
        "supervised": False,  # User-enrolled BYOD Mac!
        "user_approved_mdm": True,
        "bootstrap_token_escrowed": False,
        "mdm_server_url": "https://jamf.synthetic-corp.local:8443"
    },
    "agent_daemons": {
        "jamf_agent_running": True,
        "intune_agent_running": False,
        "kandji_agent_running": False
    },
    "installed_profiles": [
        {
            "profile_name": "Enterprise Security Restrictions & AirDrop Disable",
            "payload_identifier": "com.synthetic-corp.restrictions.airdrop",
            "payload_type": "com.apple.applicationaccess",
            "profile_uuid": "00000000-0000-4000-a000-000000000002",
            "install_error_code": -20109,
            "supervision_required": True
        }
    ],
    "install_log_findings": []
}

# 3. Developer ID Certificate Expired / Untrusted Root (Signing Failure)
f3 = {
    "timestamp_utc": "2026-11-08T12:10:00Z",
    "hostname": "mock-mac-design-03.local",
    "serial_number": "C02TESTEXP03",
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
        "mdm_server_url": "https://jamf.synthetic-corp.local:8443"
    },
    "agent_daemons": {
        "jamf_agent_running": True,
        "intune_agent_running": False,
        "kandji_agent_running": False
    },
    "installed_profiles": [],
    "install_log_findings": [
        "2026-11-08 12:08:44+0000 PackageKit: Verifying certificate chain for Developer ID Installer: Vendor Software Ltd (ABC1234XYZ)",
        "2026-11-08 12:08:44+0000 PackageKit: CSSMERR_TP_NOT_TRUSTED: Certificate expired on 2026-05-15 00:00:00 UTC",
        "2026-11-08 12:08:44+0000 PackageKit: Install Failed: Package signature validation failed: certificate expired or untrusted developer root",
        "2026-11-08 12:08:44+0000 installd[910]: Fatal error: package untrusted, aborting deployment."
    ]
}

# 4. APNs Push Token Expired / Port 5223 Firewall Timeout
f4 = {
    "timestamp_utc": "2026-11-08T12:15:00Z",
    "hostname": "mock-mac-remote-04.local",
    "serial_number": "C02TESTAPN04",
    "os_name": "macOS Sequoia",
    "os_version": "15.0.1",
    "os_build": "24A348",
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
        "mdm_server_url": "https://jamf.synthetic-corp.local:8443"
    },
    "apns_status": {
        "push_token_expired": True,
        "push_handshake_timeout": True,
        "port_5223_status": "Connection Timed Out to gateway.push.apple.com:5223",
        "error_detail": "TLS handshake to gateway.push.apple.com:5223 timed out after 30 seconds"
    },
    "agent_daemons": {
        "jamf_agent_running": True,
        "intune_agent_running": False,
        "kandji_agent_running": False
    },
    "installed_profiles": [],
    "install_log_findings": []
}

# 5. PPPC / TCC Profile Missing User Approved MDM (UAMDM)
f5 = {
    "timestamp_utc": "2026-11-08T12:20:00Z",
    "hostname": "mock-mac-manual-05.local",
    "serial_number": "C02TESTTCC05",
    "os_name": "macOS Ventura",
    "os_version": "13.6.7",
    "os_build": "22G720",
    "architecture": "x86_64",
    "security_state": {
        "system_integrity_protection": "System Integrity Protection status: enabled.",
        "gatekeeper_status": "assessments enabled",
        "filevault_status": "FileVault is On."
    },
    "mdm_status": {
        "enrolled": True,
        "supervised": False,
        "user_approved_mdm": False,  # Missing UAMDM!
        "bootstrap_token_escrowed": False,
        "mdm_server_url": "https://intune.synthetic-corp.local"
    },
    "agent_daemons": {
        "jamf_agent_running": False,
        "intune_agent_running": True,
        "kandji_agent_running": False
    },
    "installed_profiles": [
        {
            "profile_name": "CrowdStrike Full Disk Access & TCC Privileges",
            "payload_identifier": "com.synthetic-corp.security.crowdstrike.tcc",
            "payload_type": "com.apple.TCC.configuration-profile-policy",
            "profile_uuid": "00000000-0000-4000-a000-000000000005",
            "install_error_code": None
        }
    ],
    "install_log_findings": []
}

# 6. Healthy Supervised Fleet MacBook Pro (Baseline Pass)
f6 = {
    "timestamp_utc": "2026-11-08T12:25:00Z",
    "hostname": "mock-macbook-pro-hq-06.local",
    "serial_number": "C02TESTOK006",
    "os_name": "macOS Sequoia",
    "os_version": "15.0.1",
    "os_build": "24A348",
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
        "mdm_server_url": "https://jamf.synthetic-corp.local:8443"
    },
    "agent_daemons": {
        "jamf_agent_running": True,
        "intune_agent_running": False,
        "kandji_agent_running": False
    },
    "installed_profiles": [
        {
            "profile_name": "Corporate 802.1X Wi-Fi",
            "payload_identifier": "com.synthetic-corp.wifi",
            "payload_type": "com.apple.wifi.managed",
            "profile_uuid": "00000000-0000-4000-a000-000000000006",
            "install_error_code": 0
        }
    ],
    "install_log_findings": []
}

fixtures = {
    "fixture-pkg-postinstall-script-error.json": f1,
    "fixture-profile-supervision-required.json": f2,
    "fixture-cert-expired-signing-failure.json": f3,
    "fixture-apns-push-token-expired.json": f4,
    "fixture-pppc-tcc-missing-uamdm.json": f5,
    "fixture-healthy-jamf-fleet-mac.json": f6
}

for filename, content in fixtures.items():
    dest = FIXTURES_DIR / filename
    with open(dest, "w", encoding="utf-8") as fp:
        json.dump(content, fp, indent=2)
    print(f"Generated fixture: {dest}")

print(f"Successfully generated {len(fixtures)} synthetic test fixtures in {FIXTURES_DIR}")


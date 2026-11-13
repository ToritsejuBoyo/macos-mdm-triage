---
name: macos-mdm-triage
description: >-
  Diagnoses macOS MDM enrollment stalls, Jamf profile rejections, APNs push disconnects, and
  PackageKit install.log failures across a 6-domain decision tree. Use when a Mac fails or stalls
  during MDM enrollment, a configuration profile is rejected, Jamf policies stop applying, APNs
  push appears disconnected, or a package install fails in /var/log/install.log.
license: MIT
version: 1.0.0
metadata:
  standard: agentskills.io
  dependencies: none (Python standard library only)
  access: read-only collectors; no state is modified on target systems
---

# macOS MDM & Jamf Profile Troubleshooter (`macos-mdm-triage`)

A deterministic, offline Level 2 / Level 3 macOS diagnostic skill and decision-tree engine that pinpoints Mac configuration profile rejections, software deployment errors, and MDM push channel failures from read-only endpoint telemetry. Evaluates MDM enrollment status, Apple Device Supervision, `/var/log/install.log` PackageKit error codes, APNs port 5223 reachability, management daemons (Jamf, Intune, Kandji, Addigy), User Approved MDM (UAMDM), and Bootstrap Token escrow to produce plain-English root causes, admin remediation playbooks, and pre-formatted ITSM escalation tickets.

---

## 1. Capabilities & Supported Diagnostic Domains

1. **Domain 1: MDM Enrollment & APNs Channel Health:**
   - Detects unenrolled Macs (`profiles status -type enrollment`), expired APNs push certificates, TLS handshake timeouts on Apple push notification port 5223 (`17.0.0.0/8`), and unescrowed Apple Silicon Bootstrap Tokens.
2. **Domain 2: Configuration Profile Syntax & Supervision:**
   - Evaluates CoreOS configuration profile error codes:
     - Error `-20108`: Digital signature verification failed or revoked signing certificate.
     - Error `-20109`: Payload restriction requires Apple Device Supervision (Automated Device Enrollment / ADE via Apple Business Manager).
     - Error `-20110`: Payload identifier or `PayloadUUID` collision with an existing profile.
3. **Domain 3: Apple PackageKit (`.pkg`) & `install.log` Analysis:**
   - Parses the system installer log (`/var/log/install.log`) for:
     - `PKInstallErrorDomain Code=112`: Postinstall or preinstall script exited with a non-zero exit status (e.g. script syntax error, missing interpreter, or UI prompt stall).
     - `CSSMERR_TP_NOT_TRUSTED`: Expired Apple Developer ID Installer certificate or untrusted CA root.
     - Gatekeeper Quarantine: Notarization ticket missing (`spctl: rejected`) or hardened runtime violations.
     - Sealed System Volume (SSV) write attempts or APFS storage exhaustion.
4. **Domain 4: MDM Agent Daemon State:**
   - Evaluates system launch daemons: Jamf Pro (`com.jamfsoftware.jamf.daemon`), Microsoft Intune (`com.microsoft.intune.agent`), and Kandji (`io.kandji.daemon`). Flags crashed, disabled, or unloaded management daemons.
5. **Domain 5: Security Architecture & Supervision Dependencies:**
   - Verifies **User Approved MDM (UAMDM)**: Privacy Preferences Policy Control (PPPC / TCC) payloads require user-approved MDM status.
   - Audits System Integrity Protection (SIP) and FileVault encryption state.
6. **Domain 6: Multi-Product Output Synthesis:**
   - Terminal status table, detailed Markdown assessment report (`-o report.md`), and ITSM escalation ticket (`--generate-tickets ticket.md`).

---

## 2. Technical Requirements & Least Privilege (Rule 3)

- **Zero Third-Party Dependencies:** Written exclusively in native Bash and Python standard library modules (`json`, `subprocess`, `hashlib`, `platform`, `argparse`, `re`, `time`).
- **Read-Only Operation:** Zero automated system configuration mutations, zero profile deletions, and zero package installations.
- **Least Privilege:** Telemetry collectors require standard user permissions for profile status queries and basic reading of `/var/log/install.log`.
- **Client-Side Data Sanitization (Rule 4):** Automated `--sanitize` mode masks hardware serial numbers (SHA-256 hashed to `C02XXXXXXXX`), Mac hostnames (`mac-xxxx.corp.example.com`), and corporate MDM URLs before any data leaves the local workstation.

---

## 3. Workflow for AI Agents & Mac Administrators

### Step 1: Ingest Endpoint Telemetry
Instruct the technician or user to execute the read-only collector on their Mac:
```bash
# Option A: Native Bash Collector (macOS only)
bash scripts/collect-macos-mdm.sh --sanitize > telemetry.json

# Option B: Cross-Platform Python Collector (macOS / Linux / Windows)
python3 scripts/collect_macos_mdm.py --sanitize -o telemetry.json
```

### Step 2: Execute Deterministic Triage
Run the offline 6-domain triage engine against the collected JSON bundle:
```bash
python3 scripts/triage_macos_mdm.py \
  -i telemetry.json \
  -o diagnostic-report.md \
  --generate-tickets itsm-ticket.md
```

### Step 3: Consume Programmatic Output in Agent Pipelines
For autonomous agents, parse structured JSON output via stdout:
```bash
python3 scripts/triage_macos_mdm.py -i telemetry.json --json
```

Output schema structure:
```json
{
  "endpoint": "mac-a1b2c3d4.corp.example.com",
  "serial": "C02TEST00001",
  "os": "macOS Sequoia 15.0.1",
  "findings": [
    {
      "domain_number": 3,
      "domain_name": "Apple PackageKit (.pkg) & Installer Engine",
      "status": "FAIL",
      "priority": "P2 - High",
      "root_cause": "Apple PackageKit installation failed because the package's postinstall script returned a non-zero exit code.",
      "evidence": [
        "PackageKit: postinstall exited with status 1",
        "PackageKit: Install Failed: Error Domain=PKInstallErrorDomain Code=112"
      ],
      "remediation_user": [
        "Restart the Mac and re-attempt installation from Jamf Self Service."
      ],
      "remediation_admin": [
        "Extract the .pkg payload with 'pkgutil --expand' and inspect the 'Scripts/postinstall' script."
      ]
    }
  ]
}
```

---

## 4. Remediation Quick Reference for Mac Admins

### PackageKit Postinstall Script Failures (Code 112)
```bash
# Expand package to inspect scripts
pkgutil --expand /path/to/software.pkg /tmp/expanded_pkg
cat /tmp/expanded_pkg/Scripts/postinstall

# Verify package signature and certificate expiration
pkgutil --check-signature /path/to/software.pkg
```

### Configuration Profile Supervision Errors (-20109)
```bash
# Verify enrollment and supervision status
profiles status -type enrollment

# Re-escrow Bootstrap Token on Apple Silicon
sudo profiles install -type bootstraptoken
```

### Restarting Stopped Jamf Agent Daemon
```bash
# Reload Jamf launch daemon
sudo launchctl bootstrap system /Library/LaunchDaemons/com.jamfsoftware.task.plist
sudo jamf manage
sudo jamf recon
```

---

## Bundled Resources

Load these on demand — they hold the decision logic behind the 6-domain triage tree.

- **MDM Troubleshooting Matrix:** [`references/macos-mdm-troubleshooting-matrix.md`](references/macos-mdm-troubleshooting-matrix.md) — MDM/package error code tables and PPPC (Privacy Preferences Policy Control) reference.
- **Profile Rejection Rubric:** [`references/configuration-profile-rejection-rubric.md`](references/configuration-profile-rejection-rubric.md) — Diagnostic rubric for `.mobileconfig` configuration profile installation failures. **Consult for any Domain 2 (profile) verdict.**
- **Installer Error Codes:** [`references/apple-installer-error-codes.md`](references/apple-installer-error-codes.md) — Apple PackageKit and Installer error codes as they appear in `/var/log/install.log`. **Consult for any Domain 4 (PackageKit) verdict.**
- **Supervision & UAMDM Guide:** [`references/mdm-supervision-uamdm-guide.md`](references/mdm-supervision-uamdm-guide.md) — Enterprise guide to supervision, User-Approved MDM, and Bootstrap Token hierarchies. **Consult for enrollment and escrow failures.**
- **Diagnostic Report Template:** [`assets/macos-triage-report-template.md`](assets/macos-triage-report-template.md) — Structured macOS MDM and package deployment assessment report.
- **ITSM Ticket Template:** [`assets/itsm-jamf-ticket-template.md`](assets/itsm-jamf-ticket-template.md) — Jamf/ITSM escalation ticket brief for Mac deployment failures.

---

## Data Handling & Sanitization

Sanitization runs **client-side, before any output is produced**, so credentials and
personal data are removed on the operator's machine rather than being sent to a model
or pasted into a ticket.

Two layers apply:

1. This skill's own domain-aware masking (hostnames, accounts, and the identifiers
   specific to this domain).
2. A shared residual pass, [`scripts/sanitizer.py`](scripts/sanitizer.py), vendored
   identically across every skill in the library. It is the common floor: private keys,
   cloud provider keys, JWTs and bearer tokens, connection-string passwords, assigned
   secrets, emails, IPv4/IPv6 addresses, MAC addresses, GUIDs, SSNs, payment card
   numbers, and phone numbers.

The contract is enforced by `tests/sanitizer_conformance_test.py`, which runs the same
adversarial corpus in every skill. Documentation placeholders (RFC 5737/3849 addresses,
RFC 7042 MAC ranges, `example.com` names, and existing `[REDACTED-*]` tokens) are
preserved, so the pass is safe to apply more than once.

Sanitization is thorough and tested, but it is not a substitute for reading output
before sharing it outside your organization.

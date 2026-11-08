# Apple PackageKit & Installer Error Codes Reference

A technical diagnostic reference for macOS software installation failures in `/var/log/install.log`.

---

## 1. PackageKit Error Domains (`PKInstallErrorDomain`)

| Error Code | Error Constant | Technical Meaning | Root Cause | Remediation Procedure |
| :--- | :--- | :--- | :--- | :--- |
| **Code 112** | `PKInstallErrorDomain Code=112` | Script execution failed | A `preinstall` or `postinstall` script returned an exit status other than 0. | Expand `.pkg` with `pkgutil --expand`, inspect script for non-interactive execution, missing paths, or UI prompts. |
| **Code 100** | `PKInstallErrorDomain Code=100` | Package verification failed | Corrupted archive payload or payload digest mismatch. | Re-download package or verify MD5/SHA-256 hash. |
| **Code 101** | `PKInstallErrorDomain Code=101` | Untrusted package signer | Developer ID Installer certificate expired, revoked, or untrusted CA root. | Re-sign with active Developer ID Installer certificate (`productsign --sign`). |
| **Code 102** | `PKInstallErrorDomain Code=102` | Notarization missing | Gatekeeper blocked execution because ticket is missing or invalidated. | Notarize package using `xcrun notarytool submit` and staple with `xcrun stapler staple`. |
| **Code 103** | `PKInstallErrorDomain Code=103` | Disk space exhausted | Insufficient storage on target APFS volume. | Free up disk space; macOS requires 2x package size during extraction. |
| **Code 106** | `PKInstallErrorDomain Code=106` | Read-only target volume | Attempted to write to the Sealed System Volume (SSV) `/`. | Redirect installation destination to `/Applications` or `/Library`. |

---

## 2. Common Installer CoreOS & Security Codes

| Error String | Originating Component | Root Cause | Fix Action |
| :--- | :--- | :--- | :--- |
| `CSSMERR_TP_NOT_TRUSTED` | Apple Security Framework | Certificate chain cannot be verified against Apple WWDR CA. | Update local keychain certificates or renew expired developer certificate. |
| `CSSMERR_TP_CERT_EXPIRED` | Apple Security Framework | Developer ID Installer certificate past validity timestamp. | Re-sign installer with current active certificate. |
| `spctl: rejected` | Gatekeeper Assessment | Hardened runtime violation or untrusted binary. | Enable hardened runtime during compilation (`--options runtime`). |
| `com.apple.quarantine` | macOS Sandbox | File downloaded via Safari/Chrome flagged with quarantine attribute. | Strip attribute: `xattr -d com.apple.quarantine <file>`. |
| `Operation not permitted` | Transparency, Consent, and Control (TCC) | Script attempted to access protected user directories without Full Disk Access. | Deploy MDM PPPC profile (`com.apple.TCC.configuration-profile-policy`). |


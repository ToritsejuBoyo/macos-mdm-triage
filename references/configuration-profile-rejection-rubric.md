# macOS Configuration Profile Rejection Rubric

A diagnostic rubric for troubleshooting Apple configuration profile (`.mobileconfig`) installation failures on macOS.

---

## 1. CoreOS Configuration Profile Error Codes

| Error Code | Error Message | Root Cause | Admin Remediation |
| :--- | :--- | :--- | :--- |
| **`-20108`** | `Verification failed` | Profile digital signature invalid, intermediate certificate missing, or profile altered after signing. | Re-export and re-sign `.mobileconfig` with active enterprise certificate. |
| **`-20109`** | `Payload not allowed / Supervision required` | Payload includes restrictions (e.g. `com.apple.applicationaccess`, AirDrop disable, Web Content Filter) that require Apple Device Supervision. | Re-enroll device via Apple Business Manager (ABM) / Automated Device Enrollment (ADE), or remove supervised restrictions. |
| **`-20110`** | `Duplicate payload identifier or UUID` | A profile with the exact same `PayloadUUID` or conflicting payload identifier already exists in the macOS profile store. | Regenerate a unique UUID (`uuidgen`) in profile XML or remove conflicting profile using `sudo profiles remove -identifier <ID>`. |
| **`-20111`** | `Payload cannot be removed` | User or script attempted to remove an MDM-locked configuration profile. | Profile must be unassigned or removed from the MDM server console. |
| **`-20112`** | `Payload decrypt error` | Encrypted configuration profile payload cannot be decrypted with device identity certificate. | Verify device SCEP or MDM identity certificate validity in Keychain. |

---

## 2. Payload Compatibility by Enrollment State

| Payload Domain | Unsupervised (User-Enrolled) | Supervised (ADE / ABM) | User Approved MDM (UAMDM) Required? |
| :--- | :--- | :--- | :--- |
| **Wi-Fi 802.1X (`com.apple.wifi.managed`)** | Supported | Supported | No |
| **VPN (`com.apple.vpn.managed`)** | Supported | Supported | No |
| **Passcode (`com.apple.mobiledevice.passwordpolicy`)** | Basic only | Full enforcement | No |
| **PPPC / TCC (`com.apple.TCC.configuration-profile-policy`)** | Blocked | Supported | **Yes (Mandatory)** |
| **System Extensions (`com.apple.system-extension-policy`)** | Blocked | Supported | **Yes (Mandatory)** |
| **Kernel Extensions (`com.apple.syspolicy.kernel-extension-policy`)** | Blocked | Supported (User approved) | **Yes (Mandatory)** |
| **Application Restrictions (`com.apple.applicationaccess`)** | Basic | Full enforcement | No |

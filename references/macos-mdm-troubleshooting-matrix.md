# macOS MDM Error Codes & PPPC Reference

## Common Package & MDM Error Codes

| Error Code / Keyword | Meaning | Primary Root Cause | Resolution |
| --- | --- | --- | --- |
| `Package untrusted` / `CSSMERR_TP_NOT_TRUSTED` | Code-signing cert untrusted | Developer certificate expired or root CA missing | Re-sign `.pkg` with valid Apple Developer ID Installer cert |
| `Postinstall error` (Exit 1) | Script execution failed | Postinstall script has broken bash/zsh syntax or expects UI | Test script standalone; ensure non-interactive execution |
| `System Extension Blocked` | Security kext/sysext blocked | User has not approved system extension in System Settings | Deploy MDM System Extension payload (`mobileconfig`) |
| `Operation not permitted` | TCC / PPPC restriction | Process attempted to access protected user folder | Grant Full Disk Access via MDM Privacy Preferences payload |

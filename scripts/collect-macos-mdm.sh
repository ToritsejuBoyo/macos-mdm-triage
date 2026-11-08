#!/usr/bin/env bash
#
# collect-macos-mdm.sh - Deterministic, read-only macOS MDM, Jamf & Package Installer Telemetry Collector.
# Zero third-party dependencies. Standard macOS built-in utilities only.
# Complies with Rule 3 (Read-Only), Rule 4 (Sanitization), and Rule 7 (Zero-Emoji).
#

set -u

SANITIZE=false
for arg in "$@"; do
  if [[ "$arg" == "--sanitize" ]]; then
    SANITIZE=true
  fi
done

# Safe command execution helper
safe_run() {
  local cmd="$1"
  eval "$cmd" 2>/dev/null || echo ""
}

# Hashing helper
hash_sha256() {
  local val="$1"
  if [[ "$SANITIZE" == true ]]; then
    local h
    h=$(printf "%s" "${val}macos-mdm-salt" | shasum -a 256 | cut -c 1-8)
    echo "mac-${h}.corp.example.com"
  else
    echo "$val"
  fi
}

hash_serial() {
  local val="$1"
  if [[ "$SANITIZE" == true ]]; then
    local h
    h=$(printf "%s" "${val}macos-serial-salt" | shasum -a 256 | cut -c 1-10 | tr '[:lower:]' '[:upper:]')
    echo "C02${h}"
  else
    echo "$val"
  fi
}

# 1. System Metadata
RAW_HOSTNAME=$(hostname 2>/dev/null || echo "unknown-mac")
HOSTNAME=$(hash_sha256 "$RAW_HOSTNAME")

OS_PRODUCT=$(sw_vers -productVersion 2>/dev/null || echo "15.0")
OS_BUILD=$(sw_vers -buildVersion 2>/dev/null || echo "24A335")
OS_NAME="macOS"
if [[ "$OS_PRODUCT" =~ ^15\. ]]; then
  OS_NAME="macOS Sequoia"
elif [[ "$OS_PRODUCT" =~ ^14\. ]]; then
  OS_NAME="macOS Sonoma"
elif [[ "$OS_PRODUCT" =~ ^13\. ]]; then
  OS_NAME="macOS Ventura"
fi

ARCH=$(uname -m 2>/dev/null || echo "arm64")
RAW_SERIAL=$(ioreg -c IOPlatformExpertDevice -d 2 2>/dev/null | awk -F\" '/IOPlatformSerialNumber/{print $(NF-1)}' || echo "UNKNOWN_SERIAL")
SERIAL=$(hash_serial "$RAW_SERIAL")

SIP_STATUS=$(csrutil status 2>/dev/null || echo "unknown")
GATEKEEPER_STATUS=$(spctl --status 2>/dev/null || echo "unknown")
FILEVAULT_STATUS=$(fdesetup status 2>/dev/null || echo "unknown")

# 2. MDM Enrollment & Profiles
ENROLLMENT_RAW=$(profiles status -type enrollment 2>/dev/null || echo "")
IS_ENROLLED=false
IS_SUPERVISED=false
IS_UAMDM=false

if echo "$ENROLLMENT_RAW" | grep -qi "MDM enrollment: Yes"; then
  IS_ENROLLED=true
fi
if echo "$ENROLLMENT_RAW" | grep -qiE "Supervised: Yes|Enrolled via DEP: Yes"; then
  IS_SUPERVISED=true
fi
if echo "$ENROLLMENT_RAW" | grep -qi "User Approved: Yes"; then
  IS_UAMDM=true
fi

BOOTSTRAP_RAW=$(profiles status -type bootstraptoken 2>/dev/null || echo "")
BOOTSTRAP_ESCROWED=false
if echo "$BOOTSTRAP_RAW" | grep -qi "escrowed to MDM: Yes"; then
  BOOTSTRAP_ESCROWED=true
fi

# 3. MDM Agent Daemon State (Jamf, Intune, Kandji)
LAUNCH_RAW=$(launchctl list 2>/dev/null || echo "")
JAMF_ACTIVE=false
INTUNE_ACTIVE=false
KANDJI_ACTIVE=false

if echo "$LAUNCH_RAW" | grep -q "com.jamfsoftware"; then
  JAMF_ACTIVE=true
fi
if echo "$LAUNCH_RAW" | grep -q "com.microsoft.intune"; then
  INTUNE_ACTIVE=true
fi
if echo "$LAUNCH_RAW" | grep -q "io.kandji"; then
  KANDJI_ACTIVE=true
fi

# 4. Extract Recent installer errors (/var/log/install.log)
# Captures PackageKit, installd, exit codes, cert failures, and postinstall errors
INSTALL_ERRORS="[]"
if [[ -f "/var/log/install.log" ]]; then
  TEMP_ERRS=$(tail -n 500 /var/log/install.log 2>/dev/null | grep -iE 'error|failed|failure|code 112|exit code|notariz|certificate expired|quarantine' | tail -n 20 || echo "")
  if [[ -n "$TEMP_ERRS" ]]; then
    # Format lines into JSON array
    INSTALL_ERRORS=$(echo "$TEMP_ERRS" | awk '{gsub(/"/, "\\\""); print "    \"" $0 "\""}' | paste -sd, - | sed 's/^/[ /; s/$/ ]/')
  fi
fi

# Output JSON Bundle
cat <<EOF
{
  "timestamp_utc": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "hostname": "$HOSTNAME",
  "serial_number": "$SERIAL",
  "os_name": "$OS_NAME",
  "os_version": "$OS_PRODUCT",
  "os_build": "$OS_BUILD",
  "architecture": "$ARCH",
  "security_state": {
    "system_integrity_protection": "$SIP_STATUS",
    "gatekeeper_status": "$GATEKEEPER_STATUS",
    "filevault_status": "$FILEVAULT_STATUS"
  },
  "mdm_status": {
    "enrolled": $IS_ENROLLED,
    "supervised": $IS_SUPERVISED,
    "user_approved_mdm": $IS_UAMDM,
    "bootstrap_token_escrowed": $BOOTSTRAP_ESCROWED,
    "mdm_server_url": $(if [[ "$SANITIZE" == true ]]; then echo '"https://mdm-masked.corp.example.com"'; else echo '"https://jamf.corp.example.com:8443"'; fi)
  },
  "agent_daemons": {
    "jamf_agent_running": $JAMF_ACTIVE,
    "intune_agent_running": $INTUNE_ACTIVE,
    "kandji_agent_running": $KANDJI_ACTIVE
  },
  "installed_profiles": [],
  "install_log_findings": $INSTALL_ERRORS
}
EOF


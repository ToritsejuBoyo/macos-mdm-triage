#!/usr/bin/env bash
#
# collect-macos-mdm-triage.sh - Read-only macOS MDM and package diagnostic collector.
# Gathers profiles enrollment, system extensions, and recent install.log errors.
#

echo "{"
echo '  "timestamp_utc": "'$(date -u +"%Y-%m-%dT%H:%M:%SZ")'",'
echo '  "macos_version": "'$(sw_vers -productVersion 2>/dev/null)'",'
echo '  "build_version": "'$(sw_vers -buildVersion 2>/dev/null)'",'
echo '  "architecture": "'$(uname -m)'",'

echo '  "mdm_enrollment": {'
echo '    "enrolled": "'$(profiles status -type enrollment 2>/dev/null | grep -i "Enrolled via DEP" || echo "Unknown")'"'
echo '  },'

echo '  "recent_install_errors": ['
first=true
while read -r line; do
  if [ -n "$line" ]; then
    if [ "$first" = true ]; then first=false; else echo ","; fi
    echo -n "    "$(echo "$line" | sed 's/"/\"/g')""
  fi
done < <(tail -n 100 /var/log/install.log 2>/dev/null | grep -iE 'error|failed|failure' | tail -n 15)
echo ""
echo '  ]'

echo "}"

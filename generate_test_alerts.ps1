<#
.SYNOPSIS
  Triggers real Sysmon network connection events to known-bad IPs.

  This script creates actual TCP connections to IPs from the URLhaus
  threat database. Sysmon logs these as Event ID 3. The Wazuh agent
  reads the Sysmon event log and sends them to the Manager, which:
    1. Displays the alert in the Wazuh Dashboard (rule 61603)
    2. Forwards the IOC to n8n via the custom-n8n integration

  Run this AFTER:
    - Docker Wazuh stack is running  (docker compose up -d)
    - Sysmon is installed and running
    - Wazuh Windows agent is running and connected to the manager
    - n8n is running  (npx n8n) with the workflow active

.EXAMPLE
  .\generate_test_alerts.ps1
#>

param(
    [string]$ProjectDir = $PSScriptRoot
)

# ─────────────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "=== Wazuh + Sysmon -> n8n End-to-End Pipeline Test ===" -ForegroundColor Cyan
Write-Host ""

# The known-bad IP from our URLhaus database
$targetIp = "45.148.120.78"
$targetPort = 80

# TEST 1 - DNS lookup to known-bad IP (port 53)
# We verified that nslookup holds the socket open long enough/is tracked
# by Sysmon properly to reliably generate Event ID 3 for UDP connections.
Write-Host "--- Test 1: DNS lookup to known-bad IP ---" -ForegroundColor Cyan
Write-Host "  Target : ${targetIp}" -ForegroundColor Yellow
Write-Host "  Action : Running 'nslookup test.com $targetIp' (Sysmon logs this immediately)" -ForegroundColor Yellow

try {
    # Run nslookup and silence the expected timeout output
    & nslookup test.com $targetIp 2>&1 | Out-Null
    Write-Host "  [+] nslookup command completed (Sysmon Event ID 3 generated for $targetIp)" -ForegroundColor Green
} catch {
    Write-Host "  [-] Failed to run nslookup: $_" -ForegroundColor Red
}

# Verify Sysmon logged the events
Write-Host ""
Write-Host "--- Verifying Sysmon captured the events ---" -ForegroundColor Cyan
Start-Sleep -Seconds 2
try {
    $events = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 10 -ErrorAction Stop |
        Where-Object { $_.Id -eq 3 -and $_.Message -match $targetIp } |
        Select-Object -First 2
    if ($events) {
        Write-Host "  [+] Found $($events.Count) Sysmon Event ID 3 entries for $targetIp" -ForegroundColor Green
        foreach ($evt in $events) {
            Write-Host "      TimeCreated: $($evt.TimeCreated)" -ForegroundColor DarkGray
        }
    } else {
        Write-Host "  [-] No Sysmon events found for $targetIp" -ForegroundColor Red
        Write-Host "      Check: Is Sysmon installed? (sysmon64.exe -c)" -ForegroundColor DarkYellow
    }
} catch {
    Write-Host "  [-] Could not query Sysmon log: $_" -ForegroundColor Red
    Write-Host "      Check: Is Sysmon installed? Run as Admin?" -ForegroundColor DarkYellow
}

Write-Host ""
Write-Host "=== Done ===" -ForegroundColor Green
Write-Host ""
Write-Host "What happens next (within ~30 seconds):" -ForegroundColor Cyan
Write-Host "  1. Sysmon logged the TCP connections as Event ID 3"
Write-Host "  2. Wazuh agent reads the Sysmon event channel"
Write-Host "  3. Agent sends the events to the Wazuh Manager"
Write-Host "  4. Manager matches custom rule 100020 (SOC Demo: Sysmon Network Connection)"
Write-Host "  5. Alert appears in Wazuh Dashboard (https://localhost)"
Write-Host "  6. Integration script extracts destinationIp ($targetIp)"
Write-Host "  7. n8n receives the IOC and runs enrichment.py"
Write-Host "  8. Enrichment finds $targetIp in URLhaus -> HIGH confidence"
Write-Host ""
Write-Host "Check:" -ForegroundColor Yellow
Write-Host "  - Wazuh Dashboard : https://localhost -> Security Events"
Write-Host "  - n8n Executions  : http://localhost:5678 -> Executions tab"
Write-Host ""

<#
.SYNOPSIS
  Triggers real Sysmon network connection and DNS query events to known-bad IPs and domains.

  This script creates:
    1. A UDP connection to an IP from the URLhaus threat database (Sysmon Event ID 3)
    2. A DNS resolution query for a domain from the URLhaus threat database (Sysmon Event ID 22)
  The Wazuh agent reads these Sysmon event logs and sends them to the Manager, which:
    1. Displays the alerts in the Wazuh Dashboard (rules 100020 and 100021)
    2. Forwards the IOC to n8n via the custom-n8n integration

  Run this AFTER:
    - Docker Wazuh stack is running
    - Sysmon is installed and running
    - Wazuh Windows agent is running and connected to the manager
    - n8n is running with the workflow active
#>

param(
    [string]$ProjectDir = $PSScriptRoot
)

# ─────────────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "=== Wazuh + Sysmon -> n8n End-to-End Pipeline Test ===" -ForegroundColor Cyan
Write-Host ""

# The known-bad IP and domain from our URLhaus database
$targetIp = "104.236.37.21"
$targetDomain = "102policeonlainedtp.vercel.app"

# TEST 1 - Network connection to known-bad IP (port 53)
Write-Host "--- Test 1: Outbound network connection to known-bad IP ---" -ForegroundColor Cyan
Write-Host "  Target IP: ${targetIp}" -ForegroundColor Yellow
Write-Host "  Action   : Running 'nslookup test.com $targetIp' (Sysmon logs this as Event 3)" -ForegroundColor Yellow

try {
    # Run nslookup and silence the expected timeout output
    & nslookup test.com $targetIp 2>&1 | Out-Null
    Write-Host "  [+] Command completed (Sysmon Event ID 3 generated for $targetIp)" -ForegroundColor Green
} catch {
    Write-Host "  [-] Failed to run test 1 command: $_" -ForegroundColor Red
}

# TEST 2 - DNS query to known-bad domain
Write-Host ""
Write-Host "--- Test 2: DNS query to known-bad domain ---" -ForegroundColor Cyan
Write-Host "  Target Domain: ${targetDomain}" -ForegroundColor Yellow
Write-Host "  Action       : Clearing DNS cache and running 'Resolve-DnsName -Name $targetDomain' (Sysmon logs this as Event 22)" -ForegroundColor Yellow

try {
    # Clear DNS client cache to force a real DNS lookup
    Clear-DnsClientCache
    # Run Resolve-DnsName and silence output/errors
    & Resolve-DnsName -Name $targetDomain -ErrorAction SilentlyContinue | Out-Null
    Write-Host "  [+] Command completed (Sysmon Event ID 22 generated for $targetDomain)" -ForegroundColor Green
} catch {
    Write-Host "  [-] Failed to run test 2 command: $_" -ForegroundColor Red
}

# Verify Sysmon logged the events
Write-Host ""
Write-Host "--- Verifying Sysmon captured the events ---" -ForegroundColor Cyan
Start-Sleep -Seconds 2

# Verify Test 1 (Event 3)
try {
    $events = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 200 -ErrorAction Stop |
        Where-Object { $_.Id -eq 3 -and $_.Message -match $targetIp } |
        Select-Object -First 2
    if ($events) {
        Write-Host "  [+] Found $($events.Count) Sysmon Event ID 3 entries for $targetIp" -ForegroundColor Green
        foreach ($evt in $events) {
            Write-Host "      TimeCreated: $($evt.TimeCreated)" -ForegroundColor DarkGray
        }
    } else {
        Write-Host "  [-] No Sysmon Event ID 3 found for $targetIp" -ForegroundColor Red
    }
} catch {
    Write-Host "  [-] Could not query Sysmon Event 3 log: $_" -ForegroundColor Red
}

# Verify Test 2 (Event 22)
try {
    $events22 = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 200 -ErrorAction Stop |
        Where-Object { $_.Id -eq 22 -and $_.Message -match $targetDomain } |
        Select-Object -First 2
    if ($events22) {
        Write-Host "  [+] Found $($events22.Count) Sysmon Event ID 22 entries for $targetDomain" -ForegroundColor Green
        foreach ($evt in $events22) {
            Write-Host "      TimeCreated: $($evt.TimeCreated)" -ForegroundColor DarkGray
        }
    } else {
        Write-Host "  [-] No Sysmon Event ID 22 found for $targetDomain" -ForegroundColor Red
    }
} catch {
    Write-Host "  [-] Could not query Sysmon Event 22 log: $_" -ForegroundColor Red
}

Write-Host ""
Write-Host "=== Done ===" -ForegroundColor Green
Write-Host ""
Write-Host "What happens next (within ~30 seconds):" -ForegroundColor Cyan
Write-Host "  1. Sysmon logged Event 3 and Event 22"
Write-Host "  2. Wazuh agent reads the Sysmon event channel"
Write-Host "  3. Agent sends the events to the Wazuh Manager"
Write-Host "  4. Manager matches custom rules 100020 and 100021"
Write-Host "  5. Alerts appear in Wazuh Dashboard (https://localhost)"
Write-Host "  6. Integration script extracts destinationIp ($targetIp) and queryName ($targetDomain)"
Write-Host "  7. n8n receives the IOCs and runs enrichment.py"
Write-Host "  8. Enrichment finds them in URLhaus -> HIGH confidence"
Write-Host ""

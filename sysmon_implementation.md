# Sysmon Implementation Plan & Architecture

This document details the transition to the Sysmon-based alert generation strategy, explaining the data flow, logical file modifications, and an honest assessment of how this demo compares to a real-world Security Operations Center (SOC) implementation.

## 1. Information Flow: End-to-End Pipeline

The objective is to prove that a suspicious network connection on a Windows endpoint can be automatically detected, forwarded, and enriched.

1. **Trigger (`generate_test_alerts.ps1`)**: The script executes `nslookup test.com 45.148.120.78`.
2. **Detection (Sysmon)**: Sysmon monitors network activity. It detects the outbound UDP connection to `45.148.120.78` (port 53) and records **Event ID 3 (Network Connection)** in the Windows Event Log.
3. **Collection (Wazuh Agent)**: The Wazuh Windows Agent continuously monitors the `Microsoft-Windows-Sysmon/Operational` event channel, reads the new event, and transmits it to the Wazuh Manager.
4. **Analysis (Wazuh Manager)**:
   - The manager decodes the JSON-formatted Sysmon event.
   - It evaluates the event against its ruleset.
   - It matches our custom rule `100020`, elevating the event to a **Level 5 Alert**.
5. **Visibility**: Because the alert is level 5 (above the threshold of 3), it is saved to `alerts.json` and immediately appears in the **Wazuh Dashboard**.
6. **Forwarding (Integration Script)**: The Wazuh Manager's `integratord` daemon triggers `wazuh_n8n_integration.py` (configured to run on alerts >= level 3).
7. **Extraction**: The script parses the alert JSON, extracts the Sysmon `destinationIp` (`45.148.120.78`), and POSTs it to the n8n webhook.
8. **Enrichment (n8n)**: n8n receives the webhook, runs the local `enrichment.py` script against the URLhaus database, scores the IP as `HIGH` confidence, and conditionally triggers active response workflows.

---

## 2. Logical Changes to Files

To enable this pipeline, the following modifications were made:

### `generate_test_alerts.ps1`
- **Change**: Replaced arbitrary file creation (FIM) and custom log appending with a native `nslookup` command directed at a known malicious IP.
- **Why**: Native binaries making real network requests are reliably captured by Sysmon. This creates a genuine Windows forensic artifact rather than a fabricated log string.

### `sysmon_config.xml`
- **Change**: Created a minimal Sysmon configuration.
- **Why**: By default, Sysmon can be incredibly noisy. This config exclusively tracks `NetworkConnect` (Event ID 3), specifically filtering out local loopback traffic (`127.0.0.1`, `::1`) to keep the demo clean and focused.

### `wazuh_n8n_integration.py`
- **Change**: Added extraction logic for `data.win.eventdata.destinationIp`.
- **Why**: The original script only looked for `srcip` (inbound attacks) or `ipAddress` (Windows logon events). Sysmon Event 3 stores the outbound target IP in `destinationIp`. We must extract this specific field to cross-reference it against our threat databases.

### `wazuh_custom_rules.xml`
- **Change**: Added rule `100020` to trigger on Sysmon Event 3 (`if_sid 185001`) and elevate its severity to `level 5`.
- **Why**: *This is the crux of the pipeline.* Wazuh's default ruleset categorizes raw Sysmon Event 3 connections as `level 0` (informational). Level 0 events are silently discarded by the manager—they do not trigger integrations and are not stored in the dashboard. Elevating the level ensures the alert survives the manager and reaches n8n.

---

## 3. Real SOC vs. Demo Reality (The "Fakery" Analysis)

While the *architecture* (Agent -> SIEM -> Integration -> SOAR -> Enrichment) perfectly mirrors a modern enterprise SOC, the *trigger mechanism* deviates significantly from realistic security practices.

### The Rule Change: Elevating ALL Network Connections
> [!WARNING]
> **Deviation from Reality**: In this demo, we elevate *every single* outbound Sysmon network connection to a Level 5 alert using rule `100020`. 

**Why it's not okay for a real SOC:**
In a corporate environment, endpoints make thousands of legitimate network connections a minute (web browsing, background updates). Elevating Sysmon Event 3 to a Level 5 alert universally would result in a catastrophic alert flood, instantly overwhelming the SIEM, the network, and the analysts. 

**How a real SOC handles this:**
A real SOC keeps the base Sysmon Event 3 at `level 0` (silently collected). They then write highly specific child rules that elevate to Level 5+ *only if*:
- The connection originates from an untrusted process (e.g., `powershell.exe` reaching out to the internet).
- The destination IP is *already known* to a threat intelligence feed ingested directly into the SIEM (e.g., Wazuh's CDB lists).
- The connection correlates with a recently downloaded executable.

### The Test Method: Triggering with `nslookup`
> [!CAUTION]
> **Deviation from Reality**: We are artificially running `nslookup` against a known-malware IP just to generate the Sysmon log.

**Why it's faked:**
We know the IP is in our local enrichment database, so we force a connection to it to ensure n8n returns a `HIGH` score. In reality, a user clicking a phishing link or malware beaconing out to its Command & Control (C2) server would generate this traffic organically. 

### Conclusion
The **plumbing** (the integrations, the data extraction, the n8n logic) is highly realistic and production-grade. The **trigger** is heavily contrived to guarantee a successful demonstration in a sterile environment without deploying live malware.

---

## 4. Failures Observed and Overcome

The path to this Sysmon architecture involved navigating several technical hurdles:

1. **The FIM Hash Failure**: We initially tried using File Integrity Monitoring (FIM). We generated a dummy text file, which Wazuh detected. However, the file's hash was random and would never exist in URLhaus/MalwareBazaar, meaning enrichment would always return `LOW` confidence. We abandoned FIM because it couldn't demonstrate a successful threat intel match.
2. **The File Lock Conflict**: We attempted to write custom log strings (`SOC_ALERT: OUTBOUND_CONNECTION`) to a local file monitored by the Wazuh agent. PowerShell's `Add-Content` threw "file in use" errors because the Wazuh Agent maintained a persistent read lock on the file. We had to use .NET `FileStream` to bypass this, but ultimately abandoned custom logs for organic Sysmon events.
3. **TCP Timeout Silencing Sysmon**: We initially used PowerShell TCP sockets to connect to the malicious IPs. Because the malware servers were offline, the TCP handshakes never completed. Sysmon *only* logs TCP connections if the handshake succeeds.
4. **UDP Socket Evasion**: We switched to UDP (which has no handshake) using `.NET UdpClient`. However, the raw socket opened and closed so rapidly that the Sysmon driver occasionally failed to hook and record the event.
5. **The `nslookup` Solution**: We finally settled on using the native Windows `nslookup` binary. It holds the UDP socket open long enough for Sysmon to reliably capture and log Event ID 3.
6. **Wazuh's Silent Discard (Level 0)**: Even after Sysmon successfully logged the event and the agent transmitted it, nothing appeared in the Wazuh dashboard or n8n. We discovered that Wazuh's default rule `185001` assigns Sysmon Event 3 a `level 0`, causing the manager to silently drop the event. We resolved this by writing custom rule `100020` to elevate it.

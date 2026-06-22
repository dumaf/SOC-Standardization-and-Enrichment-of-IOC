#!/usr/bin/env python3
"""
Wazuh -> n8n Custom Integration Script
=======================================
Deployed inside the Wazuh manager container at:
  /var/ossec/integrations/custom-n8n

Wazuh integratord calls it as:
  custom-n8n <alert_file_path> <api_key> <hook_url>

Reads the alert JSON, extracts the best enrichable IOC, and POSTs
a normalized payload to the n8n enrichment webhook.

IOC Priority: external_srcip > url > sha256 (FIM) > domain
Private/loopback IPs are skipped — they are not enrichable IOCs.
"""

import json
import sys
import urllib.request
import urllib.error
from typing import Optional

# Fallback if hook_url is not passed via ossec.conf
FALLBACK_WEBHOOK = "http://host.docker.internal:5678/webhook/firewall-alert"


def _is_private(ip: str) -> bool:
    """Returns True for RFC1918, loopback, and link-local addresses."""
    return (
        ip.startswith("10.")
        or ip.startswith("192.168.")
        or ip.startswith("172.")       # simplified; covers 172.0.0.0/8
        or ip.startswith("127.")
        or ip.startswith("169.254.")
        or ip in ("::1", "0.0.0.0", "-", "")
    )


def extract_ioc(alert: dict) -> Optional[dict]:
    """
    Walk the Wazuh alert structure and extract the most enrichable IOC.
    Returns a flat dict ready to POST to n8n, or None if nothing found.
    """
    data  = alert.get("data", {})
    rule  = alert.get("rule", {})
    agent = alert.get("agent", {})

    ioc      = None
    ioc_type = None

    # 1. Network: external source IP (most useful for SOC — indicates inbound attack)
    for field in ("srcip", "src_ip", "sourceIp"):
        val = data.get(field, "").strip()
        if val and not _is_private(val):
            ioc, ioc_type = val, "ip"
            break

    # Windows event data source address (e.g. failed RDP logon, event 4625)
    if not ioc:
        win_ip = (
            data.get("win", {})
                .get("eventdata", {})
                .get("ipAddress", "")
                .strip()
        )
        if win_ip and not _is_private(win_ip):
            ioc, ioc_type = win_ip, "ip"

    # Sysmon Event 3: Network Connection — outbound destination IP
    if not ioc:
        sysmon_dst = (
            data.get("win", {})
                .get("eventdata", {})
                .get("destinationIp", "")
                .strip()
        )
        if sysmon_dst and not _is_private(sysmon_dst):
            ioc, ioc_type = sysmon_dst, "ip"

    # 2. URL from web/proxy/firewall log fields
    if not ioc:
        for field in ("url", "URL", "http_url"):
            val = data.get(field, "").strip()
            if val and val.startswith(("http://", "https://")):
                ioc, ioc_type = val, "url"
                break

    # 3. File hash from FIM (syscheck module monitors file changes)
    if not ioc:
        for field in ("sha256_after", "sha256", "md5_after", "md5"):
            val = data.get(field, "").strip()
            if val and len(val) in (32, 64):          # MD5 or SHA-256 length
                ioc_type = "sha256" if len(val) == 64 else "md5"
                ioc = val
                break

    # 4. Domain from DNS query fields
    if not ioc:
        dns_name = (
            data.get("dns", {})
                .get("question", {})
                .get("name", "")
                .strip()
        )
        if dns_name:
            ioc, ioc_type = dns_name, "domain"

    if not ioc:
        return None      # nothing enrichable in this alert, skip silently

    return {
        # Fields consumed by n8n Execute Command: enrichment.py "<ioc>"
        "ioc":             ioc,
        "ioc_type":        ioc_type,
        # Wazuh metadata — passed through for Active Response and audit trail
        "wazuh_rule_id":   rule.get("id"),
        "wazuh_rule_desc": rule.get("description"),
        "wazuh_level":     rule.get("level"),
        "wazuh_agent_id":  agent.get("id", "001"),
        "wazuh_agent":     agent.get("name"),
        "wazuh_timestamp": alert.get("timestamp"),
    }


def main() -> None:
    if len(sys.argv) < 2:
        sys.exit(1)

    alert_file = sys.argv[1]
    hook_url   = sys.argv[3] if len(sys.argv) > 3 else FALLBACK_WEBHOOK

    # Wazuh passes the hook_url; validate it looks like a URL
    if not hook_url.startswith("http"):
        hook_url = FALLBACK_WEBHOOK

    try:
        with open(alert_file, "r", encoding="utf-8") as fh:
            alert = json.load(fh)
    except Exception:
        sys.exit(1)

    payload = extract_ioc(alert)
    if not payload:
        sys.exit(0)      # no IOC found — exit cleanly (not an error)

    body = json.dumps(payload).encode("utf-8")
    req  = urllib.request.Request(
        hook_url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        urllib.request.urlopen(req, timeout=10)
    except Exception:
        sys.exit(1)      # n8n unreachable; Wazuh will log the failure


if __name__ == "__main__":
    main()

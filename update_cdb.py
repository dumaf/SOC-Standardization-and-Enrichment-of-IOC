"""URLhaus CDB list generator and synchronizer for Wazuh.

Reads abuse_stream.jsonl, extracts all IPs and domains from URLhaus indicators,
writes them in Wazuh CDB format (key:), copies them to the wazuh-manager container,
sets ownership/permissions, and restarts the Wazuh manager to compile the CDB.
"""

import json
import os
import re
import subprocess
import sys
from urllib.parse import urlparse

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
INPUT_FILE = os.path.join(BASE_DIR, "abuse_stream.jsonl")
IPS_FILE = os.path.join(BASE_DIR, "urlhaus-ips")
DOMAINS_FILE = os.path.join(BASE_DIR, "urlhaus-domains")
CONTAINER_NAME = "single-node-wazuh.manager-1"
LISTS_DIR_IN_CONTAINER = "/var/ossec/etc/lists"

_IP_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)

_STIX_URL_RE = re.compile(r"url:value\s*=\s*'([^']+)'")


def extract_hosts():
    """Reads abuse_stream.jsonl and extracts hostnames, partitioning into IPs and domains."""
    if not os.path.exists(INPUT_FILE):
        print(f"[-] Input file not found: {INPUT_FILE}", file=sys.stderr)
        return set(), set()

    ips = set()
    domains = set()

    with open(INPUT_FILE, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue

            if obj.get("type") != "indicator":
                continue

            pattern = obj.get("pattern", "")
            m = _STIX_URL_RE.search(pattern)
            if m:
                url = m.group(1)
                try:
                    parsed = urlparse(url)
                    hostname = parsed.hostname
                    if hostname:
                        hostname = hostname.lower().strip()
                        # Remove port if present
                        if ":" in hostname and not hostname.startswith("["):
                            hostname = hostname.split(":")[0]
                        
                        if _IP_RE.match(hostname):
                            ips.add(hostname)
                        else:
                            # Verify it looks like a domain (has dots, no spaces)
                            if "." in hostname and " " not in hostname:
                                domains.add(hostname)
                except Exception as e:
                    print(f"[!] Error parsing URL '{url}': {e}", file=sys.stderr)

    return ips, domains


def write_cdb_file(items, filepath):
    """Writes list of items to a CDB text source file in key: format."""
    # Sort items for consistency and easier diffing
    sorted_items = sorted(list(items))
    with open(filepath, "w", encoding="utf-8") as f:
        for item in sorted_items:
            f.write(f"{item}:\n")
    print(f"[+] Wrote {len(sorted_items)} entries to {os.path.basename(filepath)}")


def run_cmd(cmd_list, shell=False):
    """Helper to run command and return stdout/stderr."""
    res = subprocess.run(cmd_list, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=shell)
    if res.returncode != 0:
        print(f"[!] Command failed: {' '.join(cmd_list)}", file=sys.stderr)
        print(f"[!] Error output: {res.stderr.strip()}", file=sys.stderr)
        return False, res.stdout, res.stderr
    return True, res.stdout, res.stderr


def update_cdb():
    print("[*] Starting CDB lists update process...")
    
    # 1. Extract IPs and Domains
    ips, domains = extract_hosts()
    if not ips and not domains:
        print("[-] No indicators extracted. Aborting CDB update.")
        return False

    # 2. Write local CDB files
    write_cdb_file(ips, IPS_FILE)
    write_cdb_file(domains, DOMAINS_FILE)

    # 3. Copy files to the Docker container
    print(f"[*] Copying lists to container '{CONTAINER_NAME}'...")
    
    ips_dest = f"{CONTAINER_NAME}:{LISTS_DIR_IN_CONTAINER}/urlhaus-ips"
    success, _, _ = run_cmd(["docker", "cp", IPS_FILE, ips_dest])
    if not success:
        return False

    domains_dest = f"{CONTAINER_NAME}:{LISTS_DIR_IN_CONTAINER}/urlhaus-domains"
    success, _, _ = run_cmd(["docker", "cp", DOMAINS_FILE, domains_dest])
    if not success:
        return False

    # 4. Set correct ownership and permissions in container
    print("[*] Setting file permissions inside container...")
    perms_cmd = [
        "docker", "exec", CONTAINER_NAME, "bash", "-c",
        f"chown root:wazuh {LISTS_DIR_IN_CONTAINER}/urlhaus-ips {LISTS_DIR_IN_CONTAINER}/urlhaus-domains && "
        f"chmod 660 {LISTS_DIR_IN_CONTAINER}/urlhaus-ips {LISTS_DIR_IN_CONTAINER}/urlhaus-domains"
    ]
    success, _, _ = run_cmd(perms_cmd)
    if not success:
        return False

    # 5. Restart Wazuh manager to compile CDB lists and apply changes
    print("[*] Restarting Wazuh manager to compile lists...")
    restart_cmd = ["docker", "exec", CONTAINER_NAME, "/var/ossec/bin/wazuh-control", "restart"]
    success, stdout, _ = run_cmd(restart_cmd)
    if not success:
        return False
        
    print("[+] Wazuh manager restarted and CDB lists compiled successfully!")
    return True


if __name__ == "__main__":
    if update_cdb():
        print("[+] CDB Sync complete!")
    else:
        print("[!] CDB Sync failed!")
        sys.exit(1)

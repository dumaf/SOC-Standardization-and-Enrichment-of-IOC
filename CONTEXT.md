# Project Context: SOC Standardization and Enrichment of IOCs

## Project Goals
- Create a closed-loop automated SOC (Security Operations Center) pipeline for demonstration purposes.
- Pipeline flow: Wazuh Agent detects threat -> Wazuh Manager dashboard -> Custom Integration -> n8n webhook -> Threat Enrichment script (cross-referencing local URLhaus/MalwareBazaar STIX data) -> Automated Response (optional/pending).
- The primary objective is to prove that a real Wazuh alert generated on a Windows endpoint can be organically forwarded, enriched, and acted upon, demonstrating a realistic enterprise security workflow.

## Current Architecture
- **Wazuh Server**: Deployed locally on Windows via Docker Desktop using the official `wazuh-docker` single-node compose stack.
- **Wazuh Agent**: Installed natively on the Windows host machine, connected to the local Docker manager (`127.0.0.1`).
- **Automation Platform**: n8n, running locally via `npx n8n`.
- **Enrichment Engine**: A Python script (`enrichment.py`) that queries local JSONL databases (`abuse_stream.jsonl`, `malwarebazaar_recent.jsonl`).
- **Integration Layer**: A custom Python script (`wazuh_n8n_integration.py`) deployed inside the Wazuh Manager container (`/var/ossec/integrations/custom-n8n`) that parses Wazuh alerts, extracts IOCs, and POSTs them to the n8n webhook.

## System Components
- **Wazuh Manager/Dashboard/Indexer**: Containerized SIEM stack handling log collection, decoding, rules processing, and alert visualization.
- **Wazuh Windows Agent**: Endpoint monitor collecting events.
- **n8n Webhook Listener**: Entry point for automated workflows (`http://host.docker.internal:5678/webhook/firewall-alert`).
- **Enrichment Script**: `enrichment.py`, processes IOCs and returns threat intelligence scoring.

## File Responsibilities
- `wazuh_n8n_integration.py`: Resides in the Wazuh Manager container. Extracts the most relevant IOC (IP, URL, Hash, Domain) from an `alerts.json` event, filters out private/internal IPs, and sends a normalized JSON payload to n8n.
- `Enrichment_workflow.json`: n8n workflow definition. Receives the webhook, executes `enrichment.py`, processes the results, and routes high-confidence threats to Active Response nodes.
- `generate_test_alerts.ps1`: Utility script to simulate alerts. (Currently undergoing a redesign to write to a monitored log file instead of POSTing directly to n8n).
- `ossec.conf`: Wazuh Manager configuration file. Modified to include the `<integration>` block pointing to the `custom-n8n` script.
- `.env`: Environment variables (API keys, Wazuh credentials, webhook URLs).
- `docker-compose.yml`: (Inside `wazuh-docker/single-node/`) Defines the Wazuh container stack, ports, and named volume mounts.

## Design Decisions Made
- **Docker for Wazuh (over native WSL)**: Chosen because WSL lacks native `systemd` support out of the box (causing complex daemon management issues), suspends when idle (breaking continuous monitoring), and is harder to cleanly rebuild. Docker provides isolated, pre-configured containers with persistent named volumes.
- **Local JSONL Databases for Enrichment**: Using `abuse_stream.jsonl` and `malwarebazaar_recent.jsonl` locally instead of live API calls (like VirusTotal) to ensure fast, reliable enrichment for the demo without rate-limiting concerns.
- **Custom Integration Script (`wazuh_n8n_integration.py`)**: Needed because Wazuh's native webhook integration sends the entire raw alert JSON, which is complex to parse in n8n. The custom script parses the alert at the source, prioritizes the most actionable IOC (external IP > URL > Hash > Domain), filters out private IPs, and sends a clean, targeted payload.
- **Integration Placement**: Inserted the `<integration>` block just before the final `</ossec_config>` tag in the manager's `ossec.conf`.
- **Testing Strategy Redesign (Option C)**: Instead of faking webhooks or triggering arbitrary FIM alerts (which yield benign hashes), the final testing strategy is to create a custom Wazuh rule, monitor a specific log file via the Windows Agent, and inject known-bad IPs from the URLhaus database into that log file. This exercises the *entire* organic pipeline (Agent -> Manager -> Dashboard -> Integration -> n8n -> Enrichment) while guaranteeing a high-confidence threat match.

## Design Decisions Rejected and Why
- **Native WSL Wazuh Install**: Rejected due to systemd issues, sleep/suspend behavior, and SSL certificate generation complexity.
- **Direct Webhook Testing for Demo**: The initial `generate_test_alerts.ps1` POSTed directly to n8n. Rejected because it bypassed the Wazuh Dashboard and Manager, failing to demonstrate the SIEM detection aspect of the pipeline.
- **FIM (File Integrity Monitoring) for Demo**: Triggering an alert by creating a random text file. Rejected because the resulting file hash would never match the known-bad threat intelligence databases. This would cause the enrichment to correctly return "no match," making for an unconvincing demo. FIM alerts also do not logically map to firewall blocking responses.
- **Failed Login Brute-Force Testing**: Rejected because the source IP of a local test would be `127.0.0.1`, which the integration script intentionally ignores as a non-enrichable private IP.

## Assumptions
- The host OS is Windows.
- Docker Desktop is running and configured to support Linux containers.
- Node.js/npm is installed to run n8n natively.
- The necessary STIX/JSONL databases exist locally.

## Dependencies
- Docker Desktop
- `wazuh-docker` repository (single-node)
- Wazuh Windows Agent (v4.12.0, matching the server version)
- n8n
- Python 3 (for enrichment scripts)

## Environment Setup
1. Clone `wazuh-docker`, navigate to `single-node`.
2. Generate certs: `docker compose -f generate-indexer-certs.yml run --rm generator`.
3. Start Wazuh: `docker compose up -d` (Must be run from inside the `single-node` directory).
4. Install Wazuh Windows Agent via MSI, pointing `WAZUH_MANAGER` to `127.0.0.1`.
5. Copy `wazuh_n8n_integration.py` to the manager: `docker cp wazuh_n8n_integration.py single-node-wazuh.manager-1:/var/ossec/integrations/custom-n8n`.
6. Set permissions in the container: `chmod 755 /var/ossec/integrations/custom-n8n` and `chown root:wazuh /var/ossec/integrations/custom-n8n`.
7. Extract, edit, and replace `/var/ossec/etc/ossec.conf` to add the `<integration>` block pointing to `http://host.docker.internal:5678/webhook/firewall-alert`.
8. Restart Wazuh Manager: `docker exec single-node-wazuh.manager-1 /var/ossec/bin/wazuh-control restart`.
9. Start n8n: run `npx n8n` in the project root.
10. Import `Enrichment_workflow.json` into n8n and publish it.

## Known Issues
- **Container Tooling Limitations**: The Wazuh manager container lacks terminal text editors (`nano`, `vi`), requiring configuration files to be extracted via `docker cp`, edited locally, and copied back.
- **n8n Workflow Editor State Confusion**: Importing workflows can duplicate nodes on the canvas. If the canvas has unsaved changes (yellow dot), external webhook triggers will execute the *last published* version, not the current visible draft. This can cause confusing execution histories where new nodes are seemingly ignored.

## Debugging Discoveries
- **Docker Compose Context**: Running `docker compose up` must be done inside the `wazuh-docker/single-node` directory so relative volume mounts and the `.yml` file are resolved correctly.
- **Docker `cp` Context**: PowerShell commands executing `docker cp` failed when the terminal was inside the `single-node` folder but referencing a script in the project root without using relative paths (`..\..\`).
- **PowerShell String Parsing**: The `generate_test_alerts.ps1` script failed due to unescaped smart quotes (`—` vs `-`) and unclosed strings, highlighting PowerShell's strict syntax parsing.
- **Data Persistence**: Docker named volumes (`wazuh_etc`, `wazuh_integrations`) persist even if the containers are deleted in the Docker Desktop UI, ensuring custom configurations and scripts survive restarts. n8n state is safely stored in a local SQLite database (`~/.n8n/database.sqlite`).

## Lessons Learned
- **End-to-End Testing Must Be Organic**: Testing a pipeline by faking inputs midway (sending mock HTTP payloads directly to n8n) invalidates the demonstration of the integration layer. The alert must originate from the agent to prove the system works.
- **Threat Intel Demos Require Careful Staging**: You cannot rely on random filesystem noise (FIM) to trigger a meaningful threat intelligence match. To successfully demo enrichment, you must plant known IOCs (from the actual database being queried) into monitored log streams.

## Current Project State
- The Wazuh infrastructure (Manager, Dashboard, Indexer) and Windows Agent are installed and running.
- The custom integration script is deployed and configured in the Manager.
- n8n is running with the imported, cleaned-up workflow (Active Response nodes included).
- The project is pivoting to implement "Option C": a custom Wazuh rule that monitors a local log file, allowing injection of known-bad IPs to trigger organic alerts.

## Next Steps
1. Create custom Wazuh decoder and rules XML to detect a specific injected log format (e.g., "OUTBOUND_CONNECTION to <ip>").
2. Deploy these custom rules to the Wazuh Manager container.
3. Modify the Wazuh Windows Agent `ossec.conf` to add a `<localfile>` block monitoring a specific test log file (e.g., `C:\SOC_test\alerts.log`).
4. Rewrite `generate_test_alerts.ps1` to extract a known-bad IP from `abuse_stream.jsonl` and append it into the monitored log file, rather than POSTing to n8n.
5. Test the end-to-end flow and verify the alert appears in the Wazuh dashboard *and* triggers the n8n enrichment pipeline.

## Open Questions
- Should the Active Response nodes in the n8n workflow be fully implemented to execute a firewall block on the Windows host, or should the demo conclude at the enrichment/notification stage?

---

## PROJECT HISTORY

**Event 1: Project Initiation & Architecture Selection**
- **What happened**: User requested a closed-loop automated SOC demo combining Wazuh, n8n, and local STIX threat databases. Discussed deploying Wazuh natively on WSL vs. Docker. Decided on Docker.
- **Why it happened**: WSL native installations struggle with `systemd` daemon management and idle suspension. Docker provides a robust, pre-configured stack (`wazuh-docker`).
- **Outcome**: User cloned `wazuh-docker` and spun up the single-node stack on Windows.

**Event 2: Pipeline Component Creation**
- **What happened**: Agent generated three core files: `wazuh_n8n_integration.py` (Wazuh integration script), `Enrichment_workflow.json` (n8n workflow), and `generate_test_alerts.ps1` (PowerShell test script).
- **Why it happened**: To bridge the gap between Wazuh Manager alerts and the n8n webhook, and to provide a way to simulate alerts for the demo.
- **Outcome**: Files were saved to the project root. The `.env` file was updated with relevant credentials.

**Event 3: Debugging Docker `cp` Path Issues**
- **What happened**: User attempted to copy the integration script into the container but received a "file not found" error.
- **Why it happened**: User's terminal was located in `wazuh-docker/single-node`, but the script was in the project root.
- **Outcome**: Agent provided the correct relative path (`..\..\`) and explained the context issue.

**Event 4: Docker Compose Context Clarification**
- **What happened**: User asked why they had to `cd` into `single-node` to run `docker compose up`.
- **Why it happened**: Docker compose relies on the CWD to locate `docker-compose.yml` and resolve relative volume mounts.
- **Outcome**: Agent explained the necessity of running compose commands from the directory containing the config file.

**Event 5: Editing `ossec.conf` without Container Text Editors**
- **What happened**: User tried to `nano` or `vi` the `ossec.conf` file inside the Wazuh manager container, but the tools were not installed.
- **Why it happened**: The official Wazuh Docker image is stripped down and lacks standard text editors.
- **Outcome**: Agent instructed the user to `docker cp` the file to the host, edit it locally to add the `<integration>` block, and `docker cp` it back, followed by a service restart.

**Event 6: Debugging n8n Execution History**
- **What happened**: User reported that n8n was executing an older, simpler version of the workflow, and the latest executions weren't showing the new Active Response nodes.
- **Why it happened**: The user had imported the workflow multiple times, resulting in duplicate nodes on the canvas. The canvas had unsaved changes (draft state), so external webhooks triggered the last *published* version.
- **Outcome**: Agent guided the user to delete duplicate nodes, verify the webhook path, and click 'Publish' to activate the new pipeline.

**Event 7: Fixing PowerShell Syntax Errors**
- **What happened**: Running `generate_test_alerts.ps1` produced parsing errors regarding the `&` character and missing string terminators.
- **Why it happened**: The script contained unescaped smart quotes (`—`) which broke string termination in PowerShell.
- **Outcome**: The user manually corrected the quotes, and the script executed successfully.

**Event 8: Addressing Data Persistence Concerns**
- **What happened**: User accidentally deleted the containers in Docker Desktop and closed their terminals, fearing lost progress.
- **Why it happened**: Misunderstanding of how Docker Desktop handles container deletion vs. volume deletion.
- **Outcome**: Agent confirmed that progress was safe because Wazuh configurations are stored in Docker named volumes (`wazuh_etc`), and n8n workflows are saved in a local SQLite database.

**Event 9: Strategic Pivot on Alert Generation (Option C)**
- **What happened**: User questioned the logic of using a FIM (File Integrity Monitoring) alert to trigger a firewall block, noting it doesn't make sense and the fake alert wasn't appearing in the Wazuh dashboard. User requested a redesign of the testing approach.
- **Why it happened**: The initial test script bypassed Wazuh entirely for HTTP payload tests, and the FIM test produced arbitrary hashes that would never match threat databases. This failed the core goal of demonstrating a realistic, end-to-end SIEM detection and enrichment flow.
- **Outcome**: Agent proposed "Option C": writing a custom Wazuh rule, monitoring a local log file, and injecting known-bad IPs from the local STIX databases into that log. This ensures a real alert is generated, visible in the dashboard, and guaranteed to yield a high-confidence threat match in n8n. The project context was documented to hand over to a new agent for this implementation.

12:14 thursday^

Option D: DNS Query to Known-Bad Domain (via Sysmon)
How: Install Sysmon, configure Wazuh to monitor Sysmon logs, then do nslookup to a known-bad domain.
Problem: Requires installing and configuring Sysmon — adds complexity. Also, the domain needs to be in our database.
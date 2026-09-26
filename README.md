# Linux SOC Automation

A Linux-based SOC automation project built with Wazuh and Python.

The system monitors Wazuh alerts, detects SSH brute-force activity, extracts indicators, enriches the source IP with AbuseIPDB, sends notifications to Discord, simulates a response, and records the incident.
## Workflow

SSH Authentication Failure
            ↓
          Wazuh
            ↓
       alerts.json
            ↓
    Python SOC Monitor
            ↓
      IOC Extraction
            ↓
        AbuseIPDB
            ↓
         Discord
            ↓
      Dry-Run Response
            ↓
      Incident Logging

## Features

- Continuous monitoring of Wazuh alerts.json

- SSH brute-force detection using Wazuh Rule 2502

- IOC extraction including source IP and username

- MITRE ATT&CK mapping (T1110)

- AbuseIPDB threat-intelligence enrichment

- Discord security notifications

- Automated response workflow in dry-run mode

- JSON incident logging

- Least-privilege access to Wazuh alert files

## Project Structure

```text
linux-soc-automation/
│
├── detection/
│   ├── ssh_bruteforce.py
│   ├── abuseipdb_test.py
│   ├── discord_test.py
│   └── incident_log.example.json
│
├── .gitignore
└── README.md
```

## Example Detection

WAZUH SECURITY ALERT
Severity        : 10
Rule ID         : 2502
Source IP       : 127.0.0.1
Username        : testuser
MITRE ID        : ['T1110']

The system then performs threat-intelligence enrichment, sends a Discord notification, and records the incident.
## Security

API credentials are kept outside the source code using environment variables:

ABUSEIPDB_API_KEY
DISCORD_WEBHOOK_URL

The actual generated incident_log.json is excluded from GitHub. A sanitized example is provided instead.

The project uses 127.0.0.1 for controlled lab testing. The response mechanism is currently configured for dry-run operation, so no firewall changes are made automatically.
## Running the Project

Set the required environment variables and run:

cd ~/linux-soc-automation/detection
python3 ssh_bruteforce.py

The monitor will wait for new Wazuh alerts and process matching events automatically.
## Technologies

    Linux

    Wazuh

    Python

    AbuseIPDB

    Discord Webhooks

    Git / GitHub

    MITRE ATT&CK

## Future Improvements

    Support additional Wazuh detection rules

    Add more IOC types

    Add controlled firewall enforcement

    Improve incident visualization

    Expand automated response capabilities

## Disclaimer

This project was built as a cybersecurity learning project in a controlled lab environment.

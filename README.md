Linux-Based SOC & Automated Threat Response System

A small cybersecurity lab project I built to understand how a SOC automation workflow works from start to finish.

The project monitors Wazuh security alerts, detects SSH brute-force activity, extracts useful information from the alert, checks the source IP with AbuseIPDB, sends a notification to Discord, and records the incident in a local JSON log.

The whole thing is running in a Linux lab environment, so the attacks and responses are controlled and safe.
What the project does

The current workflow looks like this:

SSH login failures
        ↓
      Wazuh
        ↓
   alerts.json
        ↓
 Python SOC Monitor
        ↓
 Rule 2502 detected
        ↓
   IOC extraction
        ↓
   AbuseIPDB check
        ↓
 Discord notification
        ↓
  Dry-run response
        ↓
 Incident log

The main goal was not just to detect an attack, but to connect several parts of a basic SOC workflow together.
Detection

Wazuh is monitoring the Linux system and generates an alert when repeated SSH authentication failures are detected.

The Python script monitors:

/var/ossec/logs/alerts/alerts.json

The main alert used by this project is Wazuh Rule 2502:

syslog: User missed the password more than one time

The alert contains information such as:

    Source IP

    Username

    Severity

    Wazuh rule ID

    MITRE ATT&CK technique

For the lab, the SSH activity is generated locally using:

127.0.0.1

This is intentional. I am not testing against real external systems.
IOC Extraction

When Rule 2502 is detected, the Python script extracts the important information into a structured object.

Example:

Source IP : 127.0.0.1
Username  : testuser
Severity  : 10
Rule ID   : 2502
MITRE     : T1110

This gives the rest of the automation pipeline structured data to work with.
AbuseIPDB Enrichment

The source IP is checked against AbuseIPDB using its API.

The script retrieves information such as:

    Abuse confidence score

    Number of reports

    Country

    ISP

API credentials are not stored in the source code. They are loaded through environment variables.

export ABUSEIPDB_API_KEY="your_api_key"

Because the testing is done against 127.0.0.1, the AbuseIPDB result should not be treated as evidence that a real external attacker is involved. It is mainly being used here to test the enrichment part of the SOC workflow.
Discord Notifications

After the alert is processed, the script sends a notification to a Discord channel using a webhook.

The webhook URL is also stored as an environment variable instead of being hardcoded:

export DISCORD_WEBHOOK_URL="your_webhook_url"

The notification contains the main alert information, IOC data, AbuseIPDB results, and the response status.
Response

The project currently uses a dry-run response mode.

It does not automatically change the firewall.

Instead, it prints:

INCIDENT RESPONSE
DRY RUN: Would block source IP 127.0.0.1
Firewall action: NOT EXECUTED

I kept this as a dry run because automatically changing firewall rules on a live system can cause problems if the logic is wrong.

The response mechanism can be extended later with a controlled and reversible firewall action.
Incident Logging

Each processed incident is written to:

detection/incident_log.json

The log contains:

    Unique incident ID

    Timestamp

    Source IP

    Username

    Severity

    Rule ID

    MITRE technique

    AbuseIPDB information

    Response action

An example file is included in the repository:

detection/incident_log.example.json

The real lab incident log is not included in the repository.
Reliability

The monitor also keeps track of processed Wazuh alert IDs during runtime.

This prevents the same alert from being processed more than once while the script is running.

The project also handles cases such as:

    Invalid JSON alert lines

    Missing AbuseIPDB API key

    Missing Discord webhook

    AbuseIPDB request failures

    Discord request failures

Security and Permissions

The Wazuh alert file is not made world-readable.

Instead, the Linux user running the automation was added to the Wazuh group so the script can read the alert file without running the entire Python program as root.

This keeps the permissions more limited than simply changing the Wazuh log file to be readable by everyone.

Secrets are also kept outside the source code using environment variables.
Project Structure

linux-soc-automation/
│
├── detection/
│   ├── ssh_bruteforce.py
│   ├── ssh_bruteforce_v1.py
│   ├── abuseipdb_test.py
│   ├── discord_test.py
│   └── incident_log.example.json
│
├── .gitignore
└── README.md

Running the Project

Make sure the required environment variables are available:

export ABUSEIPDB_API_KEY="your_api_key"
export DISCORD_WEBHOOK_URL="your_discord_webhook"

Then run:

cd ~/linux-soc-automation/detection
python3 ssh_bruteforce.py

The script will wait for new Wazuh alerts.

A controlled test can be generated with:

ssh testuser@127.0.0.1

Entering an incorrect password several times should generate the Wazuh brute-force alert.
Example Result

A successful test produces output similar to:

WAZUH SECURITY ALERT

Severity        : 10
Rule ID         : 2502
Source IP       : 127.0.0.1
Username        : testuser
MITRE ID        : ['T1110']

EXTRACTED IOC
{'source_ip': '127.0.0.1', 'username': 'testuser', 'severity': 10, 'rule_id': '2502', 'mitre': ['T1110']}

ABUSEIPDB ENRICHMENT
Abuse Confidence : 0
Total Reports    : 301

Discord notification sent

INCIDENT RESPONSE
DRY RUN: Would block source IP 127.0.0.1
Firewall action: NOT EXECUTED

What I learned

This project helped me understand how the different parts of a basic SOC workflow connect together.

Instead of looking at Wazuh, Python, threat intelligence, notifications, and response as separate things, I was able to connect them into one pipeline.

Some of the main things I worked with were:

    Linux authentication logs

    Wazuh rules and alerts

    MITRE ATT&CK mapping

    Python JSON processing

    Continuous file monitoring

    IOC extraction

    Threat intelligence APIs

    Discord webhooks

    Environment variables

    Linux permissions

    Incident logging

    Safe automated response

Future Improvements

There are several things I would like to add later:

    A proper reversible firewall blocking mechanism

    More Wazuh detection rules

    Detection for other types of attacks

    Better incident severity handling

    Persistent alert deduplication

    A small SOC dashboard

    More structured incident reports

    Automated recovery/unblocking

    Unit tests

    Containerized deployment

Disclaimer

This project is a cybersecurity learning lab.

All attack activity used during testing is controlled and performed against systems I own or have permission to test. The current demonstrations use localhost (127.0.0.1) and do not target external systems.

import json
import time
import os
import requests
import uuid

ALERT_FILE = "/var/ossec/logs/alerts/alerts.json"

TARGET_RULE_ID = "2502"
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"

DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL")

DRY_RUN = True
PROCESSED_ALERTS = set()

INCIDENT_LOG = "incident_log.json"


def log_incident(alert, abuse_data, response_action):
    incident = {
	"incident_id": str(uuid.uuid4()),
	"timestamp": alert.get("timestamp"),
        "source_ip": alert.get("data", {}).get("srcip"),
        "username": alert.get("data", {}).get("dstuser"),
        "severity": alert.get("rule", {}).get("level"),
        "rule_id": alert.get("rule", {}).get("id"),
        "mitre": alert.get("rule", {}).get("mitre", {}).get("id", []),
        "abuseipdb": {
            "abuse_confidence": abuse_data.get("abuseConfidenceScore") if abuse_data else None,
            "total_reports": abuse_data.get("totalReports") if abuse_data else None,
            "country": abuse_data.get("countryCode") if abuse_data else None,
            "isp": abuse_data.get("isp") if abuse_data else None
        },
        "response": response_action
    }

    try:
        with open(INCIDENT_LOG, "r") as file:
            incidents = json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        incidents = []

    incidents.append(incident)

    with open(INCIDENT_LOG, "w") as file:
        json.dump(incidents, file, indent=2)

def respond_to_threat(source_ip):
    if DRY_RUN:
        print()
        print("INCIDENT RESPONSE")
        print(f"DRY RUN: Would block source IP {source_ip}")
        print("Firewall action: NOT EXECUTED")
        return

    print(f"Blocking source IP: {source_ip}")

def send_discord_alert(message):
    if not DISCORD_WEBHOOK_URL:
        print("Discord webhook is not configured")
        return

    payload = {
        "content": message
    }

    try:
        response = requests.post(
            DISCORD_WEBHOOK_URL,
            json=payload,
            timeout=10
        )

        if response.ok:
            print("Discord notification sent")
        else:
            print(f"Discord notification failed: HTTP {response.status_code}")

    except requests.RequestException as e:
        print(f"Discord notification error: {e}")

def check_ip_abuse(ip):
    api_key = os.getenv("ABUSEIPDB_API_KEY")

    if not api_key:
        return None

    headers = {
        "Accept": "application/json",
        "Key": api_key
    }

    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90
    }

    try:
        response = requests.get(
            ABUSEIPDB_URL,
            headers=headers,
            params=params,
            timeout=10
        )

        if not response.ok:
            print(f"AbuseIPDB request failed: HTTP {response.status_code}")
            return None

        return response.json().get("data", {})

    except requests.RequestException as e:
        print(f"AbuseIPDB request error: {e}")
        return None


def process_alert(line):
    try:
        alert = json.loads(line)
    except json.JSONDecodeError:
        return

    rule = alert.get("rule", {})

    alert_id = alert.get("id")

    if alert_id in PROCESSED_ALERTS:
        return

    PROCESSED_ALERTS.add(alert_id)

    if str(rule.get("id")) != TARGET_RULE_ID:
        return

    data = alert.get("data", {})
    decoder = alert.get("decoder", {})
    mitre = rule.get("mitre", {})

    # Structured IOC extraction
    source_ip = data.get("srcip")
    username = data.get("dstuser")
    severity = rule.get("level")
    rule_id = rule.get("id")
    mitre_ids = mitre.get("id", [])

    ioc = {
        "source_ip": source_ip,
        "username": username,
        "severity": severity,
        "rule_id": rule_id,
        "mitre": mitre_ids
    }

    print()
    print("=" * 50)
    print("WAZUH SECURITY ALERT")
    print("=" * 50)

    print(f"Timestamp       : {alert.get('timestamp')}")
    print(f"Severity        : {severity}")
    print(f"Rule ID         : {rule_id}")
    print(f"Description     : {rule.get('description')}")
    print(f"Decoder         : {decoder.get('name')}")
    print(f"Source IP       : {source_ip}")
    print(f"Username        : {username}")
    print(f"MITRE ID        : {mitre_ids}")

    print()
    print("EXTRACTED IOC")
    print(ioc)


    abuse_data = check_ip_abuse(source_ip)

    if abuse_data:
        print()
        print("ABUSEIPDB ENRICHMENT")
        print(f"Abuse Confidence : {abuse_data.get('abuseConfidenceScore')}")
        print(f"Total Reports    : {abuse_data.get('totalReports')}")
        print(f"Country          : {abuse_data.get('countryCode')}")
        print(f"ISP              : {abuse_data.get('isp')}")

    discord_message = f"""
🚨 WAZUH SECURITY ALERT

Severity: {severity}
Rule ID: {rule_id}
Description: {rule.get('description')}

Source IP: {source_ip}
Username: {username}
MITRE: {mitre_ids}

ABUSEIPDB ENRICHMENT
Abuse Confidence: {abuse_data.get('abuseConfidenceScore') if abuse_data else 'N/A'}
Total Reports: {abuse_data.get('totalReports') if abuse_data else 'N/A'}
Country: {abuse_data.get('countryCode') if abuse_data else 'N/A'}
ISP: {abuse_data.get('isp') if abuse_data else 'N/A'}

INCIDENT RESPONSE
DRY RUN: Would block source IP {source_ip}
"""

    send_discord_alert(discord_message)

    response_action = f"DRY RUN: Would block source IP {source_ip}"

    respond_to_threat(source_ip)

    log_incident(alert, abuse_data, response_action)

    print("=" * 50)
    print()


def monitor_alerts():
    print("Starting Wazuh alert monitor...")
    print(f"Monitoring: {ALERT_FILE}")
    print("Waiting for new alerts...")
    print()

    with open(ALERT_FILE, "r") as file:
        file.seek(0, 2)

        while True:
            line = file.readline()

            if not line:
                time.sleep(1)
                continue

            process_alert(line)


if __name__ == "__main__":
    monitor_alerts()

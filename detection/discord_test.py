import os
import requests

webhook_url = os.getenv("DISCORD_WEBHOOK_URL")

if not webhook_url:
    print("ERROR: DISCORD_WEBHOOK_URL is not set")
    exit(1)

payload = {
    "content": "🚨 Linux SOC Automation test alert — Discord integration is working."
}

response = requests.post(
    webhook_url,
    json=payload,
    timeout=10
)

print("HTTP status:", response.status_code)

if response.ok:
    print("Discord notification sent successfully")
else:
    print("Discord notification failed")
    print(response.text)

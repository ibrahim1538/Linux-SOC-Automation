import os
import requests

api_key = os.getenv("ABUSEIPDB_API_KEY")

if not api_key:
    print("ERROR: ABUSEIPDB_API_KEY is not set")
    exit(1)

ip = "127.0.0.1"

url = "https://api.abuseipdb.com/api/v2/check"

headers = {
    "Accept": "application/json",
    "Key": api_key
}

params = {
    "ipAddress": ip,
    "maxAgeInDays": 90
}

response = requests.get(
    url,
    headers=headers,
    params=params,
    timeout=10
)

print("HTTP status:", response.status_code)

if response.ok:
    result = response.json()["data"]

    print("IP:", result.get("ipAddress"))
    print("Abuse confidence:", result.get("abuseConfidenceScore"))
    print("Total reports:", result.get("totalReports"))
    print("Country:", result.get("countryCode"))
    print("ISP:", result.get("isp"))
else:
    print("AbuseIPDB request failed")
    print(response.text)

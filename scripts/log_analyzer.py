import json
import time
from collections import defaultdict

LOG_FILE = "/var/ossec/logs/archives/archives.json"
THRESHOLD = 5

failed_attempts = defaultdict(int)
suspicious_ips = set()

def follow(file):
    file.seek(0, 2)
    while True:
        line = file.readline()
        if not line:
            time.sleep(0.5)
            continue
        yield line

def analyze():
    with open(LOG_FILE, "r") as f:
        loglines = follow(f)

        print("Monitoring logs in real-time...\n")

        for line in loglines:
            try:
                log = json.loads(line)

                event_id = log.get("data", {}).get("win", {}).get("system", {}).get("eventID")
                ip = log.get("data", {}).get("win", {}).get("eventdata", {}).get("ipAddress")
                user = log.get("data", {}).get("win", {}).get("eventdata", {}).get("targetUserName")

                # Login attempts
                if event_id == "4625" and ip:
                    failed_attempts[ip] += 1

                    print(f"[INFO] Failed login from {ip} (count={failed_attempts[ip]})")

                    if failed_attempts[ip] >= THRESHOLD:
                        suspicious_ips.add(ip)
                        print(f"[WARNING] Suspicious IP detected: {ip}")

                # Correlation
                if event_id == "4624" and ip:
                    if ip in suspicious_ips:
                        print("\n COMPROMISE DETECTED")
                        print(f"IP: {ip}")
                        print(f"User: {user}\n")

            except json.JSONDecodeError:
                continue
            except Exception as e:
                print(f"Error: {e}")

if __name__ == "__main__":
    analyze()

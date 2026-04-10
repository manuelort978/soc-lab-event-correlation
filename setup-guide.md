# Setup Guide – Event Correlation Lab

## Requirements

* Wazuh Server (Ubuntu)
* Ubuntu Desk (Attacker)
* Windows 10 endpoint
* Python 3

---

## Steps

1. Install Wazuh agent on Windows
2. Enable audit logs
3. Verify logs in:
   /var/ossec/logs/archives/archives.json

---

## Run Script

```
sudo python3 log_analyzer.py
```

---

## Simulate Attack

1. Perform brute-force attack
2. Login successfully

---

## Expected Result

Script detects compromise based on correlation

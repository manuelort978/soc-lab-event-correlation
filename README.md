# SOC Lab – Event Correlation in Brute Force Attacks

## Overview

This project demonstrates real-time event correlation using Python and Wazuh SIEM to detect compromised accounts.

---

## Objective

Detect brute-force attacks followed by successful authentication.

---

## Detection Logic

* Event ID 4625 -> Failed login
* Event ID 4624 -> Successful login
* Correlation -> Same IP triggers both

---

## Methodology

1. Monitor logs in real time
2. Count failed attempts per IP
3. Flag suspicious IPs
4. Detect successful login after failures

---

## Detection Output

```
COMPROMISE DETECTED
IP:192.168.56.103
User: testuser
```

---

## Skills Demonstrated

* Event Correlation
* Threat Detection
* Python Automation
* SIEM Analysis

---

## Future Improvements

* Automate response actions

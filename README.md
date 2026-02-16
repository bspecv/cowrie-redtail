## Overview

This repo highlights a Cowrie open-source SSH honeypot that I set up on a VPS. The honeypot forwards logs to my Splunk server so I can monitor and analyze attacker activity in real time.

While reviewing logs between 02/08/2026 and 02/10/2026, I identified suspicious activity from the IP address `130.12.180.51`. During that timeframe, the attacker successfully logged in via SSH and gained root access to the Cowrie VPS.

The threat actor was observed:

- Uploading multiple RedTail/XMRig binaries (multi-architecture)
- Running a setup script to deploy crypto mining malware
- Attempting SSH persistence by modifying `authorized_keys`
- Locking the key file using `chattr +ai`
- Running a cleanup script to remove evidence or competing malware

There was no evidence of active (C2) traffic or a hardcoded wallet address in the captured samples.

Cowrie prevents full execution of malicious scripts, which allows safe observation of attacker behavior without impacting production systems.

This project demonstrates how honeypots combined with SIEM analysis can be used to study real-world attacker techniques in a controlled environment.

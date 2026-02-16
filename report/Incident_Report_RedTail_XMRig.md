\# Incident Report – RedTail / XMRig SSH Worm Activity



\## Executive Summary



Between 2026-02-10 and 2026-02-13, repeated malicious SSH sessions were observed against a Cowrie honeypot.  

The attacker (source IP: 130.12.180.51) successfully authenticated using valid credentials and deployed a multi-architecture payload identified as RedTail, a known SSH-propagating XMRig-based cryptomining worm.



The attack chain included:

\- Successful SSH authentication

\- Multi-architecture binary upload

\- Shell script execution

\- Cron cleaning to remove competing miners

\- SSH authorized\_keys persistence with immutable attribute



Malware analysis and OSINT correlation via MalwareBazaar confirmed the payload as a CoinMiner (XMRig variant) associated with RedTail activity.



---



\## Scope



\*\*Platform:\*\* Cowrie SSH Honeypot  

\*\*Log Source:\*\* Splunk (sourcetype="cowrie:json")  

\*\*Primary Attacker IP:\*\* 130.12.180.51  

\*\*Malware Family:\*\* RedTail / XMRig CoinMiner  

\*\*Persistence Mechanism:\*\* SSH key injection + chattr immutable flag  



---



\## Attack Timeline Summary



1\. SSH authentication success (`cowrie.login.success`)

2\. SFTP upload of:

&nbsp;  - setup.sh

&nbsp;  - clean.sh

&nbsp;  - redtail.x86\_64

&nbsp;  - redtail.i686

&nbsp;  - redtail.arm7

&nbsp;  - redtail.arm8

3\. Execution of:

&nbsp;  - sh clean.sh

&nbsp;  - sh setup.sh

4\. SSH public key written to ~/.ssh/authorized\_keys

5\. chattr +ai applied to prevent removal



Multiple deployment sessions were observed, indicating automated worm behavior.



---



\## Technical Analysis



\### clean.sh



Purpose:

\- Removes competing miners (e.g., c3pool\_miner)

\- Cleans cron entries referencing wget, curl, base64, nc, etc.

\- Clears temporary directories (/tmp, /var/tmp, /dev/shm)



This suggests competitive cryptomining environment control.



---



\### setup.sh



Purpose:

\- Detect system architecture

\- Select appropriate redtail binary

\- Drop executable into writable directory

\- Execute with SSH propagation mode

\- Remove staging artifacts



The script dynamically adapts to x86\_64, i686, arm7, arm8.



---



\### redtail.x86\_64 (Unpacked)



Binary Characteristics:

\- Statically linked ELF

\- Packed with UPX (unpacked during analysis)

\- Contains XMRig indicators

\- Stratum protocol strings

\- Monero-related algorithm references

\- Embedded SSH functionality (libssh2 strings observed)



Key Observed Strings:

\- cryptonight-monerov7

\- stratum+tcp://

\- donate.ssl.xmrig.com

\- SSH-2.0-libssh2



MalwareBazaar Classification:

\- Signature: CoinMiner

\- Vendor detections: 8

\- Delivery method: Web download



---



\## MITRE ATT\&CK Mapping



| Tactic | Technique | ID |

|--------|-----------|----|

| Initial Access | Valid Accounts | T1078 |

| Command \& Control | Application Layer Protocol (Stratum/SSL) | T1071 |

| Execution | Command Shell | T1059.004 |

| Persistence | Account Manipulation (Authorized Keys) | T1098.004 |

| Defense Evasion | Indicator Removal (Cron cleaning) | T1070 |

| Ingress Tool Transfer | File Upload via SSH | T1105 |

| Impact | Resource Hijacking (Cryptomining) | T1496 |



---



\## Indicators of Compromise (IOCs)



\### IP Address

\- 130.12.180.51



\### File Hashes (SHA256)



redtail.x86\_64  

59c29436755b0778e968d49feeae20ed65f5fa5e35f9f7965b8ed93420db91e5



redtail.i686  

048e374baac36d8cf68dd32e48313ef8eb517d647548b1bf5f26d2d0e2e3cdc7



redtail.arm8  

dbb7ebb960dc0d5a480f97ddde3a227a2d83fcaca7d37ae672e6a0a6785631e9



redtail.arm7  

3625d068896953595e75df328676a08bc071977ac1ff95d44b745bbcb7018c6f



setup.sh  

783adb7ad6b16fe9818f3e6d48b937c3ca1994ef24e50865282eeedeab7e0d59



clean.sh  

d46555af1173d22f07c37ef9c1e0e74fd68db022f2b6fb3ab5388d2c5bc6a98e



---



\## Splunk Detection Strategy



The following detection logic was developed:



1\. Detect successful SSH login events

2\. Pivot to session timeline reconstruction

3\. Detect multi-architecture payload upload

4\. Detect script execution patterns

5\. Detect authorized\_keys manipulation

6\. Hunt for chmod/chattr persistence activity



Detection queries are documented in:



`detection/splunk\_queries.md`



---



\## Findings



\- Automated worm deployment observed across multiple sessions

\- Architecture-aware payload selection

\- Competitive miner cleanup behavior

\- SSH key persistence with immutable flag

\- Malware confirmed as XMRig-based CoinMiner

\- Evidence of SSH propagation capability



This activity represents opportunistic SSH worm cryptomining activity rather than targeted intrusion.



---



\## Lessons Learned



\- Honeypots remain effective at capturing automated worm behavior

\- Multi-architecture payloads indicate scalable infrastructure

\- Persistence via authorized\_keys remains common in SSH attacks

\- UPX packing is frequently used in cryptominers

\- Detection engineering benefits from timeline-based pivoting



---



\## Conclusion



The observed activity is consistent with RedTail SSH worm behavior deploying XMRig-based cryptomining malware. The attacker leveraged valid credentials, transferred architecture-specific payloads, established persistence, and executed cryptomining functionality.



This investigation demonstrates structured SOC triage, malware analysis, MITRE mapping, and detection engineering documentation suitable for professional cybersecurity portfolio presentation.



---




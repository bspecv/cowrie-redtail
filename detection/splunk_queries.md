# Splunk Detection Queries – RedTail / XMRig Incident

These queries were used to detect and investigate RedTail-style SSH worm activity captured via Cowrie honeypot logs.

---

## 1. Initial Access – Valid Credentials (T1078)

Detect successful SSH authentication.

```spl
index=* sourcetype="cowrie:json" eventid="cowrie.login.success"
| stats count min(_time) as first max(_time) as last values(password) as password by src_ip username
| convert ctime(first) ctime(last)
| sort -count
```

---

## 2. Session Timeline – Full Attack Sequence

```spl
index=* sourcetype="cowrie:json" src_ip="130.12.180.51"
| sort 0 _time
| eval detail=coalesce(input,message,filename,outfile)
| table _time session eventid username detail
```

---

## 3. Ingress Tool Transfer – File Uploads (T1105)

```spl
index=* sourcetype="cowrie:json" eventid="cowrie.session.file_upload"
| search filename IN ("redtail.x86_64","redtail.i686","redtail.arm7","redtail.arm8","setup.sh","clean.sh")
| stats count values(filename) as files by src_ip session
| sort -count
```

---

## 4. Execution – Shell Script Activity (T1059.004)

```spl
index=* sourcetype="cowrie:json" eventid="cowrie.command.input"
| search input="*sh clean.sh*" OR input="*sh setup.sh*"
| table _time src_ip session username input
| sort 0 _time
```

---

## 5. Persistence – SSH Authorized Keys (T1098.004)

```spl
index=* sourcetype="cowrie:json" eventid="cowrie.command.input"
| search input="*authorized_keys*" OR input="*chattr*"
| table _time src_ip session username input
| sort 0 _time
```

---

## 6. Hunting – Suspicious Persistence Activity

```spl
index=* sourcetype="cowrie:json" eventid="cowrie.command.input"
| search input="*authorized_keys*" OR input="*chmod +x*" OR input="*chattr*"
| stats count values(input) as suspicious_commands by src_ip
| sort -count
```

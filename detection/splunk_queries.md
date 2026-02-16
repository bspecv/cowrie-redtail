\# Splunk Detection Queries – RedTail / XMRig Incident



These queries were used to detect and investigate RedTail-style SSH worm activity captured via Cowrie honeypot logs.



Base filter:



---



\## 1️⃣ Initial Access – Valid Credentials (T1078)



Detect successful SSH authentication.



```spl

index=\* sourcetype="cowrie:json" eventid="cowrie.login.success"

| stats count min(\_time) as first max(\_time) as last values(password) as password by src\_ip username

| convert ctime(first) ctime(last)

| sort -count



index=\* sourcetype="cowrie:json" src\_ip="130.12.180.51"

| sort 0 \_time

| eval detail=coalesce(input,message,filename,outfile)

| table \_time session eventid username detail





index=\* sourcetype="cowrie:json" src\_ip="130.12.180.51"

| sort 0 \_time

| eval detail=coalesce(input,message,filename,outfile)

| table \_time session eventid username detail





index=\* sourcetype="cowrie:json" eventid="cowrie.session.file\_upload"

| search filename IN ("redtail.x86\_64","redtail.i686","redtail.arm7","redtail.arm8","setup.sh","clean.sh")

| stats count values(filename) as files by src\_ip session

| sort -count





index=\* sourcetype="cowrie:json" eventid="cowrie.command.input"

| search input="\*sh clean.sh\*" OR input="\*sh setup.sh\*"

| table \_time src\_ip session username input

| sort 0 \_time







index=\* sourcetype="cowrie:json" eventid="cowrie.command.input"

| search input="\*authorized\_keys\*" OR input="\*chattr\*"

| table \_time src\_ip session username input

| sort 0 \_time





index=\* sourcetype="cowrie:json" eventid="cowrie.command.input"

| search input="\*authorized\_keys\*" OR input="\*chmod +x\*" OR input="\*chattr\*"

| stats count values(input) as suspicious\_commands by src\_ip

| sort -count








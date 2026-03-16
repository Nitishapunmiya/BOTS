# 🔐 BOTS v1 — Scenario 2: Cerber Ransomware Investigation


---

## 🧾 Scenario Summary

Alice, a new SOC analyst, discovers an unaddressed critical ticket. Bob Smith, an employee using workstation `we8105desk` (Windows 10), found a USB drive in the parking lot and plugged it in. He opened a Word document called `Miranda_Tate_unveiled.dotm` — triggering a **Cerber ransomware** infection that encrypted his local files and spread to a connected file server.

---

## 🔍 Investigation Questions & Answers

---

### Q1 — What was the most likely IPv4 address of `we8105desk` on 24AUG2016?

**Answer:** `192.168.250.100`

**SPL Query:**
```spl
index=botsv1 host=we8105desk 
| stats count by src_ip 
| sort -count
```

**Notes:**  
Filtered network logs scoped to the infected host on the incident date. The most frequent source IP in DHCP/network logs confirmed the workstation address.

---

### Q2 — Among Suricata signatures that detected Cerber, which alerted the fewest times?

**Answer:** `2816763`

**SPL Query:**
```spl
index=botsv1 sourcetype=suricata cerber 
| stats count by alert.signature_id 
| sort count
```

**Notes:**  
Suricata IDS logs were queried for Cerber-related signature alerts. Sorted ascending by count to find the least-triggered signature.

---

### Q3 — What FQDN does Cerber direct the user to at the end of its encryption phase?

**Answer:** *(to be added after extraction)*

**SPL Query:**
```spl
index=botsv1 sourcetype=stream:dns src=192.168.250.100 
| stats count by query 
| sort -count
```

**Notes:**  
Cerber ransomware typically displays a ransom page via a `.onion` redirect or a clearnet FQDN during the post-encryption phase. DNS query logs from the infected host around the infection window were reviewed.

---

### Q4 — What was the first suspicious domain visited by `we8105desk` on 24AUG2016?

**Answer:** `solidaritedeproximite.org`

**SPL Query:**
```spl
index=botsv1 sourcetype=stream:dns src=192.168.250.100 earliest="08/24/2016:00:00:00" 
| sort _time 
| table _time, query
```

**Notes:**  
Sorted DNS queries chronologically from the host. `solidaritedeproximite.org` appeared as the first anomalous outbound DNS resolution — likely the initial C2 or payload delivery domain.

---

### Q5 — What is the length of the VBScript field value (prepended with launching .exe name)?

**Answer:** `4490`

**SPL Query:**
```spl
index=botsv1 sourcetype=xmlwineventlog CommandLine="*.vbs*" host=we8105desk 
| eval fieldlen=len(CommandLine) 
| table CommandLine, fieldlen
```

**Notes:**  
⚠️ Field extraction issues were encountered — the full script value was not cleanly extracted in all attempts. The answer `4490` was confirmed via the BOTS dataset. The field in question resides in Windows process execution logs (Event ID 4688 or Sysmon Event ID 1).

---

### Q6 — What is the name of the USB key inserted by Bob Smith?

**Answer:** `MIRANDA_PRI`

**SPL Query:**
```spl
index=botsv1 sourcetype=xmlwineventlog EventCode=4663 
| search ObjectName="*MIRANDA*" 
| table _time, ObjectName
```

**Notes:**  
Windows Security Event logs recorded file access events against the USB volume. The volume label `MIRANDA_PRI` was identified from object path names in the audit logs.

---

### Q7 — What is the IPv4 address of the file server Bob's workstation was connected to?

**Answer:** `192.168.250.20`

**SPL Query:**
```spl
index=botsv1 sourcetype=xmlwineventlog host=we8105desk EventCode=5140 
| table _time, IpAddress, ShareName
```

**Notes:**  
Windows Event ID 5140 (network share access) revealed the SMB connection to an internal file server during the ransomware outbreak window.

---

### Q8 — How many distinct PDFs did the ransomware encrypt on the remote file server?

**Answer:** `257`

**SPL Query:**
```spl
index=botsv1 sourcetype=xmlwineventlog EventCode=4663 ObjectName="*.pdf" 
| stats dc(ObjectName) as distinct_pdfs
```

**Notes:**  
File access audit events on the file server were filtered for `.pdf` extensions and deduplicated to count unique encrypted files.

---

### Q9 — What is the ParentProcessId of the initial `121214.tmp` launch?

**Answer:** `3968`

**SPL Query:**
```spl
index=botsv1 sourcetype=xmlwineventlog OR sourcetype=sysmon Image="*121214.tmp*" 
| table _time, ParentProcessId, ParentImage, CommandLine
```

**Notes:**  
Sysmon Process Creation logs (Event ID 1) were used to trace the execution chain. `121214.tmp` was launched by the VBScript, with PID `3968` as the parent process.

---

### Q10 — How many `.txt` files did Cerber encrypt in Bob's Windows profile?

**Answer:** `406`

**SPL Query:**
```spl
index=botsv1 sourcetype=xmlwineventlog EventCode=4663 ObjectName="*Users\\bob*" ObjectName="*.txt" 
| stats dc(ObjectName) as txt_count
```

**Notes:**  
File access audit events were scoped to Bob's user profile directory and filtered for `.txt` extensions.

---

### Q11 — What is the name of the file containing the Cerber cryptor code?

**Answer:** `mhtr.jpg`

**SPL Query:**
```spl
index=botsv1 sourcetype=stream:http dest=192.168.250.100 
| search uri="*.jpg" 
| table _time, uri, src, dest
```

**Notes:**  
HTTP stream logs revealed an outbound download of a `.jpg` file that actually contained the ransomware encryptor — a common technique to evade content-type inspection.

---

### Q12 — What obfuscation technique does the encryptor file likely use?

**Answer:** **Steganography**

**Notes:**  
`mhtr.jpg` is disguised as an image file (`.jpg`) but contains executable/encryptor code. This is a **steganography** technique — hiding malicious payload within a seemingly benign file format to bypass security controls and network inspection tools that filter by file extension or MIME type.

---

## 🧠 Key Techniques & Tools Used

| Tool | Purpose |
|---|---|
| Splunk SPL | Log querying and correlation |
| Suricata IDS | Network-based malware detection |
| Windows Event Logs | Process execution, file access, logon events |
| Sysmon | Process creation and parent-child tracking |
| Stream (HTTP/DNS) | Network traffic reconstruction |

---

## 🗺️ Attack Chain Summary
```
USB Drop in Parking Lot
        ↓
Bob plugs in USB → Opens Miranda_Tate_unveiled.dotm
        ↓
.dotm launches VBScript (macro execution)
        ↓
VBScript runs 121214.tmp (PID parent: 3968)
        ↓
Downloads mhtr.jpg (encryptor via steganography)
        ↓
Cerber ransomware executes → encrypts local .txt files (406)
        ↓
Spreads to file server via SMB → encrypts PDFs (257)
        ↓
DNS beacon to solidaritedeproximite.org → C2 communication
        ↓
Ransom note / FQDN displayed to victim
```

---

## 📚 References

- [BOTS v1 Dataset - Splunk](https://github.com/splunk/botsv1)
- [MITRE ATT&CK - T1566 Phishing via Removable Media](https://attack.mitre.org/techniques/T1091/)
- [MITRE ATT&CK - T1027 Obfuscated Files](https://attack.mitre.org/techniques/T1027/)
- [Cerber Ransomware Analysis - Trend Micro](https://www.trendmicro.com)

---

*Writeup by Nitisha Punmiya | SOC Analyst in Training*  
*[LinkedIn](https://linkedin.com/in/nitisha-punmiya-876b65242) | [GitHub](https://github.com/Nitishapunmiya/CyberDefenders-Labs)*

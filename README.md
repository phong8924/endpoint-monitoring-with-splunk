# Splunk SOC Lab: Monitoring, Alert Triage and Incident Reporting

## 1. Overview

This project is a hands-on SOC lab built to practice security monitoring, alert triage, SPL query writing, and incident reporting using Splunk.

The lab simulates common security events in a controlled environment and documents how a SOC analyst can investigate alerts using endpoint logs, firewall logs, and Windows Security logs.

The main goal of this project is to demonstrate SOC Level 1 skills, including:

* Collecting logs from Windows endpoints
* Searching and analyzing events in Splunk
* Writing SPL detection queries
* Investigating alerts using evidence
* Mapping detections to MITRE ATT&CK
* Writing incident reports

---

## 2. Lab Architecture

| Component           | Description                 |
| ------------------- | --------------------------- |
| SIEM                | Splunk Enterprise           |
| Endpoint            | Windows 10 VM               |
| Endpoint Telemetry  | Sysmon                      |
| Log Forwarder       | Splunk Universal Forwarder  |
| Attacker Machine    | Kali Linux                  |
| Firewall Telemetry  | Windows Firewall Log        |
| Authentication Logs | Windows Security Event Logs |

### Architecture Diagram

```text
Kali Linux
    |
    | Nmap scan / simulated activity
    v
Windows 10 VM
    |
    | Sysmon Logs
    | Windows Security Logs
    | Windows Firewall Logs
    v
Splunk Universal Forwarder
    |
    v
Splunk Enterprise
```

---

## 3. Data Sources

| Data Source            | Splunk Source / Sourcetype                            | Purpose                                             |
| ---------------------- | ----------------------------------------------------- | --------------------------------------------------- |
| Sysmon Operational Log | `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` | Process creation, file activity, endpoint telemetry |
| Windows Security Log   | `XmlWinEventLog:Security`                             | Failed login and authentication events              |
| Windows Firewall Log   | `windows_firewall`                                    | Dropped TCP traffic and scan detection              |

---

## 4. Project Structure

```text
Splunk-SOC-Lab/
│
├── README.md
├── .gitignore
│
├── setup/
│   └── 01-splunk-sysmon-log-ingestion.md
│
├── spl-queries/
│   ├── 00-log-source-validation.spl
│   ├── 01-sysmon-eventcode-summary.spl
│   ├── 02-command-activity-test.spl
│   ├── 03-suspicious-powershell-detection.spl
│   ├── 04-nmap-scan-detection.spl
│   ├── 05-suspicious-file-triage.spl
│   └── 06-brute-force-login-detection.spl
│
├── detection-scenarios/
│   ├── 01-suspicious-powershell-detection.md
│   ├── 02-nmap-scan-detection.md
│   ├── 03-suspicious-file-triage.md
│   └── 04-brute-force-login-detection.md
│
├── incident-reports/
│   ├── IR-001-suspicious-powershell.md
│   ├── IR-002-nmap-scan.md
│   ├── IR-003-suspicious-file-triage.md
│   └── IR-004-brute-force-login.md
│
├── mitre-mapping/
│   └── mitre-attack-mapping.md
│
└── screenshots/
    ├── splunk-log-ingestion/
    ├── suspicious-powershell/
    ├── nmap-scan/
    ├── suspicious-file/
    └── brute-force-login/
```

---

## 5. Detection Scenarios

| No. | Scenario                             | Data Source                    | Detection File                                              | Incident Report                                     |
| --- | ------------------------------------ | ------------------------------ | ----------------------------------------------------------- | --------------------------------------------------- |
| 1   | Suspicious PowerShell Detection      | Sysmon EventCode 1             | `detection-scenarios/01-suspicious-powershell-detection.md` | `incident-reports/IR-001-suspicious-powershell.md`  |
| 2   | Nmap Scan Detection                  | Windows Firewall Log           | `detection-scenarios/02-nmap-scan-detection.md`             | `incident-reports/IR-002-nmap-scan.md`              |
| 3   | Suspicious Script File / Hash Triage | Sysmon telemetry               | `detection-scenarios/03-suspicious-file-triage.md`          | `incident-reports/IR-003-suspicious-file-triage.md` |
| 4   | Brute Force Login Detection          | Windows Security Event ID 4625 | `detection-scenarios/04-brute-force-login-detection.md`     | `incident-reports/IR-004-brute-force-login.md`      |

---

## 6. Scenario 1: Suspicious PowerShell Detection

### Objective

Detect suspicious PowerShell execution using Sysmon process creation logs collected in Splunk.

### Simulated Activity

The following safe PowerShell commands were executed to generate suspicious telemetry:

```powershell
powershell.exe -NoProfile -EncodedCommand dwBoAG8AYQBtAGkA
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Get-Process | Out-File $env:TEMP\ps-test.txt"
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Invoke-WebRequest -Uri http://example.com -OutFile $env:TEMP\test.html"
```

### Detection Query

```spl
index="main" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
(Image="*powershell.exe*" OR CommandLine="*powershell*")
| eval cmd=lower(CommandLine)
| where like(cmd, "%encodedcommand%")
   OR like(cmd, "% -enc %")
   OR like(cmd, "%executionpolicy bypass%")
   OR like(cmd, "%invoke-webrequest%")
   OR like(cmd, "%iwr%")
   OR like(cmd, "%downloadstring%")
   OR like(cmd, "%outfile%")
   OR like(cmd, "%http://%")
   OR like(cmd, "%https://%")
| table _time host User ParentImage Image CommandLine ProcessId ParentProcessId
| sort - _time
```

### Evidence

![Suspicious PowerShell Detection](screenshots/suspicious-powershell/03-suspicious-powershell-detection-result.png)

---

## 7. Scenario 2: Nmap Scan Detection

### Objective

Detect Nmap port scanning activity against a Windows 10 endpoint using Windows Firewall logs collected in Splunk.

In this lab, Windows Firewall was enabled. Because blocked inbound scan traffic may not be fully visible in Sysmon EventCode 3, Windows Firewall logs were used as the primary data source.

### Simulated Activity

Nmap was executed from Kali Linux:

```bash
nmap -Pn -sV <WINDOWS_IP>
```

### Detection Query

```spl
index="main" sourcetype="windows_firewall" "DROP" "TCP"
| rex field=_raw "(?<action>DROP|ALLOW)\s+(?<protocol>TCP|UDP)\s+(?<src_ip>\d{1,3}(?:\.\d{1,3}){3})\s+(?<dst_ip>\d{1,3}(?:\.\d{1,3}){3})\s+(?<src_port>\d+)\s+(?<dst_port>\d+)"
| search action=DROP protocol=TCP
| stats dc(dst_port) as unique_ports count as connection_count values(dst_port) as scanned_ports by src_ip dst_ip
| where unique_ports >= 3
| sort - unique_ports
```

### Evidence

![Nmap Scan Evidence](screenshots/nmap-scan/01-nmap-pn-sv-scan.png)

![Nmap Detection Result](screenshots/nmap-scan/03-nmap-scan-detection-result.png)

---

## 8. Scenario 3: Suspicious Script File / Hash Triage

### Objective

Detect suspicious script file creation and perform basic hash triage.

### Simulated Activity

A PowerShell script file was created in the temporary directory:

```powershell
Set-Content -Path "$env:TEMP\update.ps1" -Value "whoami"
Get-FileHash "$env:TEMP\update.ps1" -Algorithm SHA256
```

### Detection Query

```spl
index="main" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| search "update.ps1"
| table _time host EventCode User Image TargetFilename CommandLine _raw
| sort - _time
```

### Evidence

![Suspicious Script Hash Evidence](screenshots/suspicious-file/01-update-ps1-hash.png)

![Suspicious Script Sysmon Evidence](screenshots/suspicious-file/02-sysmon-update-ps1-evidence.png)

---

## 9. Scenario 4: Brute Force Login Detection

### Objective

Detect multiple failed login attempts using Windows Security Event ID `4625`.

### Simulated Activity

Multiple failed login attempts were generated locally on the Windows 10 VM using:

```powershell
runas /user:wronguser cmd
```

An incorrect password was entered several times to generate failed authentication events.

### Detection Query

```spl
index="main" source="XmlWinEventLog:Security" EventCode=4625
| stats count as failed_attempts
        earliest(_time) as first_seen
        latest(_time) as last_seen
        values(LogonType) as logon_types
        values(FailureReason) as failure_reasons
        values(IpAddress) as source_ips
        by host TargetUserName
| where failed_attempts >= 3
| convert ctime(first_seen) ctime(last_seen)
| sort - failed_attempts
```

### Evidence

![Failed Login Events](screenshots/brute-force-login/01-failed-login-events-4625.png)

![Brute Force Detection Result](screenshots/brute-force-login/02-brute-force-detection-result.png)

---

## 10. MITRE ATT&CK Mapping

| Scenario                             | Tactic              | Technique                                     | ID        |
| ------------------------------------ | ------------------- | --------------------------------------------- | --------- |
| Suspicious PowerShell Detection      | Execution           | Command and Scripting Interpreter: PowerShell | T1059.001 |
| Suspicious PowerShell Detection      | Defense Evasion     | Obfuscated Files or Information               | T1027     |
| Suspicious PowerShell Detection      | Command and Control | Ingress Tool Transfer                         | T1105     |
| Nmap Scan Detection                  | Discovery           | Network Service Discovery                     | T1046     |
| Nmap Scan Detection                  | Reconnaissance      | Active Scanning                               | T1595     |
| Suspicious Script File / Hash Triage | Execution           | Command and Scripting Interpreter: PowerShell | T1059.001 |
| Suspicious Script File / Hash Triage | Execution           | User Execution                                | T1204     |
| Brute Force Login Detection          | Credential Access   | Brute Force                                   | T1110     |
| Brute Force Login Detection          | Credential Access   | Password Guessing                             | T1110.001 |

---

## 11. Skills Demonstrated

This project demonstrates the following SOC analyst skills:

* Splunk log ingestion
* SPL query writing
* Sysmon log analysis
* Windows Security Event Log analysis
* Windows Firewall log analysis
* Authentication failure investigation
* Alert triage
* Incident report writing
* MITRE ATT&CK mapping
* Basic file hash triage
* Evidence-based investigation workflow

---

## 12. Key Lessons Learned

During this lab, several important SOC investigation lessons were observed:

1. Sysmon is useful for endpoint telemetry such as process creation, file activity, and PowerShell investigation.
2. Windows Firewall logs are useful when inbound traffic is blocked before Sysmon can capture enough network connection evidence.
3. Windows Security Event ID `4625` is important for detecting failed login attempts.
4. SPL queries should be adjusted based on the actual field names and log sources collected in Splunk.
5. A good SOC investigation should include evidence, triage analysis, MITRE mapping, impact assessment, and recommended response actions.

---

## 13. Future Improvements

Possible improvements for this lab:

* Add Splunk dashboards for SOC monitoring
* Add alert rules in Splunk
* Add remote SMB/RDP brute force detection
* Add TheHive for case management
* Add Shuffle SOAR for automated enrichment
* Add VirusTotal hash enrichment
* Add more MITRE ATT&CK techniques
* Add timeline analysis for each incident

---

## 14. Disclaimer

This project was built in a controlled lab environment for educational and defensive security purposes only. All simulated activities were performed on owned virtual machines.

# Incident Report: Suspicious Script File Creation

## 1. Executive Summary

A suspicious PowerShell script file named `update.ps1` was created in the Windows temporary directory and detected through Splunk using Sysmon telemetry.

The file was intentionally created in the lab environment for detection testing and is classified as a true positive lab simulation.

## 2. Alert Information

| Field          | Value                           |
| -------------- | ------------------------------- |
| Alert Name     | Suspicious Script File Creation |
| Severity       | Medium                          |
| Detection Tool | Splunk                          |
| Data Source    | Sysmon                          |
| Endpoint       | Windows 10 VM                   |
| File Name      | update.ps1                      |
| Status         | True Positive - Lab Simulation  |

## 3. Evidence

The following file was created:

```text
%TEMP%\update.ps1
```

The file hash was calculated using PowerShell:

```powershell
Get-FileHash "$env:TEMP\update.ps1" -Algorithm SHA256
```
![alt text](<../screenshots/suspicious-file/Screenshot 2026-06-20 073142.png>)
## 4. Splunk Detection Evidence

Detection query:

```spl
index="main" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| search "update.ps1"
| table _time host EventCode User Image TargetFilename CommandLine _raw
| sort - _time
```
![alt text](<../screenshots/suspicious-file/Screenshot 2026-06-20 073125.png>)

## 5. Triage Analysis

The alert is considered a true positive in the lab environment because the script file was intentionally created for detection testing.

In a real SOC environment, a `.ps1` file created in a temporary directory should be reviewed because attackers often use script files for execution, payload staging, and post-exploitation tasks.

Key triage questions:

| Question                       | Purpose                            |
| ------------------------------ | ---------------------------------- |
| Which user created the file?   | Identify the account involved      |
| What process created the file? | Determine the source process       |
| Where was the file created?    | Check for suspicious location      |
| What is the file hash?         | Support threat intelligence lookup |
| Was the script executed?       | Determine actual impact            |

## 6. Impact Assessment

| Area            | Assessment             |
| --------------- | ---------------------- |
| Endpoint Impact | Low                    |
| Malware Risk    | Low to Medium          |
| Execution Risk  | Medium                 |
| Business Impact | Low in lab environment |
| SOC Priority    | Medium                 |

## 7. Recommended Response

1. Review the file path and file extension.
2. Identify the user and process that created the file.
3. Calculate and record the SHA256 hash.
4. Check whether the script was executed.
5. Search for related PowerShell activity around the same timestamp.
6. Submit the hash to threat intelligence services if required.
7. Escalate if the script contains malicious commands or was downloaded from an external source.

## 8. Conclusion

The detection successfully identified suspicious script file activity using Splunk and Sysmon telemetry. This scenario demonstrates SOC analyst skills in file triage, hash analysis, evidence review, and incident reporting.

# Suspicious Script File Creation and Hash Triage

## 1. Objective

The objective of this scenario is to detect suspicious script file creation on a Windows 10 endpoint and perform basic hash triage.

This scenario focuses on detecting a PowerShell script file created in the user temporary directory, then calculating its SHA256 hash for investigation.

## 2. Lab Environment

| Component   | Description                          |
| ----------- | ------------------------------------ |
| SIEM        | Splunk Enterprise                    |
| Endpoint    | Windows 10 VM                        |
| Log Source  | Microsoft-Windows-Sysmon/Operational |
| Data Source | Sysmon file creation telemetry       |
| Index       | main                                 |
| File Name   | update.ps1                           |

## 3. Simulated Activity

A test PowerShell script was created in the temporary directory:

```powershell
Set-Content -Path "$env:TEMP\update.ps1" -Value "whoami"
Get-FileHash "$env:TEMP\update.ps1" -Algorithm SHA256
```

The file is safe and only contains the command `whoami`. It is used to simulate suspicious script creation behavior.

## 4. File Hash Evidence

![alt text](<../screenshots/suspicious-file/Screenshot 2026-06-20 073142.png>)

## 5. Detection Query

```spl
index="main" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| search "update.ps1"
| table _time host EventCode User Image TargetFilename CommandLine _raw
| sort - _time
```

## 6. Detection Result

Splunk successfully identified telemetry related to the created `update.ps1` file.

![alt text](<../screenshots/suspicious-powershell/Screenshot 2026-06-20 054638.png>)

## 7. Detection Logic

The detection searches for script files created in suspicious locations such as the user temporary directory.

Suspicious indicators:

* Script file extension: `.ps1`
* File created in `%TEMP%`
* File created by PowerShell or command-line activity
* Hash available for triage

## 8. MITRE ATT&CK Mapping

| Tactic          | Technique                                     | ID        |
| --------------- | --------------------------------------------- | --------- |
| Execution       | Command and Scripting Interpreter: PowerShell | T1059.001 |
| Defense Evasion | Deobfuscate/Decode Files or Information       | T1140     |
| Execution       | User Execution                                | T1204     |

## 9. Conclusion

This scenario demonstrates basic suspicious file triage using Splunk, Sysmon, and file hashing. The analyst can identify the file path, related process activity, user context, and SHA256 hash for further investigation.

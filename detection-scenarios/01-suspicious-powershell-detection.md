# Suspicious PowerShell Detection

## 1. Objective

The objective of this scenario is to detect suspicious PowerShell execution on a Windows 10 endpoint using Sysmon logs collected in Splunk.

This scenario focuses on identifying PowerShell command lines that contain indicators commonly associated with malicious or suspicious activity, such as encoded commands, execution policy bypass, web requests, and file output behavior.

## 2. Lab Environment

| Component       | Description                           |
| --------------- | ------------------------------------- |
| SIEM            | Splunk Enterprise                     |
| Endpoint        | Windows 10 VM                         |
| Log Source      | Microsoft-Windows-Sysmon/Operational  |
| Data Source     | Sysmon EventCode 1 - Process Creation |
| Index           | main                                  |
| Attacker/Tester | Local user on Windows 10 VM           |

## 3. Simulated Activity

The following safe PowerShell commands were executed in the lab environment to generate suspicious telemetry.

### Command 1: Encoded PowerShell Command

```powershell
powershell.exe -NoProfile -EncodedCommand dwBoAG8AYQBtAGkA
```

This command executes `whoami` in encoded form. It is safe, but the use of `EncodedCommand` is suspicious and should be investigated in a SOC environment.

### Command 2: Execution Policy Bypass

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Get-Process | Out-File $env:TEMP\ps-test.txt"
```

This command uses `ExecutionPolicy Bypass` and writes process information to a file in the temporary directory.

### Command 3: Web Request Using PowerShell

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Invoke-WebRequest -Uri http://example.com -OutFile $env:TEMP\test.html"
```

This command simulates PowerShell-based web download behavior by using `Invoke-WebRequest` to download content from a safe URL.

## 4. Detection Logic

The detection searches for PowerShell process creation events where the command line contains suspicious indicators.

Suspicious indicators include:

* `EncodedCommand`
* `-enc`
* `ExecutionPolicy Bypass`
* `Invoke-WebRequest`
* `iwr`
* `DownloadString`
* `OutFile`
* `http://`
* `https://`

## 5. SPL Query

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

## 6. Additional File Creation Evidence

Because some simulated commands create files in the temporary directory, Sysmon EventCode 11 can be used to verify file creation activity.

```spl
index="main" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=11
| search "ps-test.txt" OR "test.html"
| table _time host User Image TargetFilename
| sort - _time
```

## 7. Expected Result

Splunk should return Sysmon EventCode 1 logs showing PowerShell execution with suspicious command-line arguments.

Expected evidence includes:

| Evidence      | Description                                       |
| ------------- | ------------------------------------------------- |
| Process Image | `powershell.exe`                                  |
| CommandLine   | Contains suspicious PowerShell arguments          |
| ParentImage   | Shows the parent process that launched PowerShell |
| User          | Shows the account that executed the command       |
| ProcessId     | Identifies the PowerShell process                 |
| EventCode     | `1` - Process Creation                            |

If file creation logging is available, Sysmon EventCode 11 should also show files created in the temporary directory.

## 8. MITRE ATT&CK Mapping

| Tactic              | Technique                                     | ID        |
| ------------------- | --------------------------------------------- | --------- |
| Execution           | Command and Scripting Interpreter: PowerShell | T1059.001 |
| Defense Evasion     | Obfuscated Files or Information               | T1027     |
| Defense Evasion     | Impair Defenses: Execution Policy Bypass      | T1562     |
| Command and Control | Ingress Tool Transfer                         | T1105     |

## 9. Screenshots

Evidence screenshots are stored in:

```text
screenshots/suspicious-powershell/
```
![alt text](<../screenshots/suspicious-powershell/Screenshot 2026-06-20 054638.png>)

![alt text](<../screenshots/suspicious-powershell/Screenshot 2026-06-20 055122.png>)
## 10. Conclusion

This scenario demonstrates how Splunk and Sysmon can be used to detect suspicious PowerShell activity based on command-line indicators. The detection successfully identifies encoded commands, execution policy bypass behavior, web request usage, and suspicious file output activity.

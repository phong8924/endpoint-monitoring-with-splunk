# Phase 1: Splunk and Sysmon Log Ingestion

## Objective

The objective of this phase is to configure a Windows 10 endpoint to forward Sysmon logs into Splunk for security monitoring and analysis.

## Environment

| Component  | Description                |
| ---------- | -------------------------- |
| SIEM       | Splunk Enterprise          |
| Endpoint   | Windows 10 VM              |
| Log Source | Sysmon Operational Logs    |
| Forwarder  | Splunk Universal Forwarder |
| Index      | main                       |

## Validation Queries

### Check log sources

```spl
index="main"
| stats count by host source sourcetype
| sort - count
```

### Check Sysmon EventCodes

```spl
index="main" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| stats count by EventCode
| sort EventCode
```

### Test recent command activity

```spl
index="main" notepad OR whoami OR ipconfig
```

## Result

Splunk successfully received Sysmon events from the Windows 10 endpoint. The lab is ready for detection scenario development using Sysmon telemetry such as process creation, network connection and file creation events.

## Evidence

Screenshots are stored in:

```text
screenshots/splunk-log-ingestion/
```

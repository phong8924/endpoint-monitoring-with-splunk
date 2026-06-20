# SOC Monitoring Overview Dashboard

## 1. Objective

This dashboard provides a centralized SOC monitoring view for the lab environment. It summarizes key security events collected in Splunk from Windows Security Logs, Sysmon telemetry, and Windows Firewall logs.

## 2. Dashboard Panels

| Panel | Purpose | Data Source |
|---|---|---|
| Failed Login Attempts | Detect repeated failed authentication attempts | Windows Security Event ID 4625 |
| Suspicious PowerShell Activity | Identify suspicious PowerShell command-line behavior | Sysmon EventCode 1 |
| Possible Port Scan Activity | Detect multiple dropped TCP connections to different ports | Windows Firewall Log |
| Suspicious Script File Activity | Identify suspicious script file creation activity | Sysmon telemetry |

## 3. Dashboard Screenshot

![alt text](<../screenshots/dashboard/Screenshot 2026-06-20 081213.png>)
## 4. Result

The dashboard provides a quick overview of the main detection scenarios implemented in this lab. It helps a SOC analyst review authentication failures, suspicious PowerShell activity, possible port scanning, and suspicious script file activity from one place.

## 5. Skills Demonstrated

- Splunk dashboard creation
- SPL query visualization
- SOC monitoring workflow
- Alert triage overview
- Security event correlation
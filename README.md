# Splunk SOC Lab: Monitoring, Alert Triage and Incident Reporting

## Overview

This project documents a hands-on SOC lab built with Splunk, Sysmon and a Windows 10 endpoint. The goal is to collect endpoint telemetry, analyze security events, write SPL queries, perform alert triage and create incident reports based on simulated attack scenarios.

## Lab Architecture

* Splunk Enterprise installed on the host machine
* Windows 10 virtual machine as the monitored endpoint
* Sysmon installed on Windows 10 for endpoint telemetry
* Splunk Universal Forwarder used to send logs to Splunk
* Kali Linux will be used later to simulate attack scenarios

## Current Progress

### Phase 1: Log Ingestion

Splunk successfully received Sysmon logs from the Windows 10 endpoint.

Evidence collected:

* Splunk indexed events from the Windows VM
* Log source: `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`
* Sourcetype: `XmlWinEventLog`
* Sysmon EventCodes observed include process, network, file and registry-related events

## Detection Scenarios Planned

1. Suspicious PowerShell Detection
2. Nmap Scan Detection
3. Brute Force Login Detection
4. Suspicious File / Hash Triage

## Skills Demonstrated

* Splunk log ingestion
* Sysmon telemetry collection
* SPL query writing
* Windows endpoint monitoring
* Security event analysis
* Alert triage documentation
* Incident report writing
* MITRE ATT&CK mapping

# Nmap Scan Detection Using Windows Firewall Logs

## 1. Objective

The objective of this scenario is to detect Nmap port scanning activity against a Windows 10 endpoint using Windows Firewall logs collected in Splunk.

In this lab, the Windows Firewall is enabled. Because the firewall drops inbound scan traffic before it reaches normal application-level activity, Sysmon EventCode 3 may not capture enough evidence of the scan. Therefore, Windows Firewall logging is used as the primary data source for this detection.

## 2. Lab Environment

| Component         | Description                                           |
| ----------------- | ----------------------------------------------------- |
| SIEM              | Splunk Enterprise                                     |
| Target Endpoint   | Windows 10 VM                                         |
| Attacker Machine  | Kali Linux                                            |
| Log Source        | Windows Firewall Log                                  |
| Firewall Log File | `C:\Windows\System32\LogFiles\Firewall\pfirewall.log` |
| Splunk Sourcetype | `windows_firewall`                                    |
| Index             | `main`                                                |

## 3. Simulated Activity

The Kali Linux machine performed an Nmap scan against the Windows 10 VM while Windows Firewall was enabled.

Command used on Kali:

```bash
nmap -Pn -sV <WINDOWS_IP>
```

Example:

```bash
nmap -Pn -sV 10.130.10.145
```

The `-Pn` option was used because Windows Firewall may block ICMP ping, causing Nmap to incorrectly treat the host as down.

## 4. Nmap Scan Evidence
![alt text](<../screenshots/nmap-scan/Screenshot 2026-06-20 063253.png>)

## 5. Firewall Log Evidence in Splunk

After running the scan, Windows Firewall generated log entries showing dropped TCP traffic from the Kali machine to the Windows endpoint.

Validation query:

```spl
index="main" sourcetype="windows_firewall" "DROP" "TCP" "<KALI_IP>" "<WINDOWS_IP>"
| table _time _raw
| sort - _time
```

Example:

```spl
index="main" sourcetype="windows_firewall" "DROP" "TCP" "10.130.10.132" "10.130.10.145"
| table _time _raw
| sort - _time
```
![alt text](<../screenshots/nmap-scan/Screenshot 2026-06-20 064814.png>)

## 6. Detection Logic

The detection identifies source IP addresses that generate a high number of dropped TCP connections to multiple destination ports on the same target endpoint.

This behavior is commonly associated with port scanning or service discovery activity.

Suspicious indicators:

* Many dropped TCP connections
* Same source IP
* Same destination IP
* Multiple destination ports
* Short time window
* Traffic blocked by Windows Firewall

## 7. SPL Detection Query

```spl
index="main" sourcetype="windows_firewall" "DROP" "TCP"
| rex field=_raw "^(?<date>\d{4}-\d{2}-\d{2})\s+(?<time>\d{2}:\d{2}:\d{2})\s+(?<action>\w+)\s+(?<protocol>\w+)\s+(?<src_ip>\S+)\s+(?<dst_ip>\S+)\s+(?<src_port>\S+)\s+(?<dst_port>\S+)"
| search action=DROP protocol=TCP
| stats dc(dst_port) as unique_ports count as connection_count values(dst_port) as scanned_ports by src_ip dst_ip
| where unique_ports >= 20
| sort - unique_ports
```

## 8. Detection Result

The query successfully identified a source IP attempting to connect to multiple destination ports on the Windows 10 endpoint.

![alt text](<../screenshots/nmap-scan/Screenshot 2026-06-20 065659.png>)
## 9. MITRE ATT&CK Mapping

| Tactic         | Technique                 | ID    |
| -------------- | ------------------------- | ----- |
| Discovery      | Network Service Discovery | T1046 |
| Reconnaissance | Active Scanning           | T1595 |

## 10. Result

The Nmap scan was successfully detected using Windows Firewall logs in Splunk. This scenario demonstrates how firewall telemetry can be used to detect reconnaissance activity when endpoint telemetry such as Sysmon EventCode 3 does not provide sufficient inbound scan visibility.

## 11. Conclusion

This scenario shows that Windows Firewall logs are useful for detecting blocked port scanning activity. In this lab, the firewall dropped the Nmap scan traffic, and Splunk was used to parse and aggregate the log entries to identify scanning behavior.

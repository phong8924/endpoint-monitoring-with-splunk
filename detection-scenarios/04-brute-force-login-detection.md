# Incident Report: Brute Force Login Detection

## 1. Executive Summary

Multiple failed login attempts were detected on a Windows 10 endpoint using Windows Security Event Logs collected in Splunk.

The activity was generated in a lab environment using the `runas` command with an invalid username and incorrect password attempts. The detection is classified as a true positive lab simulation.

## 2. Alert Information

| Field          | Value                          |
| -------------- | ------------------------------ |
| Alert Name     | Multiple Failed Login Attempts |
| Severity       | Medium                         |
| Detection Tool | Splunk                         |
| Data Source    | Windows Security Log           |
| Event ID       | 4625                           |
| Endpoint       | Windows 10 VM                  |
| Status         | True Positive - Lab Simulation |

## 3. Evidence

Windows Security Event ID `4625` was observed in Splunk.

Validation query:

```spl
index="main" source="XmlWinEventLog:Security" EventCode=4625
| table _time host TargetUserName IpAddress LogonType FailureReason Status SubStatus ProcessName
| sort - _time
```

![Failed login events 4625](../screenshots/brute-force-login/01-failed-login-events-4625.png)

## 4. Detection Query

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

## 5. Detection Result

The detection query identified repeated failed login attempts for the same user account on the Windows endpoint.


## 6. Triage Analysis

The alert is classified as a true positive in the lab environment because multiple failed login attempts were intentionally generated for detection testing.

Key observations:

| Observation            | Analysis                                               |
| ---------------------- | ------------------------------------------------------ |
| Multiple failed logons | Indicates possible brute force or password guessing    |
| Event ID 4625          | Windows failed logon event                             |
| Same target user       | Repeated attempts against one account                  |
| Same endpoint          | Activity occurred on the monitored Windows host        |
| Local test source      | The lab used `runas`, so source IP may appear as local |

In a real SOC environment, repeated Event ID `4625` logs should be reviewed to determine whether the activity is caused by user error, misconfigured services, password guessing, or brute force activity.

## 7. Impact Assessment

| Area                 | Assessment             |
| -------------------- | ---------------------- |
| Credential Risk      | Medium                 |
| Endpoint Impact      | Low                    |
| Account Lockout Risk | Medium                 |
| Business Impact      | Low in lab environment |
| SOC Priority         | Medium                 |

## 8. MITRE ATT&CK Mapping

| Tactic            | Technique         | ID        |
| ----------------- | ----------------- | --------- |
| Credential Access | Brute Force       | T1110     |
| Credential Access | Password Guessing | T1110.001 |

## 9. Recommended Response

Recommended actions for a real SOC environment:

1. Identify the affected user account.
2. Check whether there were successful logins after the failed attempts.
3. Review the source IP or workstation name.
4. Determine whether the activity is user error or suspicious authentication behavior.
5. Check for similar failed login activity on other hosts.
6. Lock or reset the account password if compromise is suspected.
7. Escalate if failed attempts are followed by successful login or lateral movement.

## 10. Conclusion

The detection successfully identified repeated failed login attempts using Splunk and Windows Security Event Logs. This scenario demonstrates SOC analyst skills in authentication log analysis, alert triage, evidence review, MITRE ATT&CK mapping, and incident reporting.

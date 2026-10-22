# Incident Report IR-001: Local Administrators group modified on win-soc-01

| | |
|---|---|
| **Incident** | Sentinel incident #3 |
| **Detection rule** | `win-admin-group-add` (Windows: member added to local Administrators) |
| **Severity** | High |
| **Host** | win-soc-01 (Windows Server 2022, Azure Austria East) |
| **Date of activity** | 21 October 2026, 15:55 UTC |
| **Analyst** | Seth Owolabi |
| **Classification** | Benign Positive (authorised detection test) |
| **Status** | Resolved |

---

## 1. Summary

A new local account, `labtest`, was created on win-soc-01 and added to the built-in Administrators group within 67 milliseconds. The change was made by the `SYSTEM` account via **Azure Run Command**, which was initiated by the Azure user `owolabiseth7@gmail.com`. The activity was confirmed as an authorised detection test. The test account was removed after the investigation.

## 2. Timeline (UTC)

| Time | Source | Event |
|---|---|---|
| 15:55 | AzureActivity | `owolabiseth7@gmail.com` invokes Run Command on win-soc-01 from 155.117.189.112 (Start → Accept → Success) |
| 15:55:32.185 | SecurityEvent 4720 | Account `win-soc-01\labtest` created by `WORKGROUP\win-soc-01$` |
| 15:55:32.252 | SecurityEvent 4732 | Member SID `...-1000` (labtest) added to `Builtin\Administrators` by `WORKGROUP\win-soc-01$` |
| 16:04:57 | SecurityAlert | Rule `win-admin-group-add` raises a High alert; incident #3 created |
| 16:04:57 | SecurityAlert | Rule `win-new-local-user` raises a Medium alert (incident #2, same activity) |
| ~16:30 | Analyst | Incident assigned and set to In progress |
| ~16:47 | Run Command | `labtest` removed from Administrators (4733) and deleted (4726) |

**Time to detect:** about 9.5 minutes from the change to the alert.

## 3. Investigation

### 3.1 What happened on the host?
```kql
SecurityEvent
| where TimeGenerated between (datetime(2026-10-21 15:50) .. datetime(2026-10-21 16:00))
| where EventID in (4720, 4732)
| project TimeGenerated, EventID, Activity, TargetAccount, SubjectAccount, MemberSid
```
Both events were performed by `WORKGROUP\win-soc-01$`, the **computer account**, which means the action ran as `SYSTEM`, not as a logged-on person. The two events were 67 ms apart, which points to a script rather than manual activity.

### 3.2 Who was behind it?
A `SYSTEM`-level change with no interactive logon raises the question of how the command reached the machine. Azure Run Command lets anyone with sufficient Azure permissions execute scripts as `SYSTEM` without network access to the VM (MITRE ATT&CK T1651).
```kql
AzureActivity
| where TimeGenerated between (datetime(2026-10-21 15:50) .. datetime(2026-10-21 16:00))
| where OperationNameValue has "runCommand"
| project TimeGenerated, Caller, CallerIpAddress, OperationNameValue, ActivityStatusValue
```
Result: `owolabiseth7@gmail.com` ran Run Command against win-soc-01 at 15:55 from `155.117.189.112` and it succeeded. This links the host-level change to a specific cloud identity.

### 3.3 Was it authorised?
Yes. The caller is the lab owner, and the action matches a planned detection test (create a test account, add it to Administrators, confirm both rules fire).

**Note on the IP address:** `155.117.189.112` is a VPN exit address and differed from the IP allowed in the network security group at the time. An IP address alone did not identify the person. The authenticated Azure identity (MFA-protected) was the reliable evidence.

## 4. Classification

**Benign Positive.** The rule fired correctly on genuinely suspicious behaviour (privileged account creation via a remote execution path), and the activity was authorised.

In a real environment, the same evidence would be treated as a **likely compromise** if the Azure caller were unexpected, the sign-in came from an unusual location or device, or no change request existed. Recommended response in that case: disable the new account, revoke the caller's Azure sessions and reset their credentials, review the caller's other recent Azure activity, and check the host for further persistence.

## 5. Response actions

- Confirmed authorisation with the activity owner (lab owner).
- Removed the test account: `Remove-LocalGroupMember` (event 4733) and `Remove-LocalUser` (event 4726).
- Resolved incidents #2 and #3 as Benign Positive with comments.

## 6. MITRE ATT&CK mapping

| Technique | ID | Evidence |
|---|---|---|
| Create Account: Local Account | T1136.001 | Event 4720 |
| Account Manipulation | T1098 | Event 4732 (Administrators, SID S-1-5-32-544) |
| Cloud Administration Command | T1651 | AzureActivity Run Command by an Azure identity |

## 7. Lessons and detection improvements

1. **Correlate host and cloud logs.** The Windows events alone pointed to `SYSTEM`. Only the Azure Activity log identified the person. **Recommended new rule:** alert when Run Command executes on a VM, enriched with the caller identity, so analysts don't have to make this link manually.
2. **Duplicate alert.** `win-new-local-user` produced two alerts for one account creation. Grouping limited the impact (one incident), but the cause should be identified and fixed to reduce alert fatigue.
3. **Default filters can hide incidents.** The Defender Cases view filtered out priority scores below 15, which hid all new lab incidents. Analysts should not rely on a single default view.
4. **Identity beats IP.** VPN usage meant the source IP changed between actions. Investigations should anchor on authenticated identity, then use IP as supporting context.

# Detection Validation Report

Every detection rule in `detections/` was tested by deliberately performing the behaviour it should catch, on lab machines I own, and confirming that Sentinel raised an alert and incident. Tests were run with Azure Run Command or ordinary admin tools, so they did not depend on network access to the VMs.

**Test dates:** 21–22 October 2026
**Environment:** win-soc-01 (Windows Server 2022), lnx-soc-01 (Ubuntu 24.04), Azure subscription activity

---

## Results

| Rule | MITRE | Test performed | Expected evidence | Result | Time to alert |
|---|---|---|---|---|---|
| `win-new-local-user` | T1136.001 | Created local account `labtest` via Run Command | Event 4720 | ✅ Fired (2 alerts, grouped into 1 incident) | ~9 min |
| `win-admin-group-add` | T1098 | Added `labtest` to local Administrators | Event 4732, SID S-1-5-32-544 | ✅ Fired | ~9 min |
| `win-brute-force` | T1110 | 6 failed SMB logons to 127.0.0.1 as non-existent user `fakeuser` | 6 × Event 4625, SubStatus 0xc0000064 | ✅ Fired (3 alerts before tuning) | ~5 min |
| `win-security-log-cleared` | T1070.001 | `wevtutil cl Security` | Event 1102 | ✅ Fired | ~6 min |
| `linux-ssh-failed-logins` | T1110 | 6 SSH attempts to localhost as non-existent user `testuser` | sshd "Invalid user" in Syslog | ✅ Fired (3 alerts before tuning) | ~5 min |
| `azure-nsg-change` | T1562.007 | Updated the NSG's allowed source IP with Terraform | AzureActivity NSG write | ✅ Fired | ~4 min |
| `azure-role-assignment` | T1098 | Granted myself Reader on the lab resource group (twice) | AzureActivity roleAssignments/write | ❌ **Not fired: data source gap** (see below) | – |

**6 of 7 rules validated end to end.** All test artefacts were removed afterwards (test account deleted, test role removed, test incidents resolved as Benign Positive with comments).

---

## Tuning applied

### 1. Duplicate alerts from threshold rules
**Finding:** `win-brute-force` and `linux-ssh-failed-logins` raised **3 alerts for one burst** of failures. Both rules run every 5 minutes but look back 15 minutes, so the same events fell inside three consecutive windows.

**Fix:** 15-minute alert suppression on these two rules only (`suppression_enabled = true`). One burst now produces one alert.

**Trade-off considered:** suppression could hide a second, separate attack in the same 15 minutes. It was therefore **not** applied to single-event rules (new user, admin group add, log cleared, Azure changes), where every occurrence must alert.

### 2. False negative in the Azure rules
**Finding:** the `azure-role-assignment` rule did not fire although a role assignment existed. Investigation showed two causes:
- The rule only matched `ActivityStatusValue == "Success"`, and the Activity log recorded the test as **Started → Failed** although the assignment succeeded.
- Activity log events can arrive 5–15+ minutes late, and a 5-minute look-back can miss them.

**Fix (both Azure rules):**
- Match `Success` **and** `Failure`. A failed attempt to grant permissions or change a firewall is itself worth reviewing.
- Look back **1 hour**, but keep only rows that **arrived** since the last run: `where ingestion_time() > ago(5m)`. Each event alerts exactly once, however late it is ingested.

---

## Known detection gap: Azure role assignments

Even after the fix, the role assignment test could not be validated, because **the data source did not record the activity reliably**:

| Test (UTC) | Real outcome | What the Activity log recorded |
|---|---|---|
| 22 Oct 06:58 | Reader role assigned (confirmed with `az role assignment list`) | `roleAssignments/write`: **Started → Failed** |
| 22 Oct 13:29:37 | Reader role removed | `roleAssignments/delete`: Started → Succeeded |
| 22 Oct 13:29:44 | Reader role assigned (CLI returned the new assignment) | **Nothing recorded**, checked again after 24 hours |

The rule logic is correct, but it cannot alert on events that never reach the log. The deletion seven seconds earlier was recorded normally, so this is specific to the create operation and not a delivery problem with the whole log.

**Risk:** an attacker granting themselves a role could go undetected by this rule alone.

**Recommended mitigation (production):** add a second, independent control, such as a scheduled job that lists current role assignments and compares them against an approved baseline, alerting on any difference. This detects the *result* of the change rather than relying on the change being logged.

---

## Lessons

1. **Test every rule.** Two of seven rules had problems (duplicates, a false negative) that were only visible through testing.
2. **When a rule doesn't fire, check each stage in order:** did the event happen, did the source log it, did it reach Sentinel, did the rule run? Here the evidence pointed to the source.
3. **Detect results as well as actions.** Logs of changes can be incomplete; checking the current state against a baseline covers the gap.
4. **Document gaps honestly.** A known, explained gap with a mitigation plan is more useful to a security team than a rule that is assumed to work.

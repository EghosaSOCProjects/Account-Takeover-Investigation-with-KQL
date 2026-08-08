# Account Takeover Investigation with KQL


### Project Overview

This project demonstration is to get an understanding of analyzing and investigation of a suspected Account Takeover (ATO) using Kusto Query Language (KQL).

The investigation follows a real SOC workflow from alert triage through investigation, evidence gathering, incident analysis, attacker timeline creation, MITRE ATT&CK mapping, containment, eradication, and lessons learned.


### The scenario

Cloudora's IT admin flagged an impossible-travel alert: the CEO, Daniel Reeve, appeared to sign in from Lagos, Nigeria at 03:12 UTC while he was asleep in London — two days before the company was due to close its biggest enterprise deal. I worked the ticket as a SOC analyst: confirm or refute the compromise, build the full timeline, find any attacker persistence, scope every affected account, and write the incident report leadership would take to the client.

# Environment

Logs were investigated in Azure Data Explorer rather than Sentinel directly — same KQL, no ingestion-API overhead for a self-contained lab. Two tables were loaded from CSV:

* CloudoraSignIn_CL — 8 days of Entra ID sign-in logs (~1,479 rows)
* CloudoraAudit_CL — tenant audit events

#### Investigation walkthrough

###1. Triage — is the Lagos sign-in real?

Pulled every sign-in on the account for the incident day and read the story in the timestamps.

<img width="1919" height="909" alt="login_attempts_01" src="https://github.com/user-attachments/assets/7ba1be11-2671-4a64-b730-6d79e2b39591" />


Three failed attempts at 03:09 and 03:10 from 102.89.44.17 (Lagos), then a success at 03:12, followed by Outlook Web (03:14) and Azure Portal (03:26) — then a genuine London sign-in at 08:41. One account, two countries, five and a half hours apart, with failures immediately ahead of the successful login. That combination rules out a simple UI/timestamp glitch straight away.

### 2. Baseline — rule out travel before calling it a breach

Location alone never proves compromise, so I pulled the account's full 8-day sign-in history and compared it against a second account that also showed a new country that week.

<img width="1919" height="909" alt="Daniel_account_login af_02" src="https://github.com/user-attachments/assets/1b1d6301-8695-4013-a8a9-2fadbe8d195a" />

Daniel's account: 38 sign-ins from London across the whole window, then a single burst of Lagos activity confined to the early hours of the last night — no prior history there at all.

<img width="1919" height="909" alt="Omar_account_login af_02" src="https://github.com/user-attachments/assets/ca6859e6-64b8-4c88-85df-3bf4be8150c9" />

Compare that against omar.farah@cloudora.io: 12 Dubai sign-ins spread across three days, all daytime, all first-try successes — a normal travel pattern. Same "new country" signal, opposite verdict. This side-by-side comparison — anomaly vs. explained anomaly — is the actual judgment call in this investigation, not the geolocation itself.

### 3. Initial access — how did the attacker get a valid password?

A successful login means the password was obtained somehow, so I hunted backwards across the whole dataset for credential attacks.

<img width="1919" height="909" alt="Password spray (MITRE T1110 003) af_04" src="https://github.com/user-attachments/assets/26e370b8-eb93-4b23-a30a-617aa7c3f9a9" />

Three Lagos IPs stand out sharply from normal background noise: 102.89.44.17 (48 failures / 23 accounts), 102.89.45.101 (38 / 20), and 102.89.44.23 (28 / 18) — each hitting dozens of different accounts only 1–3 times apiece. Compare that to the handful of failures on ordinary corporate IPs (single-digit counts, 1–4 accounts) — normal typo noise, not an attack. Few attempts spread across many accounts from the same source is the signature of a password spray (MITRE T1110.003), built to stay under lockout thresholds.

<img width="1918" height="903" alt="Screenshot 2026-08-02 212211" src="https://github.com/user-attachments/assets/c20a8bd1-3057-4bd5-baf3-2d713b1b730c" />

Bucketing by day confirms the campaign ran for three consecutive nights before the breach (44 → 36 → 34 failed attempts), with exactly 5 successful logins appearing from the same attacker infrastructure on the final night — the moment the spray actually paid off.

### 4. Persistence — what did the attacker do after getting in?

Attackers assume they'll eventually be caught, so the next question is always: what backdoor did they leave?

<img width="1912" height="902" alt="Screenshot 2026-08-02 212725" src="https://github.com/user-attachments/assets/60c3e5a7-0f4b-4161-a8bc-e5bec2556a2b" />

Two findings, both against the CEO's mailbox from the same Lagos IP:

* 03:18 — the attacker registered their own authentication app (device 'Pixel 6') — MITRE T1098.005, meaning they'd survive a password reset alone.

* 03:31 — a hidden inbox rule ('RSS Subscriptions') was created that silently diverts anything from finance@cloudora.io or containing 'invoice' — MITRE T1564.008, the standard staging move for invoice fraud (BEC).

This is exactly why "just reset the password" is not an adequate response on its own.


### 5. Scope — who else was hit?

Never assume a single victim. I pulled every account the attacker's IPs actually reached a successful login on, across the whole data set.

<img width="1919" height="909" alt="35 minutes later from a different Lagos IP af_05" src="https://github.com/user-attachments/assets/e9398767-12e8-469b-bf1b-62232039ceb9" />

The attacker successfully accessed two accounts, not one: the CEO, and a second employee, priya.nair@cloudora.io, compromised 35 minutes later from a different Lagos IP — and, per the follow-up investigation, straight into a SharePoint session rather than the mailbox. Repeating the same three-move method (timeline → baseline → persistence check) on Priya's account confirmed the same verdict: genuine compromise, no attacker persistence found in the available audit data (which is documented as an evidence gap, not proof of a clean account — she still got the full containment treatment).

# Incident Report

CEO Account Takeover via Password Spray & Mailbox Persistence

**Cloudora Security Operations — Incident Report**
`CONFIDENTIAL — Internal and client distribution only`

| Field | Value |
|---|---|
| **Report ID** | `CLD-IR-0002` |
| **Related ticket** | `INC-2026-04871` — "Impossible travel alert: D. Reeve" (raised by IT admin) |
| **Analyst** | Eghosa |
| **Date of report (UTC)** | 2026-08-08 |
| **Severity** | 🔴 **P1** — CEO and second-employee mailbox/SharePoint compromise with active attacker persistence (rogue MFA device + hidden inbox rule staged for invoice fraud), discovered two days before the company's largest pending enterprise deal |
| **Status** | ✅ Closed — contained, eradicated, verified; residual scope-verification recommendations remain open ([§8](#8-recommendations)) |

> Adapted from the [Account Takeover Investigation with KQL](https://github.com/EghosaSOCProjects/Account-Takeover-Investigation-with-KQL) project. Fields below marked as placeholders or evidence gaps should be reconciled against the original `CloudoraSignIn_CL` / `CloudoraAudit_CL` tables before this report leaves the SOC.

---

## Table of contents

1. [Executive summary](#1-executive-summary)
2. [Incident timeline](#2-incident-timeline)
3. [Findings](#3-findings)
4. [Indicators of compromise (IOCs)](#4-indicators-of-compromise-iocs)
5. [MITRE ATT&CK mapping](#5-mitre-attck-mapping)
6. [Scope](#6-scope)
7. [Actions taken](#7-actions-taken)
8. [Recommendations](#8-recommendations)
9. [Lessons learned](#9-lessons-learned)

---

## 1. Executive summary

Cloudora's CEO, Daniel Reeve, had his Microsoft 365 account taken over by an external attacker who first breached a foothold using a three-night password-spraying campaign against the tenant. The compromise was found after an IT admin flagged an impossible-travel alert — a login from Lagos, Nigeria while the CEO was believed to be asleep in London — which the SOC confirmed as genuine takeover, not travel, by comparing it against the CEO's own sign-in history and against a colleague's real overseas trip. Once inside, the attacker registered their own authenticator app and created a hidden mailbox rule designed to intercept finance and invoice-related email, and a second employee's account was compromised 35 minutes later. Both accounts were disabled, their sessions revoked, passwords reset, the rogue MFA device and mailbox rule removed, and the attacker's IP addresses blocked; no evidence of completed financial fraud or data exfiltration was found in the available logs, though the timing immediately before a major deal closure represented a significant business risk.

## 2. Incident timeline

> All times UTC. "Day N" refers to the position within the 8-day `CloudoraSignIn_CL` / `CloudoraAudit_CL` log window reviewed; exact calendar dates were not preserved in the lab export and should be substituted from the source tables before client distribution.

| Time (UTC) | Source | Event | Evidence / notes |
|---|---|---|---|
| Day 1–5 (rolling) | `CloudoraSignIn_CL` | Background noise: single-digit failed logins on ordinary corporate IPs, 1–4 accounts each. | Normal typo-level failure baseline, used for comparison against spray traffic. |
| Day 6, night | `CloudoraSignIn_CL` | 44 failed logins from `102.89.44.17` / `102.89.45.101` / `102.89.44.23` across dozens of distinct Cloudora accounts (1–3 attempts per account). | First night of password-spray campaign (T1110.003). |
| Day 7, night | `CloudoraSignIn_CL` | 36 failed logins from the same three Lagos IPs, same low-and-slow pattern. | Second night of spray campaign. |
| Day 8, 03:09–03:10 | `CloudoraSignIn_CL` | 3 failed logins on `daniel.reeve@cloudora.io` from `102.89.44.17`. | Final night of spray; this account's password guessed shortly after. |
| Day 8, 03:12 | `CloudoraSignIn_CL` | Successful sign-in on `daniel.reeve@cloudora.io` from `102.89.44.17` (Lagos, Nigeria). | Initial access achieved (T1078). 5 successful logins recorded tenant-wide from spray infrastructure this night. |
| Day 8, 03:14 | `CloudoraSignIn_CL` | Outlook Web Access session opened on `daniel.reeve@cloudora.io` from `102.89.44.17`. | Attacker begins mailbox access. |
| Day 8, 03:18 | `CloudoraAudit_CL` | New authenticator app registered on `daniel.reeve@cloudora.io` — device name **"Pixel 6"** — from `102.89.44.17`. | Attacker-controlled MFA registered (T1098.005); survives a password-only reset. |
| Day 8, 03:26 | `CloudoraSignIn_CL` | Azure Portal sign-in on `daniel.reeve@cloudora.io` from `102.89.44.17`. | Attacker explores tenant/admin surface beyond mailbox. |
| Day 8, 03:31 | `CloudoraAudit_CL` | Hidden inbox rule **"RSS Subscriptions"** created on `daniel.reeve@cloudora.io`, silently redirecting mail from `finance@cloudora.io` or containing "invoice". | Defense evasion / BEC staging (T1564.008). |
| Day 8, ~03:47 (35 min after 03:12 success) | `CloudoraSignIn_CL` | Successful sign-in on `priya.nair@cloudora.io` from a second, different Lagos IP, proceeding directly into a SharePoint session. | Second account confirmed compromised; scope expands beyond the CEO mailbox. |
| Day 8, 08:41 | `CloudoraSignIn_CL` | Genuine sign-in on `daniel.reeve@cloudora.io` from London, standard device/browser. | Confirms the account owner was in London throughout — corroborates the 03:12 Lagos login as illegitimate. |

## 3. Findings

### Finding 1 — Password-spray campaign
A password-spray campaign targeting the Cloudora tenant ran for three consecutive nights from three Lagos-based IP addresses before the breach.

- **Evidence:** `CloudoraSignIn_CL` failed-logon counts by source IP: `102.89.44.17` (48 failures / 23 accounts), `102.89.45.101` (38/20), `102.89.44.23` (28/18), each averaging 1–3 attempts per account across dozens of accounts — versus single-digit, 1–4-account failure counts on ordinary corporate IPs. Daily failure totals: 44 → 36 → 34, culminating in 5 successful logins on the final night.
- **Why it matters:** Explains how the attacker obtained a valid password without triggering standard lockout thresholds, and confirms this was a targeted campaign rather than isolated guesswork.

### Finding 2 — Genuine takeover, not travel
The Lagos sign-in on `daniel.reeve@cloudora.io` at 03:12 UTC was a genuine account takeover, not a false positive from travel.

- **Evidence:** 8-day sign-in baseline shows 38 London logins for this account with no prior Lagos activity; the Lagos session was immediately preceded by 3 failed attempts from the same IP and followed 5.5 hours later by a legitimate London login. This is the opposite pattern to `omar.farah@cloudora.io`, whose 12 Dubai logins that week were spread across three days, daytime, all first-try successes.
- **Why it matters:** Establishes the core judgment call of the investigation: the same raw signal (new country) produced two different verdicts depending on the surrounding pattern, which is why baselining mattered more than the geolocation alone.

### Finding 3 — MFA persistence
The attacker established MFA-level persistence on the CEO's account 6 minutes after gaining access.

- **Evidence:** `CloudoraAudit_CL` shows a new authenticator app registered under device name "Pixel 6" at 03:18 UTC from `102.89.44.17`, on `daniel.reeve@cloudora.io`.
- **Why it matters:** A password reset alone would not have evicted the attacker, since the rogue MFA method would still authenticate them — this materially changed the required containment steps.

### Finding 4 — Hidden inbox rule (BEC staging)
The attacker created a hidden inbox rule on the CEO's mailbox designed to intercept finance and invoice-related correspondence.

- **Evidence:** `CloudoraAudit_CL` shows an inbox rule named "RSS Subscriptions" created at 03:31 UTC, filtering and redirecting mail from `finance@cloudora.io` or containing the word "invoice".
- **Why it matters:** Consistent with staging for business email compromise / invoice-fraud follow-on activity, and indicates financial-fraud intent rather than opportunistic access.

### Finding 5 — Second account compromised
A second account, `priya.nair@cloudora.io`, was independently compromised by the same attacker infrastructure 35 minutes after the CEO account.

- **Evidence:** `CloudoraSignIn_CL` shows a successful login on `priya.nair@cloudora.io` from a second, distinct Lagos IP, proceeding directly into a SharePoint session.
- **Why it matters:** Confirms this was not a single-account incident; scope had to be extended before containment could be considered complete.

### Finding 6 — No persistence found (evidence gap)
No attacker persistence (rogue MFA device or mailbox rule) was found on `priya.nair@cloudora.io` in the available audit data.

- **Evidence:** `CloudoraAudit_CL` reviewed for the same window and account; no equivalent device-registration or inbox-rule events located.
- **Why it matters:** Reduces likelihood of ongoing access on this account, but does not prove a clean account.
- **⚠️ Inference flag:** This is an absence-of-evidence finding, not a confirmed absence of persistence — audit log coverage for this account was not independently verified as complete. Treat as an evidence gap, not a clean bill of health.

## 4. Indicators of compromise (IOCs)

| Type | Value | First seen (UTC) | Context |
|---|---|---|---|
| IP address | `102.89.44.17` | Day 6 (spray start) | Primary spray + initial-access IP; 48 failed logins across 23 accounts; source of CEO account compromise, MFA registration, and inbox rule creation. |
| IP address | `102.89.45.101` | Day 6 (spray start) | Secondary spray IP; 38 failed logins across 20 accounts. |
| IP address | `102.89.44.23` | Day 6 (spray start) | Tertiary spray IP; 28 failed logins across 18 accounts. |
| IP address | `[second Lagos IP – priya.nair session]` ⚠️ | Day 8, ~03:47 | Used for the `priya.nair@cloudora.io` compromise; distinct from the three spray IPs above. Exact address not captured in the reviewed log excerpt — pull from `CloudoraSignIn_CL` and add before client distribution. |
| Device name | `Pixel 6` | Day 8, 03:18 | Rogue authenticator app registered on `daniel.reeve@cloudora.io` for MFA persistence. |
| Mailbox rule name | `RSS Subscriptions` | Day 8, 03:31 | Hidden inbox rule on `daniel.reeve@cloudora.io` redirecting mail from `finance@cloudora.io` / containing "invoice" — BEC staging. |

## 5. MITRE ATT&CK mapping

| Tactic | Technique ID | Technique name | Evidenced by |
|---|---|---|---|
| Credential Access | [T1110.003](https://attack.mitre.org/techniques/T1110/003/) | Brute Force: Password Spraying | Finding 1 — low-and-slow failed logins from 3 Lagos IPs against dozens of accounts over 3 nights. |
| Initial Access | [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | Finding 2 — successful sign-in on `daniel.reeve@cloudora.io` using a valid, spray-obtained password. |
| Persistence | [T1098.005](https://attack.mitre.org/techniques/T1098/005/) | Account Manipulation: Device Registration | Finding 3 — attacker-registered authenticator app ("Pixel 6") on the CEO's account. |
| Defense Evasion | [T1564.008](https://attack.mitre.org/techniques/T1564/008/) | Hide Artifacts: Email Hiding Rules | Finding 4 — hidden inbox rule "RSS Subscriptions" diverting finance/invoice mail. |

## 6. Scope

**Accounts confirmed compromised**
- `daniel.reeve@cloudora.io` (CEO) — successful login, MFA persistence, and mailbox-rule persistence confirmed (Findings 2–4).
- `priya.nair@cloudora.io` — successful login and SharePoint access confirmed 35 minutes later from a second Lagos IP; no persistence found, treated as an evidence gap rather than a clean result (Findings 5–6).

**Accounts targeted but not breached**

Approximately 40+ distinct accounts received 1–3 failed login attempts from the three spray IPs (`102.89.44.17`, `102.89.45.101`, `102.89.44.23`) with no successful authentication recorded against them in `CloudoraSignIn_CL` for the reviewed window. The exact deduplicated account list should be pulled from the full 1,479-row dataset and attached as an appendix before client distribution — it was not itemised in the source investigation notes reviewed for this report.

**Accounts investigated and cleared (false positives)**

- `omar.farah@cloudora.io` — flagged for a new country (Dubai) in the same period, but 12 logins spread across three days, all daytime and first-try successes, consistent with genuine business travel and inconsistent with the spray/takeover pattern seen on the CEO account (Finding 2).

## 7. Actions taken

> ⚠️ Exact UTC timestamps for the containment steps below were not captured in the lab dataset/source notes reviewed for this report. Per this template's own standard, an action without a timestamp did not happen — these steps are documented as completed (per the source investigation's containment checklist) but must have real timestamps added from the ticketing/SOAR system before this report is finalised for client distribution.

| Time (UTC) | Action | Performed by | Verified how |
|---|---|---|---|
| *not logged in lab dataset* | Disabled `daniel.reeve@cloudora.io` and `priya.nair@cloudora.io` | SOC analyst (Eghosa) | Sign-in logs show no further successful authentications from attacker IPs after disablement. |
| *not logged in lab dataset* | Revoked refresh tokens on both accounts | SOC analyst (Eghosa) | Forced re-authentication confirmed; no further Outlook Web / SharePoint sessions from attacker IPs. |
| *not logged in lab dataset* | Forced password reset on both accounts | SOC analyst (Eghosa) | Password change events confirmed in `CloudoraAudit_CL`. |
| *not logged in lab dataset* | Removed rogue "Pixel 6" MFA registration | SOC analyst (Eghosa) | Authenticator method list reviewed post-removal; only legitimate device remains. |
| *not logged in lab dataset* | Removed hidden "RSS Subscriptions" inbox rule | SOC analyst (Eghosa) | Inbox rules audit re-checked; rule no longer present. |
| *not logged in lab dataset* | Blocked IPs `102.89.44.17`, `102.89.45.101`, `102.89.44.23` at the edge | SOC analyst (Eghosa) | No further sign-in attempts observed from these IPs in subsequent log review. |
| *not logged in lab dataset* | Initiated user awareness training for both affected users | SOC analyst (Eghosa) | Training assignment confirmed with People Ops (not independently verified by SOC). |

## 8. Recommendations

**Quick wins**
- [ ] Block or heavily restrict sign-ins from the three identified Lagos IP ranges (`102.89.44.0/24`, `102.89.45.0/24`) pending legitimate business justification.
- [ ] Enable alerting on new authenticator-app / MFA-method registrations for executive and finance-adjacent accounts, requiring secondary verification.
- [ ] Enable alerting on creation of inbox rules that forward, redirect, or delete mail matching finance/invoice keywords.
- [ ] Re-issue credentials and re-verify MFA enrolment for the ~40 accounts targeted by the spray but not breached, as a precaution.

**Strategic changes**
- [ ] Deploy smart lockout / risk-based conditional access so repeated low-volume failures across many accounts from the same source trigger a tenant-wide signal, not just per-account thresholds.
- [ ] Move executive and finance-adjacent accounts to phishing-resistant MFA (e.g. FIDO2 hardware keys) to remove password-spray as a viable initial-access path.
- [ ] Require timestamped logging of every containment action in the incident-response tool so future reports don't have gaps like (#7-actions-taken) of this one.
- [ ] Extend the scoping methodology used here (baseline vs. anomaly comparison) into a standing detection rule rather than a manual ad-hoc comparison.

## 9. Lessons learned

**What worked**
Comparing the flagged account's own baseline against a second, independently-travelling account was the deciding factor in confirming compromise quickly — geolocation alone would not have been conclusive either way, and this comparison approach caught the second, less obvious compromise (`priya.nair`) that a single-account investigation would have missed.

**What was slow or missing**
Exact action timestamps for containment steps were not consistently captured, which weakens the evidentiary record for (#7-actions-taken) and had to be flagged rather than filled in. Full deduplicated scope (the complete list of ~40+ targeted-but-not-breached accounts) also was not itemised during the investigation and remains an outstanding appendix item.

**What the SOC should do differently**
Log containment actions with UTC timestamps directly into the case ticket as they happen, not after the fact; and treat "no persistence found" on a secondary account as an explicit evidence gap in the report rather than an implicit clean result, so it isn't mistaken for verification later.


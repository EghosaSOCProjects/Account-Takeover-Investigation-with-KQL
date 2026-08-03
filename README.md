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

# Containment

✅ Disabled account

✅ Revoked refresh tokens

✅ Forced password reset

✅ Removed MFA registration

✅ Removed mailbox rules

✅ Blocked malicious IP

✅ Initiated user awareness training

# MITRE ATT&CK Mapping

| Technique         | ID        |
| ----------------- | --------- |
| Password Spraying | T1110.003 |
| Initial Access    | T1078     |
| Persistence       | T1098.005 |
| Defense Evasion   | T1564.008 |

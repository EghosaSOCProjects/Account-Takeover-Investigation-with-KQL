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

1. Triage — is the Lagos sign-in real?

Pulled every sign-in on the account for the incident day and read the story in the timestamps.

<img width="1919" height="909" alt="login_attempts_01" src="https://github.com/user-attachments/assets/7ba1be11-2671-4a64-b730-6d79e2b39591" />


Three failed attempts at 03:09 and 03:10 from 102.89.44.17 (Lagos), then a success at 03:12, followed by Outlook Web (03:14) and Azure Portal (03:26) — then a genuine London sign-in at 08:41. One account, two countries, five and a half hours apart, with failures immediately ahead of the successful login. That combination rules out a simple UI/timestamp glitch straight away.

2. Baseline — rule out travel before calling it a breach

Location alone never proves compromise, so I pulled the account's full 8-day sign-in history and compared it against a second account that also showed a new country that week.

<img width="1919" height="909" alt="Daniel_account_login af_02" src="https://github.com/user-attachments/assets/1b1d6301-8695-4013-a8a9-2fadbe8d195a" />

Daniel's account: 38 sign-ins from London across the whole window, then a single burst of Lagos activity confined to the early hours of the last night — no prior history there at all.

<img width="1919" height="909" alt="Omar_account_login af_02" src="https://github.com/user-attachments/assets/ca6859e6-64b8-4c88-85df-3bf4be8150c9" />

Compare that against omar.farah@cloudora.io: 12 Dubai sign-ins spread across three days, all daytime, all first-try successes — a normal travel pattern. Same "new country" signal, opposite verdict. This side-by-side comparison — anomaly vs. explained anomaly — is the actual judgment call in this investigation, not the geolocation itself.


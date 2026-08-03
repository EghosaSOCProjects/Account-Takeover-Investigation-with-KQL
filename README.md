# Account Takeover Investigation with KQL


### Project Overview

This project demonstrates was to get an understanding of analyzing a investigation of a suspected Account Takeover (ATO) using Kusto Query Language (KQL).

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

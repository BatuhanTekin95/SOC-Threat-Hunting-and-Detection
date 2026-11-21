# SOC Threat Hunting & Detection

## About This Project

I started this project to improve my Splunk skills and gain practical experience in SOC investigations.

I'm currently preparing for a Junior SOC Analyst role, and I wanted to practice what I've learned using real security logs instead of just studying theory.

I'm using the Splunk BOTS v2 dataset to investigate suspicious activities, write SPL queries, create my own detection rules, and analyze triggered alerts.

When I find something suspicious, I try to understand what happened, collect evidence, and decide whether it needs to be escalated to SOC L2.

## Investigations

[01 – Multiple Failed Login Attempts](investigations/001-multi-account-password-guessing/investigation-report.md)

In my first investigation, I created a Splunk alert for repeated failed Windows logins. I identified 14 failed attempts across three accounts, followed by a successful login from the same IP address.

The activity suggested possible password guessing or password spraying, so I documented my findings and prepared an L2 escalation report.

## What's Next?

I'll keep adding new investigations, detection rules, SPL queries, and escalation reports as I continue learning Splunk and improving my SOC skills.

---

*All investigations are based on security training datasets.*

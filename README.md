🧪 Wazuh Home Lab – SIEM Detection and Triage Practice

This home lab is built for one purpose: to understand attacker behavior and see how detections actually work behind the scenes.

I wasn’t trying to build a huge enterprise cluster or “advanced” detections. The goal was to get real hands-on experience with:

* how Windows logs look in raw form

* how Sysmon reports process creation

* how Wazuh rules trigger

* how correlation works

* what real alerts look like and how to triage them

I wanted a clear mental model of how SIEM logic connects to the alerts a Tier-1 analyst sees.
This lab helped me understand that end-to-end.

🖥️ Virtualization Setup (VirtualBox)

I used two VMs:

1. Ubuntu 24.04 LTS – Wazuh Stack

* Wazuh Manager

* Wazuh Indexer

* Wazuh Dashboard

2. Windows 10 Pro – Endpoint

* Sysmon using SwiftOnSecurity config

* Wazuh agent

* Test scripts (PowerShell payloads, MiniDump tests, scheduled task tests)

🌐 Networking
Ports Used

* 1514/TCP & UDP – agent → manager data channel

* 1515/TCP – agent registration

* 443/HTTPS – dashboard access from the Windows host machine

Routing Setup

Both machines use:

* NAT – for internet access

* Host-only adapter – gives each VM a unique local IP so they can communicate directly

NAT gives both VMs the same outbound identity, so the second adapter is required for proper endpoint → SIEM communication.

🔍 Tools and Data Sources
* Sysmon (SwiftOnSecurity config)

* Primary log source (Event ID 1).
  The SwiftOnSecurity config reduces noise so only meaningful events appear.

* Atomic Red Team (Red Canary)

Used specific MITRE-aligned tests to trigger detections:

* encoded PowerShell commands

* discovery commands

* lateral movement (tscon)

* credential dumping via comsvcs.dll MiniDump

* scheduled task persistence

ATR helps validate each rule in realistic attacker scenarios.

🎯 Goal of This Lab

To build a clear understanding of:

* what attacker activity looks like at the event level

* how detection rules are constructed

* how correlation windows work

* how to investigate alerts as a SOC analyst

* how to tune rules without making them noisy

This lab is the foundation I built so I can enter a SOC environment already understanding the backend logic of alerts instead of just clicking buttons on a dashboard.

This home lab is built for one purpose:
to understand attacker behavior and see how detections actually work behind the scenes.

I wasn’t trying to build a huge enterprise cluster or “advanced” detections.
The point was to get real hands-on experience with:

## - how Windows logs look in raw form

## - how Sysmon reports process creation

## - how Wazuh rules trigger

## - how correlation works

## - what real alerts look like and how to triage them

I wanted a clear mental model of how SIEM logic connects to the alerts a Tier-1 analyst sees.
This lab helped me understand that end-to-end.

Wazuh Lab Structure
## Virtualization ##

I used VirtualBox with two VMs:

## - Ubuntu 24.04 LTS – Wazuh Stack

** Wazuh Manager

** Wazuh Indexer

** Wazuh Dashboard

## - Windows 10 Pro – Endpoint

** Sysmon + SwiftOnSecurity config

** Wazuh agent

** Test scripts, PowerShell payloads, MiniDump tests, scheduled task tests

## Networking ##
Ports Used:

** 1514/TCP & UDP – agent - manager data channel

** 1515/TCP – agent registration

** 443/HTTPS – Wazuh Dashboard (accessed from my Windows host via browser)

Routing Setup:

Both machines use:

NAT for internet access (updates, package installs, GitHub, etc.)

Host-only adapter so the Ubuntu server and Windows endpoint have unique local IPs and can communicate directly

NAT alone gives both VMs the same outbound identity, so the second adapter is required for proper endpoint-to-SIEM communication.

## Tools and Data Sources
** Sysmon (SwiftOnSecurity config)

Sysmon provides detailed process creation logs (Event ID 1), which I use as the main data source for my custom Wazuh rules.
The SwiftOnSecurity config filters out noise so only meaningful events appear.

** Atomic Red Team (Red Canary)

I used specific Atomic tests aligned to MITRE ATT&CK techniques to trigger:

encoded PowerShell commands

discovery commands

lateral movement (tscon)

credential dumping via comsvcs.dll MiniDump

scheduled task persistence

ATR helped validate each rule in realistic scenarios.

## Goal of This Lab ##

To build a clear understanding of:

how real attacker activity looks at the event level

how detection rules are constructed

how correlation windows work

how to investigate alerts as a SOC analyst

how to tune rules without making them noisy

This lab is the foundation I built so I can enter a SOC environment already understanding the backend logic of alerts instead of just clicking buttons on a dashboard.

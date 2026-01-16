TL;DR: Hands-on SOC lab demonstrating how Windows attack behaviors generate telemetry, how Wazuh detections are built, and how alerts are triaged and mapped to MITRE ATT&CK.

🔗 **YouTube Walkthrough Video:** [https://www.youtube.com/watch?v=gcVvTDXcBoE]


This project demonstrates how I built practical detections from scratch, tested them against real attacker techniques, triaged the alerts they generated, and aligned the work to the MITRE ATT&CK framework.


🧪 Wazuh Home Lab – SIEM Detection and Triage Practice

This home lab is built for one purpose: to understand attacker behavior and see how detections actually work behind the scenes.



I wasn’t trying to build a huge enterprise cluster or “advanced” detections. The goal was to get real hands-on experience with:


 * how Windows logs look in raw form
 * how Sysmon reports process creation
 * how Wazuh rules trigger
 * how correlation works
 * what real alerts look like and how to triage them




I wanted a clear mental model of how SIEM logic connects to the alerts a Tier-1 analyst sees.
This lab is what built that understanding for me.



🏛️ Lab Architecture
            
         Windows 10 (Sysmon + Wazuh Agent)
                       ↓
         Host-only Network
                       ↓
         Ubuntu 24.04 (Wazuh Manager + Indexer + Dashboard)



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



🔍 Tools and Data Sources:
   * Sysmon (SwiftOnSecurity config)
   * Primary log source (Event ID 1).
   * The SwiftOnSecurity config reduces noise so only meaningful events appear.
   * Some simulations were inspired by common MITRE ATT&CK Atomic-style techniques and manually executed using direct command-line payloads.

Tests were executed using direct command-line simulations aligned to MITRE ATT&CK techniques:

  * encoded PowerShell commands
  * discovery commands
  * lateral movement (tscon)
  * credential dumping via comsvcs.dll MiniDump
  * scheduled task persistence
  * RunKey Persistence (reg)
  * System Binary Proxy Execution: Mshta
  * Ingress Tool Transfer: certutil





🎯 Goal of This Lab

To build a clear understanding of:

  * what attacker activity looks like at the event level
  * how detection rules are constructed
  * how correlation windows work
  * how to investigate alerts as a SOC analyst
  * how to tune rules without making them noisy





🚀 How to Use This Repo (Deploy & Test the Rules)

  All custom Wazuh rules are developed inside:

   `/home/max/rules-custom`


  Each rule can be deployed into the Wazuh Manager with the helper script:
  `./deploy_rule.sh <rule_filename>`



  Example:
    `cd /home/max/rules-custom
    ./deploy_rule.sh discovery.xml`


  This script:

   * Copies the selected rule into the Wazuh rules directory:

 `/var/ossec/etc/rules/`


 Sets correct permissions

   * Restarts the Wazuh Manager so the rule becomes active

   `systemctl restart wazuh-manager`

 
   * Once the rule is deployed, you can run the test commands from:

   `AttackSimulation/`


 to trigger real alerts (PowerShell encoded commands, discovery, tscon lateral movement, MiniDump, scheduled tasks, etc).

 * View alerts in the Wazuh Dashboard → Security Events.


This lab is the foundation I built so I can enter a SOC environment already understanding the backend logic of alerts instead of just clicking buttons on a dashboard.

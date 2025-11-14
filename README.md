This home lab focuses on learning attacker behaviour and understanding how SIEM detections work under the hood.
The goal wasn't to build advanced detections, but to get real hands-on experience with event analysis, rule logic, and correlation




Wazuh lab: 

Hardware:

Virtual Box Environments (VM's):

1.Ubuntu 24.04 TLS server - Wazuh SIEM stack (wazuh-manager,wazuh-indexer,wazuh-dashboard) 

2.Windows 10 pro - Endpoint 

Networking: 

Ports - 
1514 TCP/UDP: Agent data channel, used by agent to send logs, events, alerts,sysmon data etc.. 

1515 TCP: Authentication, used only when an agent registers and gets its key.

443 HTTPS: Used for data channel of the dashboard, accesing the wazuh dashboard through 

the web browser (Through my windows host machine) using the IP of the server the Wazuh stack

is running on. (Ubuntu 24.04 TLS).

Routing:

1.Network Address Translation network (NAT) 
Used on both VM's to establish a connection to the internet. 

2. VirtualBox Host-only Ethernet adapter
Used on both VM's to assign different public IP adresses to our private ip address to establish
a connection between both VM's and make them communicate with each other on different IP's 
on the same network. (they can't run together on NAT , since they got same IP. so with second adapter
we assigning two different unique addresses to make them establish a connection between each other).

----------------------------------------------------------------------------------------------------
1. OSRegex engine, and PCRE2 (the syntax used in rule Engineering/tunning in Wazuh), # 'regex' in rule tunning

3. Atomic Red Team(By Red canary) - attack libary based on MITRE tactics, used for testing
   rules detection.
4. Sysmon agent on windows endpoint for collecting and monitoring precise logs of the system. 
-Sysmon using config SwiftOnSecurity(Widely used) for filtering the events that would be triggered. 

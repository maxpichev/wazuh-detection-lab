Detection: Account Discovery via PowerShell / CMD

Goal:
Detect account and user discovery activity (e.g., net users, whoami) executed via PowerShell or cmd.exe using Sysmon + Wazuh correlation rules.

MITRE Techniques

T1087 – Account Discovery

T1033 – System Owner / User Discovery

Detection Logic
Rule ID	Description	Type	Notes
92031	Discovery activity executed	Base (Sysmon)	Default SwiftOnSecurity Sysmon rule
900061	whoami.exe execution	Custom base	Extends coverage
900050	PowerShell-driven account discovery	Custom base	Detects PS activity
900400	Confirmed discovery: PS + spawned + executed	Correlation	3 events within 90s
900499	Confirmed discovery: PS + whoami	Correlation	2 events within 120s
Event Source

Sysmon Operational Channel

Wazuh Manager: local.discovery ruleset

Trigger Commands
# Simulate discovery via PowerShell
powershell -c "net users"
powershell -c "whoami"

# Direct CMD tests
cmd /c "net users"
whoami

Expected Results

900400 fires on PowerShell-driven account discovery chains.

900499 fires when whoami follows PowerShell activity within 120s.

Screenshots below show both detections firing in sequence.

Screenshots

images/commands.png — test commands executed

images/wazuh_alerts.png — dashboard showing 900400 / 900499 correlation alerts

Next Steps

Add dsquery, Get-ADUser, and Get-LocalUser to broaden coverage

Correlate with process tree validation for enhanced confidence

Test via Atomic Red Team (T1087, T1033)

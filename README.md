# Understanding_CI_Intrusions

Assignment 3 — Cyber & Infrastructure Defense


Author: Deeksha Reddy Patlolla


### Overview

Assignment 3 focuses on intrusion understanding, adversary emulation, and hands-on exploitation using a vulnerable PostgreSQL service on Metasploitable2. The assignment combines Cyber Kill Chain analysis, MITRE ATT&CK mapping, CVSS scoring, and real exploitation tasks to simulate a full attacker workflow—from reconnaissance through privilege escalation and log tampering.

This assignment builds operational knowledge of how real intrusions unfold and how defenders detect, prevent, and respond to them.

### Section 1 — Conceptual Assignments (25 pts)
### Cyber Kill Chain – Defensive Analysis

You documented all 7 Kill Chain stages and explained how each maps to defensive controls.
Key insights included:

Delivery is a critical choke point—controls like SEGs, sandboxing, URL rewriting, browser isolation, and phishing detection stop most attacks before exploitation.

Command & Control (C2) disruption prevents attackers from receiving instructions or exfiltrating data, even if initial access occurred.

Both stages form powerful defensive points for breaking an intrusion early or minimizing damage.

### MITRE ATT&CK Framework in Practice
### Scenario 1 — Hypothetical Intrusion

Mapped real attacker behavior to ATT&CK tactics & techniques:

Initial Access: T1566.002 — Spearphishing Link

Persistence / Privilege Escalation: T1059.001 — PowerShell Interpreter

Exfiltration: T1041 — Exfiltration Over C2 Channel

Included strong defensive measures such as MFA, URL sandboxing, constrained PowerShell, egress filtering, and DLP.

### Scenario 2 — APT Campaign Simulation

Mapped reconnaissance → exploitation → C2:

Recon: T1595.002 — Internet-scale vulnerability scanning

Exploitation: T1190 — Exploiting unpatched VPN appliances

C2: T1584.008 — Turning compromised network devices into covert C2 infrastructure

Provided matching defensive controls including external attack surface management, virtual patching, and strict device inventories.

### CVSS-Based Vulnerability Assessment

Performed scoring and justification for:

### Scenario 1 — Unauthorized DB Access

CVSS: 7.5 (High)

Internet-exposed, easy to exploit, high confidentiality impact.

### Scenario 2 — Privilege Escalation

CVSS: 7.8 (High)

Full system compromise but requires prior access.

Prioritization:
Scenario 1 is riskier due to external exposure and high breach probability, despite slightly lower CVSS.

### Section 2 — Practical Lab: Intrusion Simulation & Exploitation (75 pts)
### Task 1 — Reconnaissance (Netdiscover, Nmap)

Used ARP-based discovery + SYN scanning to enumerate:

Host IP: 192.168.10.13

20+ exposed services including PostgreSQL, Telnet, FTP, SMB, NFS, VNC, AJP.

Identified PostgreSQL 8.3.x as the highest-risk service due to EOL status, multiple public exploits, and sensitive data exposure.

Version detection supported targeted exploitation planning.

### Task 2 — PostgreSQL Default Credential Login

Logged in using postgres/postgres.
Confirmed:

User = superuser (rolsuper = t)

Complete control over roles, extensions, data, and server execution paths.

This demonstrates how default credentials create immediate high-severity compromise.

### Task 3 — RCE via Metasploit (PostgreSQL Payload Exploit)

Ran exploit/linux/postgres/postgres_payload.
Successful exploitation:

Uploaded malicious shared object

Executed payload

Returned Meterpreter session

Privilege context:

Executing as postgres (unprivileged OS user)

Requires LPE for root

Provides OS-level access and facilitates further pivoting.

### Task 4 — Persistence: Creating a Backdoor Superuser

Created a hidden PostgreSQL superuser to maintain long-term access.

Risks include:

Complete, persistent administrative control

Ability to install OS-level extensions

Log manipulation & DB-wide privilege abuse

Difficult forensic remediation if undiscovered

If undetected, enables prolonged dwell time and repeated intrusions.

### Task 5 — Privilege Escalation via SUID Nmap

Using a setuid-root Nmap binary:

nmap --interactive
!sh
bash -p


Confirmed full root access.

Highlights the severe risks of:

Leaving SUID binaries exposed

Interactive binaries enabling shell escapes

Lack of file integrity controls

### Task 6 — Defense Evasion: Log Tampering

Demonstrated clearing logs (/var/log/*) to remove intrusion evidence.

Discussed detection methods:

Centralized remote logging (SIEM, rsyslog, Wazuh)

File integrity monitoring (Tripwire, OSSEC)

Immutable logs (chattr +a)

Auditd rules for log modification events

Alerting on sudden log volume drops

Reinforced importance of off-host logging for forensic preservation.

Submission Contents

a3_report.md / a3_report.pdf (

a3_report

)

Screenshot folder

### Summary

Assignment 3 provided a realistic end-to-end view of an intrusion:

Kill Chain and ATT&CK mapping

Vulnerability scoring

Host discovery & service enumeration

Default credential abuse

PostgreSQL exploitation

Establishing persistence

Privilege escalation

Covering tracks

This assignment ties together red-team attacker methodology with blue-team defensive strategy, preparing you for more advanced threat analysis, incident response, and penetration-testing workflows.

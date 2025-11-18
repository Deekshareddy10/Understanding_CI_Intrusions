# CSCI 5743 – Assignment 3: Understanding CI Intrusions  
**Semester:** Fall 2025  
**Student Name:** [Deeksha Reddy Patlolla]  
**Student ID:** [111444513]  
**Total Points:** 100  

---

## **Section 1: Conceptual Assignments (25 pts)**

---

### **1. Cyber Kill Chain - Defensive Analysis** (5 pts)

**1.1 Briefly describe all seven stages of the Cyber Kill Chain:**

*(A structure known as the "Cyber Kill Chain" outlines the steps an adversary usually takes to organize, carry out, and profit from a cyber attack.  Reconnaissance, Weaponization, Delivery, Exploitation, Installation, Command & Control (C2), and Actions on Objectives make up the commonly used seven-stage model.  A targeted attacker action is represented by each stage, which includes gathering intelligence, developing or selecting an exploitable payload, sending it to victims, obtaining execution, establishing persistence, keeping control, and accomplishing goals.)*

*(Attackers use reconnaissance to find high-value entry points and vulnerable targets by listing public assets, staff responsibilities, and software versions.  By using exploit code or social engineering artifacts to find vulnerabilities, weaponization couples produced deliverables like harmful papers or exploit kits.  Delivery refers to the method of victim distribution, such as drive-by downloads, portable media, or spearphishing emails.  When a vulnerability is exploited or a user is duped, code runs; when that malware creates backdoors, scheduled tasks, or modified services that continue to run beyond reboots, installation takes place.  Actions on Objectives are the attacker's ultimate objectives, such as data theft, extortion, or disruption, whereas C2 is the stage where compromised hosts contact home to accept orders and exfiltrate data.)*

*(The Kill Chain is useful for defenders because it assigns specific mitigations to every stage.  Delivery success is decreased by preventive measures including email gateways, sandboxing, browser isolation, and user training.  Successful exploitation and installation are restricted by hardening, patch management, endpoint security, and application allow-listing.  C2 channels may be disrupted or made visible by network controls including beacon detection, DNS monitoring, and egress allow-listing.  The likelihood of a persistent infiltration is significantly reduced when layered, complementary measures are prioritized across several stages.)*

**1.2 Choose 2 stages most critical to defenders and explain:**

- **Selected Stage 1:Delivery**  
  - *Why it’s important:Delivery serves as the gateway between active compromise and reconnaissance/weaponization; by blocking or identifying malicious delivery, you may stop nearly every step that follows.*  
  - *Defensive strategy:To explode questionable payloads, use Secure Email Gateway (attachment/URL rewriting & sandboxing),browser isolation for untrusted connections combined with a web proxy or URL rewriting,User education combined with automated phish-report procedures and simulated phishing, Email and endpoint screening for YARA rules and hashes, which are signs of known malware.*
  - *Why effective:these measures significantly reduce the number of successful exploits by either removing the payload (sandboxing) or forcing it into an environment where exploitation fails (browser isolation).*

- **Selected Stage 2:Command & Control (C2)**  
  - *Why it’s important:Breaking their C2 channel stops coordination, payload retrieval, and data exfiltration, even if an attacker manages to obtain initial access.*  
  - *Defensive strategy:Only authorized external destinations and protocols are permitted through egress allow-listing, Targeted TLS proxying for high-risk hosts or TLS inspection (on authorized egress), DNS sinkholing and keeping an eye out for odd DNS patterns (such as nonsense domains or quick flux), Rules for detecting anomalous connection timing and beaconing patterns in networks.*  
  - *Why effective:By preventing the attacker from getting orders or stealing information, C2 disruption or detection reduces the consequences of a breach.*

---

### **2. MITRE ATT&CK Framework in Practice** (10 pts)

#### **2.1 Scenario 1: Hypothetical Cyber Intrusion**

- **Tactic 1: [Initial Access]**  
  - **Technique ID & Name:T1566.002 - Phishing: Spearphishing Link**  
  - **Description:A malicious link that led consumers to a phony login page was included in the phishing email that the attacker delivered.  After credentials were input, they were collected and utilized for remote VPN login.**  
  - **Defensive Measure:Implement secure URL sandboxing and email gateways; make multi-factor authentication (MFA) mandatory for all remote access; and train users to spot phishing attempts.**  

- **Tactic 2: [Persistence / Privilege Escalation]**  
  - **Technique ID & Name:T1059.001 – Command and Scripting Interpreter: PowerShell**  
  - **Description:A new local admin account with elevated rights and persistence was created on the compromised server by the attacker using a PowerShell script.**  
  - **Defensive Measure:Limit the formation of local administrators, enable PowerShell Script Block Logging and Constrained Language Mode, and keep an eye out for New-LocalUser or privilege escalation commands in event logs.**  

- **Tactic 3: [Exfiltration]**  
  - **Technique ID & Name:T1041 – Exfiltration Over C2 Channel**  
  - **Description:The attacker used an encrypted HTTPS connection to an external command-and-control server to compress and exfiltrate financial data.**  
  - **Defensive Measure:Set up egress rules and alarms for big or irregular HTTPS uploads; utilize TLS inspection for odd outgoing data; and use DLP (Data Loss Prevention) to monitor data transfers.**  

#### **2.2 Scenario 2: CuttingEdge APT Campaign**

- **Reconnaissance Technique:**  
  - **Technique ID & Name:T1595.002 – Active Scanning: Vulnerability Scanning**  
  - **Use in Campaign:In order to identify obsolete Ivanti and Fortinet VPN equipment susceptible to certain CVEs, the attackers searched the internet.**  
  - **Impact:supplied a list of targets that may be exploited to initiate additional intrusion actions.**  
  - **Defensive Control:Continuously scan the external attack surface, block IP ranges that are being scanned, and enforce network segmentation and patching on time.**  

- **Exploitation Technique:**  
  - **Technique ID & Name:T1190 – Exploit Public-Facing Application**  
  - **Use in Campaign:deployed web shells and obtained first access by taking advantage of unpatched VPNs.**  
  - **Impact:permitted lateral movement into internal networks and the execution of commands at will.**  
  - **Defensive Control:Implement virtual patching (WAF rules), update software often, and keep an eye out for unusual POST requests in web server logs.**  

- **C2 Technique:**  
  - **Technique ID & Name:T1584.008 – Compromise Infrastructure: Network Devices**  
  - **Use in Campaign:For endurance and secrecy, attackers turned hacked network equipment into command servers.**  
  - **Impact:Long-term access and challenging attribution were guaranteed.**  
  - **Defensive Control:Block obsolete network hardware types, keep stringent device inventories, and limit outgoing traffic.**  

---

### **3. CVSS-Based Vulnerability Assessments** (10 pts)

#### **Scenario 1: Unauthorized Database Access**

- **CVSS Metrics:**
  - AV: Network (N)
  - AC: Low (L)
  - PR: None (N) 
  - UI: None (N)  
  - C: High (H)
  - I: None (N)  
  - A: None (N)
- **CVSS Score:** [7.5 (High)]
- **Justification:**  
*(This vulnerability enables remote, unauthenticated exploitation via the internet without requiring user input.  The confidentiality effect is high yet integrity and availability are zero since attackers may read sensitive PII from the database in its entirety but cannot change or remove data.  According to the CVSS v3.1 calculation, the total base score is High (7.5) since exploitation is straightforward and doesn't need any credentials or user input.  Any public-facing service that has such a vulnerability should have it fixed right away via emergency patching, API gateway limitations, or authentication enforcement.)*

#### **Scenario 2: Privilege Escalation on Internal Server**

- **CVSS Metrics:**
  - AV: Local (L)
  - AC: Low (L)
  - PR: Low (L) 
  - UI: None (N) 
  - C: High (H)
  - I: High (H)
  - A: High (H) 
- **CVSS Score:** [7.8 (High)]
- **Justification:**  
*(The exploit results in full system compromise (root/superuser), but it needs an attacker to already have a low-privilege local account.  Confidentiality, integrity, and availability are all severely impacted as the attacker has complete control and may read, alter, and remove data.  The basic score is raised to 7.8 (High) despite the vector's locality due to its ease of exploitation and overall privilege gain.  Strict least-privilege enforcement, timely patching, and kernel-level exploit safeguards (e.g., SELinux, AppArmor) are examples of mitigations.)*

#### **Comparison and Risk Reflection**

- *Which scenario is riskier? Although both vulnerabilities have high CVSS scores, their actual risks are different: Due to the internet-exposed nature of the Database Access issue, exploitation is scalable and likely to result in imminent data breaches and regulatory consequences. The Privilege Escalation problem is serious in post-compromise situations since it offers complete power but necessitates gaining traction first.*  
- *Which should be prioritized and why?  Since exposure and data sensitivity increase organizational and legal risk, Scenario 1 is often given priority in most businesses.  Scenario 2 should be performed to solidify internal lateral-movement routes once exterior surfaces have been secured.*

---

## **Section 2: Practical Lab – Intrusion Simulation & Exploitation (75 pts)**

---

### **Task 1: Reconnaissance** (20 pts)

#### **1-1: Netdiscover**

**Screenshot:**  
![Netdiscover Output](./screenshots/netdiscover.png)

**Analysis Questions:**
1️⃣ What does `netdiscover` do, and what protocol does it use?  
*(Your answer)*  
2️⃣ What is the IP address of Metasploitable 2 (MS-2)?  
*(Your answer)*

---

#### **1-2: Nmap SYN Scan**

**Screenshot:**  
![Nmap SYN Scan](./screenshots/nmap_sS.png)

**Analysis Questions:**
3️⃣ List all open ports on MS-2.  
*(Your answer)*  
4️⃣ What is the most dangerous open service and why?  
*(Your answer)*

---

#### **1-3: Nmap Version Detection**

**Screenshot:**  
![Nmap Version Scan](./screenshots/nmap_sV.png)

**Analysis Questions:**
5️⃣ What version of PostgreSQL is running on MS-2?  
*(Your answer)*  
6️⃣ Why is version detection important in penetration testing?  
*(Your answer)*

---

#### **1-4: Vulnerability Scan (PostgreSQL)**

**Screenshot:**  
![Nmap Vulners PostgreSQL](./screenshots/vulners_postgres.png)

**Analysis Questions:**
7️⃣ List and rank the top 3 services.  
*(Your answer)*  
8️⃣ Justify your choices.  
*(Your answer)*  
9️⃣ Summarize the scan output.  
*(Your answer)*  
🔟 Were any vulnerabilities or warnings reported?  
*(Your answer)*  
1️⃣1️⃣ How can this inform an attacker's strategy?  
*(Your answer)*

---

### **Task 2: PostgreSQL Login with Default Credentials** (10 pts)

**Screenshot:**  
![PostgreSQL Login](./screenshots/postgres_login.png)

**Analysis Questions:**
1️⃣2️⃣ Were you able to connect with default credentials?  
*(Your answer)*  
1️⃣3️⃣ What privileges does the `postgres` user have?  
*(Your answer)*

---

### **Task 3: Exploit PostgreSQL for RCE via Metasploit** (15 pts)

**Screenshot(s):**  
- ![Metasploit Exploit Execution](./screenshots/metasploit_exploit.png)  
- ![Active Session & getuid](./screenshots/session_getuid.png)  
- ![Shell ID Output](./screenshots/id_output.png)

**Analysis Questions:**
1️⃣4️⃣ What happens when this exploit runs successfully?  
*(Your answer)*  
1️⃣5️⃣ What privileges do you have after exploitation?  
*(Your answer)*

---

### **Task 4: Persistence - Create a Backdoor PostgreSQL Superuser** (10 pts)

**Screenshot:**  
![Postgres Backdoor Creation](./screenshots/create_admin_user.png)

**Analysis Questions:**
1️⃣6️⃣ Why is it dangerous for attackers to create hidden superusers?  
*(Your answer)*  
1️⃣7️⃣ What happens if this account goes undetected?  
*(Your answer)*

---

### **Task 5: Privilege Escalation with Setuid Nmap Exploit** (10 pts)

**Screenshot:**  
![Privilege Escalation Process](./screenshots/nmap_priv_esc.png)

**Analysis Questions:**
1️⃣8️⃣ Did the exploit grant root access?  
*(Your answer)*  
1️⃣9️⃣ What is the risk of leaving setuid binaries accessible to unprivileged users?  
*(Your answer)*

---

### **Task 6: Defense Evasion - Covering Tracks (Log Tampering)** (10 pts)

**Screenshot:**  
![Log Tampering Sequence](./screenshots/log_tampering.png)

**Analysis Questions:**
2️⃣0️⃣ Why do attackers erase logs?  
*(Your answer)*  
2️⃣1️⃣ What security measures can detect log tampering?  
*(Your answer)*


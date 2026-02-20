# Interrelationship of CIS Safeguards & MITRE ATT&CK (Sub)Techniques

For each Safeguard assessed within the CSS IG1+ Assessment Framework, the list below provides the Safeguard's **dependencies** (those Safeguards upon which the referenced Safeguard depends), **dependents** (those Safeguards which depend upon the referenced Safeguard), and those (Sub)Techniques present in all five of the top MITRE ATT&CK Framework v8.2 attack types (Malware, Ransomware, Web Application Hacking, Insider Privilege and Misuse, and Targeted Intrusions) mitigated by the referenced Safeguard.

## Safeguard 1.1: Establish and Maintain a Detailed Enterprise Asset Inventory

**Dependencies:** None

**Dependents** 1.02, 2.03, 2.04, 3.02, 3.06, 4.03, 4.04, 4.05, 4.07, 6.04, 7.03, 7.04, 7.05, 7.06, 8.02, 8.03, 8.04, 8.05, 8.09, 9.02, 10.01, 10.03, 11.02, 11.03, 11.04, 13.01, 13.07

**"Top 5" (Sub)Techniques Mitigated:** None

___

## Safeguard 1.2: Address Unauthorized Assets

**Dependencies:** 1.01

**Dependents:** None

**"Top 5" (Sub)Techniques Mitigated:** None

___

## Safeguard 2.1: Establish and Maintain a Software Inventory

**Dependencies:** None

**Dependents:** 2.02, 2.03, 3.06, 4.01, 4.03, 4.04, 4.05, 4.07, 5.01, 7.03, 7.04, 7.05, 7.06, 8.09, 9.01, 10.01, 11.02, 11.03, 13.01, 13.07

**"Top 5" (Sub)Techniques Mitigated:** None

___

## Safeguard 2.2: Ensure Authorized Software is Currently Supported

**Dependencies:** 2.01

**Dependents:** None

**"Top 5" (Sub)Techniques Mitigated:**

 - VNC (T1021.005)
 - Python (T1059.006)
 - Archive Collected Data (T1560)
 - Archive via Utility (T1560.001)

___

## Safeguard 2.3: Address Unauthorized Software

**Dependencies:** 1.01, 2.01

**Dependents:** 2.04

**"Top 5" (Sub)Techniques Mitigated:**

 - Remote Desktop Protocol (T1021.001)
 - Command and Scripting Interpreter (T1059)
 - Trusted Developer Utilities Proxy Execution (T1127)

___

## Safeguard 2.4: Utilize Automated Software Inventory Tools

**Dependencies:** 1.01, 2.03

**Dependents:** None

**"Top 5" (Sub)Techniques Mitigated:** None

___

## Safeguard 3.1: Establish and Maintain a Data Management Process

**Dependencies:** None

**Dependents:** 3.04, 3.05, 3.07

**"Top 5" (Sub)Techniques Mitigated:** None

___

## Safeguard 3.2: Establish and Maintain a Data Inventory

**Dependencies:** 1.01

**Dependents:** 3.04, 3.05, 3.07

**"Top 5" (Sub)Techniques Mitigated:** None

___

## Safeguard 3.3: Configure Data Access Control Lists

**Dependencies:** 3.02, 4.01, 5.01

**Dependents:** None

**"Top 5" (Sub)Techniques Mitigated:**

 - Account Manipulation (T1098)
 - Indicator Removal on Host (T1070)

___

## Safeguard 3.4: Enforce Data Retention

**Dependencies:** 3.01, 3.02

**Dependents:** None

**"Top 5" (Sub)Techniques Mitigated:**

 - Indicator Removal on Host (T1070)

___

## Safeguard 3.5: Securely Dispose of Data

**Dependencies:** 3.01, 3.02

**Dependents:** None

**"Top 5" (Sub)Techniques Mitigated:** None

___

## Safeguard 3.6: Encrypt Data on End-User Devices

**Dependencies:** 1.01, 2.01, 4.01

**Dependents:** None

**"Top 5" (Sub)Techniques Mitigated:** None

___

## Safeguard 3.7: Establish and Maintain a Data Classification Scheme

**Dependencies:** 3.01, 3.02

**Dependents:** None

**"Top 5" (Sub)Techniques Mitigated:** None

___

## Safeguard 4.1: Establish and Maintain a Secure Configuration Process

**Dependencies:** 2.01

**Dependents:** 3.06, 4.03, 4.04, 4.05, 6.04, 6.05, 7.03, 7.04, 7.05, 7.06, 8.02, 8.10, 9.02, 10.01, 10.03, 11.02, 11.03, 11.04

**"Top 5" (Sub)Techniques Mitigated:**

 - OS Credential Dumping (T1003)
 - Remote Desktop Protocol (T1021-001)
 - Command and Scripting Interpreter (T1059)
 - Indicator Removal on Host (T1070)
 - Account Discovery (T1087)
 - Account Manipulation (T1098)
 - Brute Force (T1110)
 - Trusted Developer Utilities Proxy Execution (T1127)
 - Create Account (T1136)
 - Windows Service (T1543.003)

___

## Safeguard 4.3: Configure Automatic Session Locking on Enterprise Assets

**Dependencies:** 1.01, 2.01, 4.01

**Dependents:** None

**"Top 5" (Sub)Techniques Mitigated:** None

___

## Safeguard 4.5: Implement and Manage a Firewall on End-User Devices

**Dependencies:** 1.01, 2.01, 4.01

**Dependents:** None

**"Top 5" (Sub)Techniques Mitigated:** None

___

## Safeguard 4.7: Manage Default Accounts on Enterprise Assets and Software

**Dependencies:** 1.01, 2.01, 5.02

**Dependents:** None

**"Top 5" (Sub)Techniques Mitigated:**

 - OS Credential Dumping (T1003)
 - Remote Desktop Protocol (T1021.001)
 - Command and Scripting Interpreter (T1059)
 - Valid Accounts (T1078)
 - Default Accounts (T1078.001)
 - Domain Accounts (T1078.002)
 - Account Manipulation (T1098)
 - Brute Force (T1110)
 - Create Account (T1136)
 - Windows Service (T1543.003)

___

## Safeguard 5.1: Establish and Maintain an Inventory of Accounts

**Dependencies:** 2.01

**Dependents:** 5.03, 5.04, 6.05

**"Top 5" (Sub)Techniques Mitigated:**

 - Valid Accounts (T1078)
 - Domain Accounts (T1078.002)  

___

## Safeguard 5.2: Use Unique Passwords (Option for finding of insufficient password length)

**Dependencies:** None

**Dependents:** 4.07

**"Top 5" (Sub)Techniques Mitigated:**

 - OS Credential Dumping (T1003)
 - Valid Accounts (T1078)
 - Default Accounts (T1078.001)
 - Domain Accounts (T1078.002)
 - Brute Force (T1110)

___

## Safeguard 5.3: Disable Dormant Accounts

**Dependencies:** 5.01

**Dependents:** None

**"Top 5" (Sub)Techniques Mitigated:**

 - OS Credential Dumping (T1003)
 - Remote Desktop Protocol (T1021.001)
 - Command and Scripting Interpreter (T1059)
 - Valid Accounts (T1078)
 - Domain Accounts (T1078.002)
 - Account Manipulation (T1098)
 - Brute Force (T1110)
 - Create Account (T1136)
 - Windows Service (T1543.003)

___

## Safeguard 5.4: Restrict Administrator Privileges to Dedicated Administrator Accounts

**Dependencies:** 5.01

**Dependents:** None

**"Top 5" (Sub)Techniques Mitigated:**

 - OS Credential Dumping (T1003)
 - Command and Scripting Interpreter (T1059)
 - Indicator Removal (T1070)
 - Valid Accounts (T1078)
 - Domain Accounts (T1078.002)
 - Account Manipulation (T1098)
 - Create Account (T1136)
 - Windows Service (T1543.003)

___

## Safeguard 6.1: Establish an Access Granting Process

**Dependencies:** None

**Dependents:** None

**"Top 5" (Sub)Techniques Mitigated:**

 - OS Credential Dumping (T1003)
 - Remote Desktop Protocol (T1021.001)
 - Command and Scripting Interpreter (T1059)
 - Indicator Removal on Host (T1070)
 - Valid Accounts (T1078)
 - Domain Accounts (T1078.002)
 - Account Manipulation (T1098)
 - Create Account (T1136)
 - Windows Service (T1543.003)

___

## Safeguard 6.2: Establish an Access Revocation Process

**Dependencies:** None

**Dependents:** None

**"Top 5" (Sub)Techniques Mitigated:**

 - OS Credential Dumping (T1003)
 - Remote Desktop Protocol (T1021.001)
 - Command and Scripting Interpreter (T1059)
 - Indicator Removal on Host (T1070)
 - Valid Accounts (T1078)
 - Domain Accounts (T1078.002)
 - Account Manipulation (T1098)
 - Create Account (T1136)
 - Windows Service (T1543.003)

___

## Safeguard 6.4: Require MFA For Remote Network Access

**Dependencies:** 1.01, 4.01

**Dependents:** None

**"Top 5" (Sub)Techniques Mitigated:**

 - Remote Services: Remote Desktop Protocol (T1021.001)
 - Valid Accounts: Domain Accounts (T1078.002)
 - Account Manipulation (T1098)
 - Brute Force (T1110)
 - Create Account (T1136)

___

## Safeguard 6.5: Require MFA For Administrative Access

**Dependencies:** 4.01, 5.01

**Dependents:** None

**"Top 5" (Sub)Techniques Mitigated:**

 - Remote Desktop Protocol (T1021.001)
 - Domain Accounts (T1078.002)
 - Account Manipulation (T1098)
 - Brute Force (T1110)
 - Create Account (T1136)

___

## Safeguard 7.1: Establish and Maintain a Vulnerability Management Process

**Dependencies:** None

**Dependents:** None

**"Top 5" (Sub)Techniques Mitigated:** None

___

## Safeguard 7.2: Establish and Maintain a Remediation Process

**Dependencies:** None

**Dependents:** None

**"Top 5" (Sub)Techniques Mitigated:** None

___

## Safeguard 7.3: Perform Automated Operating System Patch Management

**Dependencies:** 1.01, 2.01, 4.01

**Dependents:** None

**"Top 5" (Sub)Techniques Mitigated:** None

___

## Safeguard 7.4: Perform Automated Application Patch Management

**Dependencies:** 1.01, 2.01, 4.01

**Dependents:** None

**"Top 5" (Sub)Techniques Mitigated:** None

___

## Safeguard 7.5: Perform Automated Vulnerability Scans of Internal Enterprise Assets

**Dependencies:** 1.01, 2.01, 4.01

**Dependents:** None

**"Top 5" (Sub)Techniques Mitigated:** None

___

## Safeguard 7.6: Perform Automated Vulnerability Scans of Externally-Exposed Enterprise Assets

**Dependencies:** 1.01, 2.01, 4.01

**Dependents:** None

**"Top 5" (Sub)Techniques Mitigated:**

 - Remote Desktop Protocol (T1021.001)

___

## Safeguard 8.1: Establish and Maintain an Audit Log Management Process

**Dependencies:** None

**Dependents:** 8.02

**"Top 5" (Sub)Techniques Mitigated:**

 - Indicator Removal on Host (T1070)

___

## Safeguard 8.2: Collect Audit Logs

**Dependencies:** 1.01, 4.01, 8.01

**Dependents:** None

**"Top 5" (Sub)Techniques Mitigated:**

 - Indicator Removal on Host (T1070)

___

## Safeguard 8.3: Ensure Adequate Log Storage 

**Dependencies:** 1.01

**Dependents:** None

**"Top 5" (Sub)Techniques Mitigated:**

 - Indicator Removal on Host (T1070)

___

## Safeguard 8.9: Centralize Audit Logs

**Dependencies:** 1.01, 2.01

**Dependents:** None

**"Top 5" (Sub)Techniques Mitigated:** None

___

## Safeguard 8.11: Conduct Audit Log Reviews

**Dependencies:** None

**Dependents:** None

**"Top 5" (Sub)Techniques Mitigated:** None

___

## Safeguard 9.1: Ensure Use of Only Fully Supported Browsers and Email Clients

**Dependencies:** 2.01

**Dependents:** None

**"Top 5" (Sub)Techniques Mitigated:** None

___

## Safeguard 9.2: Use DNS Filtering Services

**Dependencies:** 1.01, 4.01

**Dependents:** None

**"Top 5" (Sub)Techniques Mitigated:** None

___

## Safeguard 10.2: Configure Automatic Anti-Malware Signature Updates

**Dependencies:** 10.01

**Dependents:** None

**"Top 5" (Sub)Techniques Mitigated:**

 - Obfuscated Files or Information (T1027)
 - Command and Scripting Interpreter (T1059)

___


## Safeguard 10.3: Disable Autorun and Autoplay for Removable Media

**Dependencies:** 1.01, 4.01

**Dependents:** None

**"Top 5" (Sub)Techniques Mitigated:** None

___

## Safeguard 11.1: Establish and Maintain a Data Recovery Process

**Dependencies:** None

**Dependents:** None

**"Top 5" (Sub)Techniques Mitigated:** None

___

## Safeguard 11.2: Perform Automated Backups

**Dependencies:** 1.01, 2.01, 4.01

**Dependents:** None

**"Top 5" (Sub)Techniques Mitigated:** None

___

## Safeguard 11.3: Protect Recovery Data

**Dependencies:** 1.01, 2.01, 4.01

**Dependents:** None

**"Top 5" (Sub)Techniques Mitigated:**

 - OS Credential Dumping (T1003)
 - Account Manipulation (T1098)
 - Create Account (T1136)

___

## Safeguard 11.4: Establish and Maintain an Isolated Instance of Recovery Data

**Dependencies:** 1.01, 4.01

**Dependents:** None

**"Top 5" (Sub)Techniques Mitigated:**

 - Account Manipulation (T1098)
 - Create Account (T1136) 

___

## Safeguard 13.01: Centralize Security Event Alerting

**Dependencies:** 1.01, 2.01

**Dependents:** None

**"Top 5" (Sub)Techniques Mitigated:** None

___

## Safeguard 13.07: Deploy a Host-Based Intrusion Prevention Solution

**Dependencies:** 1.01, 2.01

**Dependents:** None

**"Top 5" (Sub)Techniques Mitigated:** 

 - Obfuscated Files or Information (T1027)
 - Command and Scripting Interpreter (T1059)

___

## Safeguard 14.01: Establish and Maintain a Security Awareness Program

**Dependencies:** None

**Dependents:** None

**"Top 5" (Sub)Techniques Mitigated:** None

___

## Safeguard 15.1: Establish and Maintain an Inventory of Service Providers

**Dependencies:** None

**Dependents:** None

**"Top 5" (Sub)Techniques Mitigated:** None

___

## Safeguard 17.1: Designate Personnel to Manage Incident Handling

**Dependencies:** None

**Dependents:** None

**"Top 5" (Sub)Techniques Mitigated:** None

___

## Safeguard 17.2: Establish and Maintain Contact Information for Reporting Security Incidents

**Dependencies:** None

**Dependents:** None

**"Top 5" (Sub)Techniques Mitigated:** None

___

## Safeguard 17.3: Establish and Maintain an Enterprise Process for Reporting Incidents

**Dependencies:** None

**Dependents:** None

**"Top 5" (Sub)Techniques Mitigated:** None

___

## Safeguard 18.2: Perform Periodic External Penetration Tests

**Dependencies:** None

**Dependents:** None

**"Top 5" (Sub)Techniques Mitigated:** None

___

# Purpose

The purpose of this document is to establish a standardized list of artifacts for evaluating the implementation of the Center for Internet Security’s (CIS) Critical Security Controls, in accordance with the CIS Controls Assessment Specification (CIS CAS). Derived directly from the CIS CAS, this list is provided to the assessment point of contact by Assessors prior to an assessment to allow sufficient time for the gathering of required artifacts.

# Scope

Agency-owned information and systems, whether on-premises, in the cloud, or administered through a managed service provider. The CIS Safeguards assessed are selected from Implementation Groups 1 and 2 of Version 8 of the CIS Controls.

# Applicability

The following requested artifacts are applicable to the CIS Version 8.0 Critical Security Controls, Implementation Group 1 (IG1), and constituent safeguards, as well as a select subset of controls and constituent safeguards from Implementation Group 2 (IG2) and Group 3 (IG3) for which there are Enterprise service offerings.

The artifacts listed below follow the guidance set forth by and applicable to the CIS CAS. The CIS CAS is intended to provide a common understanding of what should be measured to verify that CIS Safeguards are properly implemented.

## Artifact Collector

During the agency CIS Assessment, your assigned CSS Cybersecurity Assessor(s) performs a variety of information-gathering tasks, including agency interviews, artifact requests, vulnerability scanning, web application testing, and utilization of specialized tools that have been vetted by the CSS Risk Management team, such as ArtifactCollector.

### _Guidance for running ArtifactCollector in your environment._

ArtifactCollector is an internally developed, monolithic PowerShell script that collects artifacts for cybersecurity assessments using native tools.  No out-of-box PowerShell modules are required.  Author: Jason Adsit.  

Artifact Collector is hosted on GitHub. URL: https://github.com/stateoforegon-eis-css/ArtifactCollector

To run ArtifactCollector, open a PowerShell session (command line, or ISE environment) using an account with domain administrative privileges, and run the following:

```powershell
iex (New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/stateoforegon-eis-css/ArtifactCollector/refs/heads/master/ArtifactCollector.ps1')
```

or:
```powershell
iex (iwr 'https://raw.githubusercontent.com/stateoforegon-eis-css/ArtifactCollector/refs/heads/master/ArtifactCollector.ps1')
```

If the script runs successfully, it should generate an output file located the user’s Downloads folder, with the following naming convention:

[[Agency Acronym]]_Artifacts_yyyymmdd_hhmm.zip

If the script did not run successfully, please contact your assigned CSS Cybersecurity Assessor for assistance, and they'll be glad to help you.

Final Steps:

NOTE:	This output file contains Data Classification Level 3 information.

-	Do NOT simply email the output file back to your Cybersecurity Assessor!
-	Please upload the output file to the Agency Upload folder provisioned by your CSS Cybersecurity Assessor.

## Artifact Request Guidance

Requested Artifacts may be submitted in any format such as Excel documents, Word documents, Visio Drawings in PDF or PNG format, screenshots, configuration files, Text files, CSV, or PDFs detailing the configuration settings of security systems.  Assessors find it very useful when agencies provide some type of narrative along with any artifacts, however this is not required.

It is important to note that if an artifact does not contain all the required information, it should still be summitted, as it will likely still have value to the assessment.  

Each artifact request item below includes a section to indicate the artifact was provided or not, a text box to list the files provided to support the request, and a textbox to provide any additional details that would assist Assessors in reviewing the artifacts provided.

When submitting agency policies or procedures, please be sure the artifact contains a review date and authorized signature.

## Requested Artifacts

### _GV01: Detailed Hardware Asset Inventory_

Maintaining an inventory of all hardware devices on the network helps to ensure that only authorized devices are permitted access to the network, and that unauthorized and unmanaged devices are located and denied access or promptly removed from the network. The purpose of the hardware asset inventory is to serve as the authoritative, single source of truth as the baseline against which output from active and passive discovery tools can be compared to look for deltas and to be able to efficiently identify devices that are not authorized. Output from hardware inventory tools alone does not constitute an authoritative hardware inventory. Hardware inventory tools enumerate software that is in the environment. The authorized hardware inventory defines what should be in the environment. 

Additionally, the hardware inventory plays a critical role in configuration management, planning and executing system backup, incident response, and recovery.

The organization’s detailed inventory of all assets with the potential to receive, store, or process data. Data elements that the inventory should include, at a minimum:

-	Hardware (MAC) address
-	Machine name
-	Asset owner
-	Department
-	Approval to connect to the network
-	Date of last review or update to the inventory

The hardware asset inventory should include, at a minimum, the following types of devices:

-	Workstations
-	Servers
-	Laptops
-	Mobile devices (tablets, phones)
-	Assets used for remote access (VPN)
-	Assets used for administrative purposes (e.g. privileged-access workstations)
-	Discovery/Vulnerability Scanners (i.e. Tenable.sc)

### _GV03: Configuration Standards_

Configuration Standards are a set of documented controls for securely configuring systems, applications, and network devices.  Documented configuration standards will be used by assessors to validate implementation of select safeguards.
Examples of configuration standard submissions include but are not limited to: Group Policy objects (GPOs), industry standard configuration baselines (CIS Benchmarks, IRS SCSEMs, DISA STIGs, USGCB, etc.), screen shots from tools that show the appropriate configuration settings, and output from command line tools or utilities.

#### GV03.a Configuration Standards: Operating Systems & Software

Per the Information Technology (IT) Control Standards, CM-6(a), agencies must establish and document configuration settings for components employed within the system that reflect the most restrictive mode consistent with operational requirements using CIS Level 1 Benchmarks.

-	Workstations and servers
-	Browsers
-	Microsoft 365
-	Any other Industry standard configuration baselines in use 
-	Documented deviations from any industry standard configuration baselines in use
-	Date of last review and update to the documented Configuration Standards

#### GV03.b - Configuration Standards: Active Discovery Tool(s)

The CIS Controls Assessment Specification for Safeguard 1.3 – Utilize an Active Discovery Tool – requires that assessors review the configuration standard for the organization’s active discovery tool(s) to validate breadth of coverage for the tool(s) as well as to confirm that any tools in use are configured to interface with the organization’s asset inventory to make automatic updates.

-	Active discovery scan policy
-	Scan target list(s)
-	Bash script(s), if used, to automate discovery scan(s)
-	Nmap syntax, if used, for discovery scan(s)
-	MASSCAN syntax, if used, for discovery scan(s)
-	Timestamp(s) showing Active Discovery scan execution time(s)
-	Any other applicable scan configuration artifacts to validate breadth and depth of scan coverage.
-	If using Tenable to perform Asset Discovery, please provide the job names configured in Tenable for the asset discovery scans.

#### GV03.c - Configuration Standards: Encryption Software / Mechanisms for End-User Devices

CIS CAS requires agencies to Encrypt data on end-user devices containing sensitive data. Example implementations can include, Windows BitLocker®, Apple FileVault®, Linux® dm-crypt.

-	BitLocker encryption
-	Configuration standard for other encryption software in use

#### GV03.d - Configuration Standards: DNS Servers

The CIS CAS for Safeguard 4.9 requires that assessors review the organization's DNS configuration standard to validate that the organization is configuring its systems to leverage trusted DNS servers.

-	Provide a Screen shot or other artifact that shows DNS server configured forwarders have been configured to use state DNS servers.

#### GV03.e - Configuration Standards: Authorized Remote Access Assets

Provide a list of all Remote Access technologies providing network access and the configuration standard applied to those technologies.
-	Provide Configuration Standard for any Remote Access Technologies in place, such as Fortigate VPN, F5 VPN, ManageEngine Zoho assist, TeamViewer, etc.
-	We do not require a Configuration Standard for the enterprise F5/BigIP solution.  However please list if the agency uses this technology.

#### GV03.f - Configuration Standards: Automated Patch Management Software

The CIS CAS requires agencies to perform operating system updates on enterprise assets through automated patch management on a monthly, or more frequent, basis.

-	Provide Configuration Standard for any Automated Patch Management in place, such as ManageEngine, Microsoft Endpoint Configuration Manager (MECM), Solarwinds, PDQ Deploy, etc

#### GV03.g - Configuration Standards: Vulnerability Scanners / Scanning Software

The CIS CAS requires agencies to perform automated vulnerability scans of internal enterprise assets on a quarterly, or more frequent, basis. Conduct both authenticated and unauthenticated scans, using a SCAP-compliant vulnerability scanning tool.

-	Provide the Configuration Standard for Vulnerability Scanners in use at the agency.  If using Tenable, please provide the list of authenticated scan jobs configured.

#### GV03.h - Configuration Standards: MFA Mechanisms for Admin Accounts & Remote Access

CIS CAS requires agencies to maintain Configurations standards for all Multi-factor authentication (MFA) technologies in place.  The Statewide Information Technology (IT) Control Standards requires MFA for privileged accounts including local A/D administrative accounts in IA-2(1) and non-privileged accounts in IA-2(2).

-	Provide Configurations standard for all Multi-factor authentication (MFA) technologies in place
     -	For administrative accounts (all accounts including DCS and on-premise Active Directory)
     -	For remote network access
     
### _GV05: Authorized Software Inventory_

The purpose of the authorized software inventory is to serve as the authoritative, single source of truth as the baseline against which output from software discovery tools can be compared to look for deltas and to be able to efficiently identify software that is not authorized. Output from software inventory tools alone does not constitute an authoritative software inventory. Software inventory tools enumerate software that is in the environment. The authorized software inventory defines what should be in the environment.

Additionally, the software inventory helps to ensure that software running in the organizational environment is supported and receiving vendor updates, and that unnecessary software is not running on organizational devices, exposing the organization to unnecessary risk. The software inventory is also a necessary component for the organization to document and track exceptions for software that is beyond end-of-life and no longer supported but is necessary for the fulfilment of the organization’s mission and business purpose.

Detailed inventory of all licensed, and approved software installed on the organization’s assets. Data elements that the software inventory must document, at a minimum, include:

-	Software title
-	Software publisher
-	Initial use or software approval date
-	Business purpose
-	Software supported / unsupported
-	Date of last review & update

Software listed in the inventory should include, but is not limited to:

-	Authentication, Authorization, and accounting (AAA) Systems
-	Directory and SSO services
-	Authorized browsers
-	Authorized email clients
-	Authorized browser & email plugins
-	Authorized operating systems
-	Authorized anti‐malware software
-	Authorized patch management software
-	Authorized backup software
-	Authorized host‐based intrusion detection software
-	Authorized host‐based intrusion prevention software
-	802.1x authenticators
-	Application layer filtering software
-	Encryption software

### _GV10: Organization's Data Management Process_

Documented and approved process that describes how the organization ensures that data is collected, processed, stored, and disposed of in a secure and consistent manner.  This may or may not include agency information found in Oregon special records retention schedules.

The data management process must address, at a minimum:

-	Data sensitivity
-	Data ownership
-	Handling of data
-	Data retention limits
-	Disposal requirements based on data classification

### _GV12: Sensitive Data Inventory_

Documented and approved list that contains, at a minimum, all sensitive data that the organization generates, collects, or processes in pursuit of its mission and business purposes.  This may or may not include agency information found in Oregon special records retention schedules.

The organization’s inventory of sensitive information must include, at a minimum:

-	Date of last review and update to the data inventory
-	Data classification / sensitivity levels for each data set in the inventory
     -	Classification / sensitivity levels should be consistent with the organization’s data management process.
-	Applicable data retention timeframes, consistent with the organization's data management process
-	Data owner(s) for each data set in the inventory.  
-	For each data set, mapping to assets storing the data (data storage location)

### _GV18: Enterprise Assets Storing Sensitive Data_

Provide an inventory of any system, applications, or databases within the agency that processes, transmits or stores sensitive data. Sensitive Data at minimum would be data classified at Level 3 or higher

### _GV20: Unique Password Policy_

The organization’s official policy dictating the minimum password construction and complexity requirements to be employed for password creation and use.

The unique password policy must address, at a minimum:

-	Prescriptive requirements for managing default accounts (e.g. disabling, changing default passwords for, etc.)
-	Strength of mechanism requirements for accounts (i.e. complexity, password length, minimum and maximum password age, and password history).

### _GV22: Inventory of Accounts_

The purpose of the inventory of accounts is to serve as the authoritative, single source of truth as the baseline against which output from account inventory and management tools (e.g. Active Directory, PowerShell, etc.) can be compared to look for deltas and to be able to efficiently identify accounts that are not authorized, accounts that are no longer necessary, and accounts that are no longer in use. Account inventory and management tools enumerate accounts that are in the environment. The account inventory defines what should be in the environment. 

Documented inventory of all accounts authorized to access agency systems and components. 

The organization’s inventory of accounts must contain, at a minimum, all standard, service, and administrator accounts:

-	Account owner’s full name
-	Username
-	Start date
-	Stop date
-	Department
-	Date of last review and update to the inventory of accounts

Account types should include, but are not limited to:

-	Domain accounts
     -	standard user
     -	administrator 
     -	service accounts
-	Local system user and or admin accounts
-	Database accounts
-	Internal application accounts
-	External application accounts

Output from account inventory and management tools alone does not constitute an authoritative inventory of accounts.
     

### _GV24: Authorized Automated Patch Management Software_

A list of all automated patch management software that the organization uses to perform application updates on organization software. Will be a subset of GV05 – Authorized Software Inventory and GV03 – Configuration Standards.
     

### _GV25: List of Vulnerability Scanning Software_

A list of all vulnerability scanning software that the organization uses to perform automated vulnerability scans of internal and external assets. Will be a subset of GV05 – Authorized Software Inventory and GV03 – Configuration Standards.
     

### _GV26: Agency Audit Log Management Process_

Documented and approved process that defines the enterprise’s logging requirements. The audit log management process must address, at a minimum:

-	Instructions for the collection of audit logs
-	Instructions for review of audit logs
-	Instructions for retention of audit logs
-	The date of last review and update to the audit log management process

### _GV31: List of Authorized Anti‐malware Software_

A list of all anti-malware software that the organization deploys on organization assets. Will be a subset of GV05 – Authorized Software Inventory and GV03 – Configuration Standards.

### _GV43: List of workforce members_

Organization’s list of current workforce members including all staff, volunteers, vendors, partners, etc.  Agencies may want to reach out to their local Workday coordinator to assist in obtaining this list.  The list should include at a minimum:

-	Full Name
-	Position
-	Start Date
-	Employee Classification (Full and Part Time Staff, Contractors, Vendors, Volunteers, etc.)

### _GV44: Service Provider Inventory List_

Formal, approved list of all external service providers, including vendors, suppliers, contractors, cloud service providers, and other third-party partners that the organization leverages for the maintenance and operation of the information technology that it uses in the fulfilment of its mission and business purpose.

The service provider inventory list should include, at a minimum, the following information:

-	Name of service provider
-	Security classification of the service provider
-	Agency contact for the service provider
-	Service Provider contact for the agency
-	The date of last review and update to the service provider inventory list

### _GV51: Agency Incident Response Documentation_

Organization’s approved, documented incident response plan or other incident response documentation that provides direction to organization personnel for incident response and recovery efforts.
Incident response documentation should include, at a minimum, the following information:

-	Documents dedicated personnel to manage incident handling:
     -	Primary personnel
     -	Backup personnel
     -	Roles & responsibilities for primary personnel
     -	Roles & responsibilities for backup personnel
-	Contact information for reporting security incidents
-	Process for reporting security incidents
     -	Reporting timeframe
     -	Personnel to report to
     -	Mechanism for reporting
     -	Minimum information to be reported in the event of a security incident
-	Date of last review & update to the incident response documentation

### _GV54: Most recent external penetration test report for the organization_

Penetration testing is a security exercise where a cyber-security expert attempts to find and exploit vulnerabilities in a computer system. The purpose of this simulated attack is to identify any weaknesses in a system’s defenses which attackers could exploit.  Agencies may redact any information they do not wish to share with this assessment.

Penetration testing program characteristics include:

-	scope, such as network, web application, Application Programming Interface (API), hosted services, and physical premise controls;
-	frequency;
-	limitations, such as acceptable hours, and excluded attack types;
-	point of contact information;
-	remediation, such as how findings will be routed internally; and
-	retrospective requirements.

### _AD01: IP Address Management Documentation for the Organization_

IP address documentation for the organization that includes:

-	A comprehensive list of all IP addresses allocated to and managed by the organization
-	Details of any associated subnets and ranges
-	If applicable, information on whether these IP addresses are actively in use, reserved, or retired
-	Any relevant metadata (e.g. devices assignment, location, or purpose.)
-	Be sure to include both internal and external address ranges in use by the agency.

### _AD02: Agency policy documentation that defines the timeframe for removing unauthorized devices_

Approved, documented policy that defines the timeframe within which unauthorized devices must be removed from the organization’s network, or otherwise addressed, when discovered.

### _AD03: List of Active Discovery Tool(s) Used by the Organization_

A list of all active discovery tools that the organization uses to identify assets connected to its network. Will be a subset of GV05 – Authorized Software Inventory and GV03 – Configuration Standards.

### _AD04: Exception Documentation for Unsupported Software That is Necessary for the Fulfillment of the Organization's Mission_

Approved exception documentation for software that is unsupported yet necessary for the fulfillment of the organization’s mission and business purpose.  The exception documentation should document the following information:

-	Name of the unsupported software
-	Software publisher
-	Software version
-	The business need for the unsupported software
-	Initial use or software approval date
-	Name of authorizing official
-	Exception Approval date
-	Exception review date for renewal of exceptions
-	Compensating controls
-	Acceptance of residual risk
-	Date of last review & update

Exception documentation will be compared against unauthorized software discovered in the organization’s environment, to identify instances of unauthorized software for which the organization has formally documented an appropriate exception.

### _AD05: Policy Documentation That Defines the Timeframe Between Consecutive Active Software Discovery Scans_

Approved, documented policy that defines the maximum timeframe allowed between active software discovery scans for the organization.

### _AD06: List of Software Inventory Tools in use by the Organization_

A list of all software inventory tools that the organization uses to automate the discovery and documentation of installed software in its environment. Will be a subset of GV05 – Authorized Software Inventory and GV03 – Configuration Standards.

### _AD07: Process for Granting Access to Organization Assets_

Documented and approved process for granting access to organization assets. The access granting process should include, at a minimum:

-	Instructions for granting access upon new hire
-	Instructions for granting additional access for existing users or roles
-	Instructions for managing access for user role changes

### _AD08: Process for Revoking Access to Organization Assets_

Documented and approved process for revoking access to organization assets. The access revocation process should include, at a minimum:

-	Instructions for revocation of access upon termination of employment
-	Instructions for revocation of extraneous access for existing personnel or roles
-	Instructions for revocation of access upon role change of a user

### _AD09: Organization Vulnerability Management Process_

The organization’s documented and approved process for handling vulnerabilities, including, but not limited to vulnerability scanning, and patch management for both OS and third-party software. 

### _AD10: Organization Vulnerability Remediation Process_

Organization’s documented risk-based vulnerability remediation process. The risk-based procedure must go beyond vulnerability scores and include environmental factors such as prevalence of vulnerabilities, exposure of systems, sensitivity of systems, impact of exploitation, and ease of exploitation.

The organization’s vulnerability remediation strategy may be documented as part of its vulnerability management process, or in a separate process document.

### _AD11: Documented Data Recovery Process for the Organization_

Organization’s documented and approved process to scope and define critical systems for data recovery. The data recovery process must include, at a minimum:

-	Scope of data recovery activities
-	Recovery prioritization
-	Security of backup data
-	Date of last review and update of the data recovery process

### _AD12: Agency Security Awareness Training Program Plan_

Organization’s documented security awareness training program plan for educating organization personnel on how to interact with organization data and assets in a secure manger. Agencies may leverage the Statewide Information Security Plan if they do not maintain their own Awareness Training plan; however, agencies must document that they have adopted the Statewide Awareness Training Plan.

### _AD14: Security Awareness and Training metrics for the prior year_

Security Awareness and Training metrics for the prior calendar year, showing the total population of organization workers required to complete training, and the total population of workers that have completed the training.  Please be sure the report includes Name, Start Date in Position, Enrollment Status, and completion status.

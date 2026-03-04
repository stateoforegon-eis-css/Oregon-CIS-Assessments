Browser Notes: To open the any of the hyperlinks found on this page in a new tab, Ctrl+Click or right-click and select ‘Open link in new tab.’”

# Introduction

The purpose of this document is to assist the BSA team when providing post-assessment guidance to agencies on failed CIS Safeguards.  The Safeguards included in this document have a dependency on an agency documented policy, standard, procedure or process to be in place.

Each Safeguard documented contains the following elements:

- Purpose - Provides a summary of the Safeguard taken from the CIS [Controls Assessment Specification](https://controls-assessment-specification.readthedocs.io/en/stable/index.html)
- A list of policies, standards, procedures or processes the agency should have in place to meet the CIS control specifications.  CIS develops a [Policy Library](https://www.cisecurity.org/controls/policy-templates) to help organizations develop the policies required to implement the CIS controls.

## Safeguard 1.01: Establish and maintain detailed enterprise asset inventory

1.   Purpose: Establish and maintain an accurate, detailed, and up-to-date inventory of all enterprise assets with the potential to store or process data, to include: end-user devices (including portable and mobile), network devices, non-computing/IoT devices, and servers. Ensure the inventory records the network address (if static), hardware address, machine name, data asset owner, department for each asset, and whether the asset has been approved to connect to the network.
2. Policy: Establish a formal Asset Management Policy that mandates the tracking of all enterprise assets (e.g., servers, desktops, laptops, network devices, mobile devices, etc.).
3. Tool Selection: Deploy an asset management tool to automatically discover and inventory devices on the network.
4. Data Collection: Collect asset attributes to include hardware address, machine name, asset owner, department, and whether the asset is approved to connect to the network.
5. Automated Scanning: Schedule automated network scans on a daily or weekly basis to ensure up-to-date inventories.
6. Manual Entries: For offline or newly purchased devices, establish a manual asset registration process in the asset management tool.
7. Regular Audits: Perform bi-annual, or more frequent physical audits where IT staff compare automated inventories with actual devices.


## Safeguard 1.02: Address Unauthorized Assets

1.  Purpose: Prevent unauthorized devices from accessing the network and minimize potential risks. Ensure that a process exists to address unauthorized assets on a weekly basis. The enterprise may choose to remove the asset from the network, deny the asset from connecting remotely to the network, or quarantine the asset.
2. Detection Tools: Implement Detection solutions to automatically detect unauthorized devices connect to the network. 
3. Alert and Action: Configure tools to alert the security team upon detecting an unauthorized device or application and isolate the device within 1 day, until it is investigated.
4. Asset Reconciliation: Review alerts daily and cross-reference them with the authorized asset inventory to determine if the device is a legitimate asset.
5. Response Plan: If deemed unauthorized, investigate the device or application and take appropriate action (e.g., remove, disable, or escalate to security for further investigation).
6. Logging: Keep a detailed log of all unauthorized asset incidents, including remediation actions and status.
7. Reporting: Present monthly unauthorized asset incident reports to leadership.


## Safeguard 2.01: Establish and Maintain a Software Inventory

1.  Purpose: Ensure that only authorized software is used to minimize the risk of vulnerable or malicious software. 
2. Policy: Establish a Software Management Policy that mandates the use of authorized software.
3. Software Inventory Fields: Track software title, publisher, initial install/use date, and business purpose and supported/unsupported designation for each entry; where appropriate, include the Uniform Resource Locator (URL), app store(s), version(s), deployment mechanism and decommission date.
4. Manual Registration Process: For any custom software or software that’s not automatically detected, require IT administrators to manually register it in the software inventory system.
5. Audits: Perform bi-annual, or more frequent manual audits of software on critical systems to verify inventory accuracy.


## Safeguard 2.02: Ensure Authorized Software is Currently Supported 

1.  Purpose: Ensure that only currently supported software is designated as authorized in the software inventory for enterprise assets. If software is unsupported, yet necessary for the fulfillment of the enterprise’s mission, document an exception detailing mitigating controls and residual risk acceptance. For any unsupported software without an exception documentation, designate as unauthorized. Review the software list to verify software support at least monthly, or more frequently.
2. Tool Selection: Deploy a software management tool to automatically discover and inventory software installed on devices withing the agency.
3. Automated Scanning: Schedule automated scans on a regular basis to ensure up-to-date inventories. 
4. Manual Entries: For offline or non-networked systems, establish a manual software registration process in the software management tool.
5. Regular Audits: Perform monthly, or more frequent audits where staff compare automated inventories with actual software installed.


## Safeguard 2.03: Address Unauthorized Software
Purpose: Ensure that unauthorized software is either removed from use on enterprise assets or receives a documented exception.

1.  Tool Selection: Use a software asset management (SAM) tool to automate the detection of unauthorized software installed across the organization.
2. Optional Allowlist Approach: Implement an application allowlisting solution to only allow pre-approved software to execute on workstations and servers.
2. Policy Enforcement: Define a policy that prohibits the installation or execution of unauthorized software. Ensure the policy includes enforcement through automated tools.
3. Approval Process: Establish a formal approval process for adding new software to the Software Asset Inventory. Require justification, security vetting, and testing in a sandbox environment before approval.
4. Regular Review: Review and update regularly to remove outdated or unnecessary software.
5. Logging: Ensure the tools logs any attempt to execute unauthorized software and alerts the security team for follow-up investigation.


## Safeguard 2.04: Utilize Automated Software Inventory Tools

1.  Purpose: Utilize software inventory tools, when possible, throughout the enterprise to automate the discovery and documentation of installed software.
2. Tool Selection: Use a software asset management (SAM) tool to automate the detection of installed software across the organization.
3. Regular Review: Review and update the Software Asset Inventory quarterly to remove outdated or unnecessary software.


## Safeguard 3.01: Establish and Maintain a Data Management Process

1.  Purpose: Protect sensitive data and ensure proper handling based on its classification by developing processes and technical controls to identify, classify, securely handle, retain, and dispose of data.
2. Data Management Procedures: Develop Data Management Procedures, in accordance with 107-004-050, that documents Data Sensitivity, Data Owner, Handling of Data, Data Retention Limits based on Sensitivity of Data, and Disposal Requirements based on Sensitivity of Data for each data classification category.
3. Labeling and Tagging Tools: Use tools to automatically classify and label data based on predefined rules (e.g., documents containing Social Security Numbers are classified as "Level 3").
4. Access Controls: Enforce access controls based on data classification using Active Directory, role-based access control (RBAC), or equivalent tools to ensure only authorized users can access certain types of data.
5. Data Retention: Develop and implement data retention and destruction schedules aligned with compliance requirements (e.g., HIPAA, GDPR). 
6. Review and Audit: Conduct annual reviews of Data Management Procedures and perform periodic audits to verify that data is classified and handled correctly.


## Safeguard 3.02: Establish and Maintain a Data Inventory 

1.  Purpose: Establish and maintain a data inventory, based on the enterprise's data management process. Inventory sensitive data, at a minimum. Review and update inventory annually, at a minimum, with a priority on sensitive data. 
2. Data Collection: Maintain Data inventory to include mapping to sensitive data types and to assets storing sensitive data.
3. Regular Audits: Perform annual, or more frequent audits where staff compare inventories with data types in use and assets storing each data type.


## Safeguard 3.04: Enforce Data Retention

1.  Purpose: Retain data according to the enterprise's data management process. Data retention must include both minimum and maximum timelines. 
2. Data Collection: Ensure that a Portion of the Data management Process (3.1) captures both minimum and maximum retention times.


## Safeguard 3.05: Securely Dispose of Data 

1.  Purpose: Securely dispose of data when no longer needed according to the enterprise's data management process and sensitivity level. 
2. Data Collection: Ensure that a Portion of the Data management Process (3.1) captures disposal requirements for each data type recorded.


## Safeguard 3.06: Encrypt Data on End-User Devices

1.  Purpose: Encrypt data on end-user devices (e.g., laptops, mobile). 
2. Tool Selection: Implement a tool that ensures data, specifically sensitive data, is encrypted on all end user devices in use by the agency.


## Safeguard 3.07: Establish and Maintain a Data Classification Scheme

1.  Purpose: Establish and maintain an overall data classification scheme for the enterprise. Enterprises may use labels, such as “Sensitive”, “Confidential,” and “Public”, and classify their data according to those labels. Review and update the classification scheme annually, or when significant enterprise changes occur. 
2. Data Collection: Ensure a process exists to label all data owned, processed or stored by the agency, conforming to the Oregon Information Asset Classification Policy (https://www.oregon.gov/das/Policies/107-004-050.pdf).


## Safeguard 4.01: Establish and Maintain a Secure Configuration Process

1.  Purpose: Ensure that assets and software are securely configured to reduce vulnerabilities.
2. Baseline Configuration Standards: Create secure configuration baseline templates based on CIS Level 1 Benchmarks as required in the Statewide Standards (CM-6) at a minimum, DISA STIGs, or NIST standards for each asset type (e.g., workstations, servers, non-computing/IoT devices).
3. Configuration Management Tools: Use automated configuration management tools to deploy configurations across all systems.
4. Automated Enforcing and Monitoring: Leverage tools to enforce CIS Level 1 Benchmark baseline security configurations and continuously monitor deviations.
5. Regular Configuration Reviews: Schedule annual reviews of all configuration baselines to ensure they align with new security patches, emerging threats, or changes in the infrastructure.  Perform bi-annual configuration audits to verify systems are compliant with secure baseline configurations. Report non-compliance to IT leadership.


## Safeguard 4.03: Configure Automatic Device Lock 

1.  Purpose: Configure automatic session locking on enterprise assets after 15 minutes of inactivity per Statewide Standards (AC-11). For mobile end-user devices, the period must not exceed 5 minutes.
2. Policy:  Require the user to initiate a device lock before leaving the system unattended.


## Safeguard 4.04: Implement and Manage a Firewall on Servers

1.  Purpose: Implement and manage a firewall on servers, where supported. Example implementations include a virtual firewall, an operating system firewall, or a third-party firewall agent.  Ensure firewall rules and configurations are actively being managed, not accepting default settings.


## Safeguard 4.05: Implement and Manage a Firewall on End-User Devices

1.  Purpose: Implement and manage a host-based firewall or port-filtering tool on end-user devices with a default-deny rule that drops all traffic except those services and ports that are explicitly allowed.  Ensure firewall rules and configurations are actively being managed, not accepting default settings.


## Safeguard 4.07: Manage Default Accounts on Enterprise Assets and Software

1.  Purpose: Manage default accounts on enterprise assets and software, such as root, administrator, and other pre-configured vendor accounts. Example implementations can include: renaming default accounts or disabling, making them unusable.


## Safeguard 5.01: Establish and Maintain an Inventory of Accounts

1.  Purpose: Maintain visibility into all accounts and ensure only authorized accounts exist.
2. Policy: Implement an Account Management Policy that requires the creation, deletion, and modification of user accounts to be centrally controlled documenting, at minimum, person’s name, username, start/stop dates, and department.
3. Tool Selection: Use Active Directory (AD) or an Identity Governance and Administration (IGA) solution to inventory all user and service accounts.
4. Account Attributes: Persons name, username, start/stop dates and department.
5. Review Process: Conduct quarterly, or more frequent reviews of all user accounts and disable or remove any stale or unauthorized accounts.
6. Reconciliation: Compare the account inventory on a monthly basis to ensure that all employee statuses (e.g., new hire, termination, role change) are accurately reflected in the account inventory.


## Safeguard 5.02: Use unique passwords

1.  Purpose: Protect all accounts with strong authentication measures.
2. Password Policy: Enforce a password policy incorporating the requirements in CSS Statewide Information Technology Control Standards, IA-5(1) Authenticator Management | Password-Based Authentication.


## Safeguard 5.03: Disable Dormant Accounts

1.  Purpose: Minimize risk by disabling accounts that are no longer in use.
2. Detection and Monitoring: Use a tool or an IAM solution to monitor accounts for inactivity.
3. Threshold Setting: Define a dormancy (inactivity) threshold incorporating but not detracting from the requirements in CSS Statewide Information Technology Control Standards, AC-2(3) Account Management | Disable Accounts.
4. Alerting: Define automated alerts that notify system administrators when an account exceeds the dormancy threshold.
5. Action: Automatically disable accounts flagged as dormant or manually withing 24 hours when the account :
a. Has expired; 
b. Is no longer associated with a user or individual; 
c. Is in violation of organizational policy; or 
d. Has been inactive for ninety (90) days


## Safeguard 5.04: Restrict Administrative Privileges to Dedicated Administrative Accounts

1.  Purpose: Ensure that administrative privileges are only granted to accounts designated for administrative use, minimizing exposure.
2. Account Creation: Establish separate accounts for administrative and non-administrative tasks. For example, create one account for day-to-day activities and another for privileged actions.
3. Access Controls: Enforce the principle of least privilege (POLP) for administrative accounts. Ensure that they only have the necessary permissions to perform their tasks.
4. MFA Enforcement: Apply multi-factor authentication (MFA) to all administrative accounts.


## Safeguard 6.01: Establish an Access Granting Process

1.  Purpose: Establish a process, preferably automated, for granting access to enterprise assets upon new hire, rights grant, or role change of a user. Control access to systems and data based on need-to-know and job roles.
2. Process: Maintain an Access Granting Process for granting access to enterprise assets outlining that access must be granted based on business need, with mandatory approval for any access modification.
3. Access Reviews: Conduct annual access reviews for systems to ensure access levels are appropriate and revoke access where necessary in alignment with CSS Statewide Information Technology Control Standards, AC-6(7) Least Privilege | Review of User Privileges.
4. Logging: Ensure that all access requests, approvals, and modifications are logged and stored for at least one year for audit purposes.


## Safeguard 6.02: Establish an Access Revoking Process

1.  Purpose: Establish a process, preferably automated, for revoking access to enterprise assets upon termination, rights revocation, or role change of a user. Control access to systems and data based on need-to-know and job roles.
2. Process: Maintain an Access Revoking Process for revoking access to enterprise assets, with mandatory approval for any access modification.
3. Access Reviews: Conduct annual access reviews for systems to ensure access levels are appropriate and revoke access where necessary in alignment with CSS Statewide Information Technology Control Standards, AC-6(7) Least Privilege | Review of User Privileges.
4. Logging: Ensure that all access revocations are logged and stored for at least one year for audit purposes.


## Safeguard 6.04: Require Multifactor Authentication for Remote Network Access

1.  Purpose: Protect remote access by requiring multifactor authentication (MFA), thus preventing unauthorized access.
2. Policy: Maintain a Remote Access Policy to mandate MFA for all users accessing the network remotely.
3. MFA Tools: Deploy an MFA solution, integrated with VPN or remote access tools.
4. Implementation and Testing: Enable MFA for all VPN connections, RDP sessions, and cloud services (e.g., AWS, Azure) accessed remotely.
5. User Training: Train users on the MFA process and provide step-by-step guidance on setting up MFA, including recovery processes for lost devices.
6. Auditing and Logging: Log all remote access attempts and any MFA failures to identify and mitigate potential threats.


## Safeguard 6.05: Require Multifactor Authentication for Administrative Access

1.  Purpose: Require MFA for all administrative access accounts, where supported, on all enterprise assets, whether managed on-site or through a third-party provider.
2. Policy: Maintain a formal policy requiring MFA for administrative accounts at all access points (local, remote, and cloud environments).
3. Process: Develop a process for enrolling users into the MFA system. This process should include user verification and technical support for setup.
4. Tool Selection: Use a tool to enforce multifactor authentication for all administrative accounts.
5. Emergency Access: Establish a secure emergency access procedure that requires approval from senior management and logs every bypass of MFA.


## Safeguard 7.01: Establish and Maintain a Vulnerability Management Process

1.  Purpose: Identify, prioritize, and remediate vulnerabilities in systems to reduce security risks. 

2. Process: Establish Vulnerability Management Processes defining the steps for identifying, assessing, and mitigating vulnerabilities.  
3. Review: Review and update the Vulnerability Management Process annually, or when significant enterprise changes occur.


## Safeguard 7.02: Establish and Maintain a Remediation Process

1.  Purpose: Ensure that identified vulnerabilities are mitigated or remediated in a timely manner.
2. Process: Ensure the Remediation Process addresses the sensitivity and criticality of assets.  The process should require vulnerabilities are reviewed at least monthly.
3. Patch Prioritization: Prioritize patch deployment based on asset sensitivity and the vulnerability criticality as determined by scanning tools.
4. Verification: After patch deployment, verify that the vulnerability is remediated by running follow-up vulnerability scans.
5. Emergency Patch Process: Establish an emergency patching process that triggers immediate deployment for critical vulnerabilities, bypassing normal scheduling.
6. Review and Documentation: Maintain documentation for all patches applied, including version, date, and systems patched, and review these regularly in security meetings.


## Safeguard 7.03: Perform Automated Operating System Patch Management

1.  Purpose: Ensure that operating system vulnerabilities are identified and automatically patched promptly to minimize the risk of exploitation.
2. Process: Ensure Vulnerability Management Process (7.1) requires patch management software to run at least monthly.
3. Automated Tools: Use tools for automated patch management on operating systems.
4. Patch Scheduling: Schedule automatic Operating System patch scans on all systems and ensure patches are automatically applied monthly, or more frequent basis
5. Patch Exceptions: If a patch cannot be applied, document the exception, implement compensating controls (e.g., network segmentation), and re-assess quarterly.
6. Review and Reporting: Review Patch Management Processes monthly to ensure automated patch management software is properly configured.  


## Safeguard 7.04: Perform Automated Application Patch Management

1.  Purpose: Regularly update applications to reduce the risk of exploitation from known vulnerabilities.
2. Policy: Implement a formal Patch Management Policy requiring regular application updates, at least monthly.
3. Automated Tools: Use tools for automated patch management on applications.
4. Patch Scheduling: Schedule automatic application patch scans on all systems and ensure patches are automatically applied monthly, or more frequent basis
5. Patch Exceptions: If a patch cannot be applied, document the exception, implement compensating controls (e.g., network segmentation), and re-assess quarterly.
6. Review and Reporting: Review Patch Management Processes monthly to ensure automated patch management software is properly configured.  


## Safeguard 7.05: Perform Automated Vulnerability Scans of Internal Enterprise Assets

1.  Purpose: Identify vulnerabilities within the internal network to prevent exploitation.
2. Scanning Tools: Deploy SCAP-compliant automated vulnerability scanning tools to perform internal scans.
3. Scanning Schedule: Schedule monthly, or more frequent scans of all internal systems, including workstations, servers, and network devices.
4. Validation: After remediation, rescan systems to ensure vulnerabilities are resolved.


## Safeguard 7.06: Perform Automated Vulnerability Scans of Externally Exposed Enterprise Assets

1.  Purpose: Regularly scan externally exposed systems to detect and remediate vulnerabilities that attackers could exploit.
2. Scanning Tools: Deploy SCAP-compliant automated vulnerability scanning tools to scan all externally facing systems.
3. Scanning Schedule: Schedule monthly, or more frequent scans of all external systems.


## Safeguard 8.01: Establish and Maintain an Audit Log Management Process

1.  Purpose: Ensure critical systems generate and store audit logs to detect and investigate security incidents.
2. Policy: Develop an Audit Log Management Policy detailing what logs should be collected, where they are stored, how and when they are reviewed, and how long they should be retained.  Ensure process addresses collection, review and retention of audible events.  This process should be reviewed annualy.
3. Audits: Perform annual audits of log retention, reviewing whether log policies are followed and access is appropriately controlled.


## Safeguard 8.02: Collect Audit Logs

1.  Purpose: Ensure all relevant security and operational activities are recorded in audit logs for forensic and monitoring purposes.
2. Log Sources: Identify key log sources, including servers, firewalls, VPN, Active Directory, endpoint protection systems, and critical applications.  For example, Windows Firewall: Domain, Private and Public profiles should have logging enabled to separate log destinations.
3. Real-Time Monitoring: Use SIEM systems to monitor logs in real time for suspicious activities.  


## Safeguard 8.03: Ensure Adequate Audit Log Storage

1.  Purpose: Ensure that logging destinations maintain adequate storage to comply with the enterprise’s audit log management process. 
2. Storage Capacity Planning: Allocate audit log storage capacity to accommodate State of Oregon records retention schedules and any other applicable retention requirements. CSS Statewide Information Technology Control Standards, AU-4 Audit Storage Capacity.


## Safeguard 8.04: Standardize Time Across Systems

1.  Purpose: Ensure consistent timestamps across systems for accurate correlation and investigation of security incidents.
2. NTP Configuration: Synchronize all systems with a trusted Network Time Protocol (NTP) server (ntp.state.or.us) to standardize timestamps.
3. Monitoring: Use monitoring tools to detect systems that have drifted from the correct time.
4. Policy: Define a time-synchronization policy that mandates the use of the organization’s NTP servers for all systems.


## Safeguard 8.05: Collect Detailed Audit Logs 

1.  Purpose: Collect, alert, and retain logs from additional sources (e.g., network infrastructure). 
2. Logging: Expected Elements: event source, date, username, timestamp, source addresses, and destination addresses.


## Safeguard 8.09: Centralize Audit Logs

1.  Purpose: Centralize log collection and analysis (e.g., via SIEM). 


## Safeguard 8.10: Retain Audit Logs 

1.  Purpose: Retain audit logs per enterprise policy and legal requirements. 
2. Process: Audit Log Management Process should ensure the retention of Audit Logs for at least 90 days or more.


## Safeguard 8.11: Conduct Audit Log Reviews

1.  Purpose: Generate and respond to alerts from audit log analysis. 
2. Process: Audit Log Management Process should ensure the Review of Audit Logs occurs at least weekly.


## Safeguard 9.01: Ensure Use of Only Fully Supported Browsers and Email Clients

1.  Purpose: Ensure only fully supported browsers and email clients are allowed to execute in the enterprise, only using the latest version of browsers and email clients provided through the vendor.
2. Supported Software List: Maintain a list of fully supported browsers and email clients (e.g., Google Chrome, Mozilla Firefox, Microsoft Edge, Microsoft Outlook).  Ensure this list documents product supported/unsupported designation.
3. Enforcement: Use endpoint management tools to enforce the use of supported software and block unsupported versions.
4. Patching: Ensure that browsers and email clients are patched automatically or manually as soon as new updates are available.


## Safeguard 9.02: Use DNS Filtering Services

1.  Purpose: Use DNS filtering services on all enterprise assets to block access to known malicious domains.
2. DNS Filtering Solution: Ensure DNS filtering services, managed by the State of Oregon EIS are used for DNS filtering (Enterprise “cat” DNS servers) across the organization.
3. Configuration: Ensure all devices are configured to use the organization’s DNS filtering solution, including corporate devices used remotely.


## Safeguard 10.01: Deploy and Maintain Anti-Malware Software

1.  Purpose: Protect all enterprise assets from malware infections through effective anti-malware solutions.
2. Anti-malware Solution: Deploy industry-standard anti-malware solutions across all endpoints.
3. Real-time Protection: Enable real-time scanning features to continuously monitor for malware activity.


## Safeguard 10.02: Configure Automatic Anti-Malware Signature Updates

1.  Purpose: Confirm that all endpoints protected by active anti-malware solutions are automatically updated.
2. Asset Inventory: Maintain an up-to-date inventory of all endpoints, ensuring they have anti-malware software installed.
3. Updating: Use automated tools to automatically update anti-malware solution and signatures.


## Safeguard 10.03: Disable Autorun and Autoplay for Removable Media

1.  Purpose: Disable autorun and autoplay auto-execute functionality for removable media.
2. Process: Ensure an automated process exists to disable MTP Autoplay, Autoplay on all drives, and Autorun for all systems.


## Safeguard 11.01: Establish and Maintain a Data Recovery Process
Purpose: Ensure the ability to recover critical data after a loss event.

1.  Process: Develop a Data Recovery Process defining the processes and responsibilities for data recovery operations.  Ensure Process addresses scope of data recovery activities, recovery prioritization and the security of backups.
2. Data Classification: Classify data based on importance and sensitivity to prioritize recovery efforts.
3. Backup Frequency: Establish a regular backup schedule (e.g., daily, weekly) to backup necessary agency data.
4. Security of Backups: Ensure backups are securely stored (e.g. offsite or in a secure cloud).
5. Documentation: Maintain detailed documentation of the data recovery process, including recovery time objectives (RTO) and recovery point objectives (RPO).
6. Updates: Review the data recovery process annually, or as significant changes occur.


## Safeguard 11.02: Perform Automated Backups 

1.  Purpose: Perform automated backups of in-scope enterprise assets. 


## Safeguard 11.03: Protect Recovery Data

1.  Purpose: Protect backups from unauthorized access and tampering.  This is typically done by implementing encryption.


## Safeguard 11.04: Establish and Maintain an Isolated Instance of Recovery Data

1.  Purpose: Establish and maintain an isolated instance of recovery data. Example implementations include, version-controlling backup destinations through offline, cloud, or off-site systems or services.


## Safeguard 13.01: Centralize Security Event Alerting

1.  Purpose: Centralize security event alerting across enterprise assets for log correlation and analysis. Best practice implementation requires the use of an SIEM, which includes vendor-defined event correlation alerts. A log analytics platform configured with security-relevant correlation alerts also satisfies this requirement.


## Safeguard 13.07: Deploy a Host-Based Intrusion Prevention Solution

1.  Purpose: Deploy a host-based intrusion prevention solution on enterprise assets, where appropriate and/or supported. Example implementations include the use of an Endpoint Detection and Response (EDR) client or host-based IPS agent.


## Safeguard 14.01: Establish a Security Awareness Program

1.  Purpose: Educate the enterprise’s workforce on how to interact with enterprise assets and data in a secure manner.
2. Program Development: Create a Security Awareness Program that outlines training objectives, topics, and delivery methods (e.g., e-learning, workshops).
3. Regular Training Schedule: Schedule mandatory annual training sessions for employees, including onboarding for new hires.
4. Documentation: Maintain records of training completion and regularly review content to ensure relevance and effectiveness.
5. Review: Review Security Awareness Program annually, or when significant changes occur.


## Safeguard 15.01: Establish and Maintain a Service Provider Management Process 

1.  Purpose: Establish and maintain an inventory of service providers. The inventory is to list all known service providers, including classification(s), and designate an enterprise contact for each service provider. Review and update the inventory annually, or when significant enterprise changes occur.
2. Data Collection: Ensure the inventory includes the following components: service provider name, classification of service provider, and an enterprise contact for the provider.


## Safeguard 17.01: Designate Personnel to Manage Incident Handling 

1.  Purpose: Develop and maintain an incident response plan to effectively handle security incidents.
2. Incident Response Policy: Create an Incident Response Policy detailing the framework for responding to security incidents.
3. Incident Response Team: Establish a dedicated incident response team with defined roles and responsibilities, designating one key person, and at least one backup, who will manage the enterprise’s incident handling process.


## Safeguard 17.02: Establish and Maintain Contact Information for Reporting Security Incidents 

1.  Purpose: Outline specific steps for responding to different types of incidents.
2. Incident Response Policy: Ensure the detailed Incident Response Policy includes procedures for detection, containment, eradication, and recovery.
3. Communication Protocols: Define communication protocols for internal and external stakeholders during an incident.
4. Response Templates: Create templates for incident reports, allowing for consistent documentation of incidents.
5. Plan Review: Review and update the incident response plan annually or after significant incidents.


## Safeguard 17.03: Establish and Maintain an Enterprise Process for Reporting Incidents

1.  Purpose: Establish and maintain an enterprise process for the workforce to report security incidents. The process includes reporting timeframe, personnel to report to, mechanism for reporting, and the minimum information to be reported. Ensure the process is publicly available to all of the workforce. Review annually, or when significant enterprise changes occur.
2. Data collection: Ensure the process captures the following components: reporting timeframe, personnel to report to, mechanism for reporting, minimum information to be reported.


## Safeguard 18.02: Perform Periodic External Penetration Tests

1.  Purpose: Perform periodic external penetration tests based on program requirements, no less than annually. External penetration testing must include enterprise and environmental reconnaissance to detect exploitable information. Penetration testing requires specialized skills and experience and must be conducted through a qualified party. The testing may be in a clear box or an opaque box.

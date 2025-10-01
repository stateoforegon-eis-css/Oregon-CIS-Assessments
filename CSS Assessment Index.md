# Purpose

This document serves as a high-level index of the CIS Safeguards included in the CSS Cybersecurity Assessment Team "IG1+" review baseline with brief explanations of how each included Safeguard aligns to the _2023 Satatewide Information Technology Control Standards_ and, where applicable, ratonale for included "IG2" and "IG3" Safeguards.  Included under each Safeguard are links to the relevant items from the Artifact Request, Internal Testing, and Methodology.

## Safeguard 1.01	(IG1)	Establish and Maintain Detailed Enterprise Asset Inventory

The implementation of Safeguard 1.01 is a critical element in the defensive mitigations for _2023 Statewide Information Technology Control Standard_ CM-8(1); and contributes to the defensive mitigation for _Standards_ CM-8 and PM-5.

**Assessed Elements:**

- [GV01: Detailed Hardware Asset Inventory](https://github.com/stateoforegon-eis-css/Oregon-CIS-Assessments/blob/main/IG1%2B%20Artifact%20Request.md#gv01-detailed-hardware-asset-inventory)
- Hardware Assets discovered during Internal Testing
  - [Powershell Script to enumerate Hardware Assets from Artifact Collector](https://github.com/stateoforegon-eis-css/Oregon-CIS-Assessments/blob/main/IG1%2B%20Artifact%20Collector.md#cis-control-1-inventory-and-control-of-enterprise-assets)
  - [KQL Script to enumerate Hardware Assets using Advanced Hunting in Defender](https://github.com/stateoforegon-eis-css/Oregon-CIS-Assessments/blob/main/IG1%2B%20Defender%20KQL.md#cis-control-1-inventory-and-control-of-enterprise-assets)
  - Both [Defender](https://security.microsoft.com/machines) and [Tenable](https://cloud.tenable.com/tio/app.html#/assets-uw/all-assets/) have a pre-built report to list Agency Hardware Assets

**Assessment Methodology**

- [CIS Controls Assessment Specification for CIS Safeguard 1.01](https://cas8.docs.cisecurity.org/en/latest/source/Controls1/#11-establish-and-maintain-detailed-enterprise-asset-inventory)
- Evaluate elements in Artifact GV01 and compare authorized assets to discovered assets

## Safeguard 1.02	(IG1)	Address Unauthorized Assets

The implementation of Safeguard 1.02 contributes to the defensive mitigation for _2023 Statewide Information Technology Control Standard_ CM-8(3).

**Assessed Elements:**

- [AD02: Agency policy documentation that defines the timeframe for removing unauthorized devices](https://github.com/stateoforegon-eis-css/Oregon-CIS-Assessments/blob/main/IG1%2B%20Artifact%20Request.md#ad02-agency-policy-documentation-that-defines-the-timeframe-for-removing-unauthorized-devices)
- Hardware Assets discovered during Internal Testing (See Safeguard 1.01)
  - [Powershell Script to enumerate Hardware Assets from Artifact Collector with a "First Seen" date exceeding enterprise time frame](https://github.com/stateoforegon-eis-css/Oregon-CIS-Assessments/blob/main/IG1%2B%20Artifact%20Collector.md#safeguard-12-address-unauthorized-assets)

**Assessment Methodology**

- [CIS Controls Assessment Specification for CIS Safeguard 1.02](https://cas8.docs.cisecurity.org/en/latest/source/Controls1/#12-address-unauthorized-assets)
- Evaluate discovered Hardware Assets for those not included in Agency's Detailed Hardware Asset Inventory with a "First Seen" date exceeding enterprise time frame to remove unauthorized assets.

## Safeguard 2.01	(IG1)	Establish and Maintain a Software Inventory

The implementation of Safeguard 2.01 is a critical element in the defensive mitigations for _2023 Statewide Information Technology Control Standard_ MA-3; and contributes to the defensive mitigation for _Standards_ CM-7(1) and CM-8.

**Assessed Elements:**

- [GV05: Authorized Software Inventory](https://github.com/stateoforegon-eis-css/Oregon-CIS-Assessments/blob/main/IG1%2B%20Artifact%20Request.md#gv05-authorized-software-inventory)

**Assessment Methodology**

- [CIS Controls Assessment Specification for CIS Safeguard 2.01](https://cas8.docs.cisecurity.org/en/latest/source/Controls2/#21-establish-and-maintain-a-software-inventory)
- Evaluate Authorized Software Inventory for the presence of required elements.

## Safeguard 2.02	(IG1)	Ensure Authorized Software is Currently Supported 

The implementation of Safeguard 2.02 is operationally equivalent to the defensive mitigation for _2023 Statewide Information Technology Control Standard_ SA-22.

**Assessed Elements:**

- [GV05: Authorized Software Inventory](https://github.com/stateoforegon-eis-css/Oregon-CIS-Assessments/blob/main/IG1%2B%20Artifact%20Request.md#gv05-authorized-software-inventory)
- [AD04: Exception Documentation for Unsupported Software That is Necessary for the Fulfillment of the Organization's Mission](https://github.com/stateoforegon-eis-css/Oregon-CIS-Assessments/blob/main/IG1%2B%20Artifact%20Request.md#ad04-exception-documentation-for-unsupported-software-that-is-necessary-for-the-fulfillment-of-the-organizations-mission)
- Software Assets discovered during Internal Testing
  - [KQL Script to enumerate Unsupported Software using Advanced Hunting in Defender](https://github.com/stateoforegon-eis-css/Oregon-CIS-Assessments/blob/main/IG1%2B%20Defender%20KQL.md#safeguard-22-ensure-authorized-software-is-currently-supported)

**Assessment Methodology**

- [CIS Controls Assessment Specification for CIS Safeguard 2.02](https://cas8.docs.cisecurity.org/en/latest/source/Controls2/#22-ensure-authorized-software-is-currently-supported)
- Evaluate Agency's Authorized Software Inventory for the proper labeling of "unsupported" software through a comparison with discovered software.

## Safeguard 2.03	(IG1)	Address Unauthorized Software

The implementation of Safeguard 2.03 contributes to the defensive mitigation for _2023 Statewide Information Technology Control Standards_ CM-7(2), CM-8(3), CM-10, and CM-11.

**Assessed Elements:**

- [AD02: Agency policy documentation that defines the timeframe for removing unauthorized devices](https://github.com/stateoforegon-eis-css/Oregon-CIS-Assessments/blob/main/IG1%2B%20Artifact%20Request.md#ad02-agency-policy-documentation-that-defines-the-timeframe-for-removing-unauthorized-devices)
- Software Assets discovered during Internal Testing
  - [KQL Script to enumerate all Software using Advanced Hunting in Defender](https://github.com/stateoforegon-eis-css/Oregon-CIS-Assessments/blob/main/IG1%2B%20Defender%20KQL.md#safeguard-23-software-present-on-enterprise-assets)

**Assessment Methodology**

- [CIS Controls Assessment Specification for CIS Safeguard 2.03](https://cas8.docs.cisecurity.org/en/latest/source/Controls2/#23-address-unauthorized-software)
- 

## Safeguard 2.04	**_(IG2)_**	Utilize Automated Software Inventory Tools

_Included in the Assessment as Enterprise Solutions (Tenable/Defender) enable subscribers to automate software discovery._

The implementation of Safeguard 2.04 contributes to the defensive mitigation for _2023 Statewide Information Technology Control Standard_ CM-8(3).

**Assessed Elements:**

- [GV01: Detailed Hardware Asset Inventory](https://github.com/stateoforegon-eis-css/Oregon-CIS-Assessments/blob/main/IG1%2B%20Artifact%20Request.md#gv01-detailed-hardware-asset-inventory)
- [AD05: Policy Documentation That Defines the Timeframe Between Consecutive Active Software Discovery Scans](https://github.com/stateoforegon-eis-css/Oregon-CIS-Assessments/blob/main/IG1%2B%20Artifact%20Request.md#ad05-policy-documentation-that-defines-the-timeframe-between-consecutive-active-software-discovery-scans)
- [AD06: List of Software Inventory Tools in use by the Organization](https://github.com/stateoforegon-eis-css/Oregon-CIS-Assessments/blob/main/IG1%2B%20Artifact%20Request.md#ad06-list-of-software-inventory-tools-in-use-by-the-organization)
- Visibility of Hardware Assets in Software Inventory Tools observed during Internal Testing
  - See Safeguard 1.01

**Assessment Methodology**

- [CIS Controls Assessment Specification for CIS Safeguard 2.04](https://cas8.docs.cisecurity.org/en/latest/source/Controls2/#24-utilize-automated-software-inventory-tools)
- 

## Safeguard 3.01	(IG1)	Establish and Maintain a Data Management Process

The implementation of Safeguard 3.01 is operationally equivalent to the defensive mitigation for _2023 Statewide Information Technology Control Standard_ SI-12; a critical element in the defensive mitigations for _Standard_ AU-11; and contributes to the defensive mitigation for _Standard_ CM-12.

**Assessed Elements:**

- [GV10: Organization's Data Management Process](https://github.com/stateoforegon-eis-css/Oregon-CIS-Assessments/blob/main/IG1%2B%20Artifact%20Request.md#gv10-organizations-data-management-process)

**Assessment Methodology**

- [CIS Controls Assessment Specification for CIS Safeguard 3.01](https://cas8.docs.cisecurity.org/en/latest/source/Controls3/#31-establish-and-maintain-a-data-management-process)
- 

## Safeguard 3.02	(IG1)	Establish and Maintain a Data Inventory

The implementation of Safeguard 3.02 is a critical element in the defensive mitigations for _2023 Statewide Information Technology Control Standards_ CM-12 and PM-5(1); and contributes to the defensive mitigation for _Standard_ RA-2.

**Assessed Elements:**

- [GV10: Organization's Data Management Process](https://github.com/stateoforegon-eis-css/Oregon-CIS-Assessments/blob/main/IG1%2B%20Artifact%20Request.md#gv10-organizations-data-management-process)
- [GV01: Detailed Hardware Asset Inventory](https://github.com/stateoforegon-eis-css/Oregon-CIS-Assessments/blob/main/IG1%2B%20Artifact%20Request.md#gv01-detailed-hardware-asset-inventory) - specifically those storing sensitive data

**Assessment Methodology**

- [CIS Controls Assessment Specification for CIS Safeguard 3.02](https://cas8.docs.cisecurity.org/en/latest/source/Controls3/#32-establish-and-maintain-a-data-inventory)
- 

## Safeguard 3.04	(IG1)	Enforce Data Retention

The implementation of Safeguard 3.04 contributes to the defensive mitigation for _2023 Statewide Information Technology Control Standards_ AU-11 and SI-12.

**Assessed Elements:**

- [GV10: Organization's Data Management Process](https://github.com/stateoforegon-eis-css/Oregon-CIS-Assessments/blob/main/IG1%2B%20Artifact%20Request.md#gv10-organizations-data-management-process)
- [GV12: Sensitive Data Inventory](https://github.com/stateoforegon-eis-css/Oregon-CIS-Assessments/blob/main/IG1%2B%20Artifact%20Request.md#gv12-sensitive-data-inventory)

**Assessment Methodology**

- [CIS Controls Assessment Specification for CIS Safeguard 3.04](https://cas8.docs.cisecurity.org/en/latest/source/Controls3/#34-enforce-data-retention)
- 

## Safeguard 3.05	(IG1)	Securely Dispose of Data

The implementation of Safeguard 3.05 contributes to the defensive mitigation for _2023 Statewide Information Technology Control Standards_ MP-6 and SR-12.

**Assessed Elements:**

- [GV10: Organization's Data Management Process](https://github.com/stateoforegon-eis-css/Oregon-CIS-Assessments/blob/main/IG1%2B%20Artifact%20Request.md#gv10-organizations-data-management-process)
- [GV12: Sensitive Data Inventory](https://github.com/stateoforegon-eis-css/Oregon-CIS-Assessments/blob/main/IG1%2B%20Artifact%20Request.md#gv12-sensitive-data-inventory)

**Assessment Methodology**

- [CIS Controls Assessment Specification for CIS Safeguard 3.05](https://cas8.docs.cisecurity.org/en/latest/source/Controls3/#35-securely-dispose-of-data)
- 

## Safeguard 3.06	(IG1)	Encrypt Data on End-User Devices

The implementation of Safeguard 3.06 contributes to the defensive mitigation for _2023 Statewide Information Technology Control Standard_ SC-28.

**Assessed Elements:**

- [GV01: Detailed Hardware Asset Inventory](https://github.com/stateoforegon-eis-css/Oregon-CIS-Assessments/blob/main/IG1%2B%20Artifact%20Request.md#gv01-detailed-hardware-asset-inventory)
- Encryption settings observed during Internal Testing
  - [KQL Script to evaluate BitLocker deployment on each system using Advanced Hunting in Defender](https://github.com/stateoforegon-eis-css/Oregon-CIS-Assessments/blob/main/IG1%2B%20Defender%20KQL.md#safeguard-36-encrypt-data-on-end-user-devices)

**Assessment Methodology**

- [CIS Controls Assessment Specification for CIS Safeguard 3.06](https://cas8.docs.cisecurity.org/en/latest/source/Controls3/#36-encrypt-data-on-end-user-devices)
- 

## Safeguard 3.07	**_(IG2)_**	Establish and Maintain a Data Classification Scheme

_Included in the Assessment in accordance with Statewide Policy 107-004-050._

The implementation of Safeguard 3.07 contributes to the defensive mitigation for _2023 Statewide Information Technology Control Standard_ RA-2.

**Assessed Elements:**

- [GV10: Organization's Data Management Process](https://github.com/stateoforegon-eis-css/Oregon-CIS-Assessments/blob/main/IG1%2B%20Artifact%20Request.md#gv10-organizations-data-management-process) - Specifically the Data Classification Scheme
- [GV12: Sensitive Data Inventory](https://github.com/stateoforegon-eis-css/Oregon-CIS-Assessments/blob/main/IG1%2B%20Artifact%20Request.md#gv12-sensitive-data-inventory)

**Assessment Methodology**

- [CIS Controls Assessment Specification for CIS Safeguard 3.07](https://cas8.docs.cisecurity.org/en/latest/source/Controls3/#37-establish-and-maintain-a-data-classification-scheme)
- 

## Safeguard 4.01	(IG1)	Establish and Maintain a Secure Configuration Process

The implementation of Safeguard 4.01 is operationally equivalent to the defensive mitigation for _2023 Statewide Information Technology Control Standards_ CM-1 and CM-9; a critical element in the defensive mitigations for _Standards_ CM-2, CM-6, CM-7(1), SA-3, SA-8, and SA-10; and contributes to the defensive mitigation for _Standard_ CM-7.

**Assessed Elements:**

- [GV05: Authorized Software Inventory](https://github.com/stateoforegon-eis-css/Oregon-CIS-Assessments/blob/main/IG1%2B%20Artifact%20Request.md#gv05-authorized-software-inventory)
- [GV03.a Configuration Standards: Operating Systems & Software](https://github.com/stateoforegon-eis-css/Oregon-CIS-Assessments/blob/main/IG1%2B%20Artifact%20Request.md#gv03a-configuration-standards-operating-systems--software)

**Assessment Methodology**

- [CIS Controls Assessment Specification for CIS Safeguard 4.01](https://cas8.docs.cisecurity.org/en/latest/source/Controls4/#41-establish-and-maintain-a-secure-configuration-process)
- 

## Safeguard 4.03	(IG1)	Configure Automatic Session Locking on Enterprise Assets

The implementation of Safeguard 4.03 is operationally equivalent to the defensive mitigation for _2023 Statewide Information Technology Control Standard_ AC-11; a critical element in the defensive mitigations for _Standards_ AC-18, AC-18(1), AC-18(3), CM-2, and CM-6; and contributes to the defensive mitigation for _Standards_ CM-7 and CM-7(1).

**Assessed Elements:**

- Hardware Assets discovered during Internal Testing (See Safeguard 1.01)
- Session Locking settings observed during Internal Testing
  - [KQL Script to evaluate Automatic Session Locking on each system using Advanced Hunting in Defender](https://github.com/stateoforegon-eis-css/Oregon-CIS-Assessments/blob/main/IG1%2B%20Defender%20KQL.md#safeguard-43-configure-automatic-session-locking-on-enterprise-assets)
  - [Group Policy Objects evaluated](https://github.com/stateoforegon-eis-css/Oregon-CIS-Assessments/blob/main/IG1%2B%20Group%20Policy%20Settings.md#benchmark-group-policy-settings-for-safeguard-403)

**Assessment Methodology**

- [CIS Controls Assessment Specification for CIS Safeguard 4.03](https://cas8.docs.cisecurity.org/en/latest/source/Controls4/#43-configure-automatic-session-locking-on-enterprise-assets)
- 

## Safeguard 4.04	(IG1)	Implement and Manage a Firewall on Servers

The implementation of Safeguard 4.04 contributes to the defensive mitigation for _2023 Statewide Information Technology Control Standards_ CA-9, SC-7, and SC-7(5).

**Assessed Elements:**

- Hardware Assets discovered during Internal Testing (See Safeguard 1.01)
- Firewall settings observed during Internal Testing
  - [KQL Script to evaluate the FIrewall status for each server using Advanced Hunting in Defender](https://github.com/stateoforegon-eis-css/Oregon-CIS-Assessments/blob/main/IG1%2B%20Defender%20KQL.md#safeguard-44-implement-and-manage-a-firewall-on-servers)

**Assessment Methodology**

- [CIS Controls Assessment Specification for CIS Safeguard 4.04](https://cas8.docs.cisecurity.org/en/latest/source/Controls4/#44-implement-and-manage-a-firewall-on-servers)
- 

## Safeguard 4.05	(IG1)	Implement and Manage a Firewall on End-User Devices

The implementation of Safeguard 4.05 contributes to the defensive mitigation for _2023 Statewide Information Technology Control Standards_ SC-7 and SC-7(5).

**Assessed Elements:**

- Hardware Assets discovered during Internal Testing (See Safeguard 1.01)
- Firewall settings observed during Internal Testing
  - [KQL Script to evaluate the Firewall status for each endpoint using Advanced Hunting in Defender](https://github.com/stateoforegon-eis-css/Oregon-CIS-Assessments/blob/main/IG1%2B%20Defender%20KQL.md#safeguard-45-implement-and-manage-a-firewall-on-end-user-devices)
  - [Group Policy Objects evaluated](https://github.com/stateoforegon-eis-css/Oregon-CIS-Assessments/blob/main/IG1%2B%20Group%20Policy%20Settings.md#benchmark-group-policy-settings-for-safeguard-405)

**Assessment Methodology**

- [CIS Controls Assessment Specification for CIS Safeguard 4.05](https://cas8.docs.cisecurity.org/en/latest/source/Controls4/#45-implement-and-manage-a-firewall-on-end-user-devices)
- 

## Safeguard 4.07	(IG1)	Manage Default Accounts on Enterprise Assets and Software

The implementation of Safeguard 4.07 contributes to the defensive mitigation for _2023 Statewide Information Technology Control Standard_ IA-5.

**Assessed Elements:**

- Hardware Assets discovered during Internal Testing (See Safeguard 1.01)
- Default Account and Group Policy settings observed during Internal Testing
  - [KQL Script to enumerate all enabled Default Accounts on each system using Advanced Hunting in Defender](https://github.com/stateoforegon-eis-css/Oregon-CIS-Assessments/blob/main/IG1%2B%20Defender%20KQL.md#safeguard-47-manage-default-accounts-on-enterprise-assets-and-software)
  - [Group Policy Objects evaluated](https://github.com/stateoforegon-eis-css/Oregon-CIS-Assessments/blob/main/IG1%2B%20Group%20Policy%20Settings.md#benchmark-group-policy-settings-for-safeguard-407)
  - [LAPS GPOs evaluated](https://github.com/stateoforegon-eis-css/Oregon-CIS-Assessments/blob/main/IG1%2B%20Group%20Policy%20Settings.md#laps-settings-related-to-safeguard-407)

**Assessment Methodology**

- [CIS Controls Assessment Specification for CIS Safeguard 4.07](https://cas8.docs.cisecurity.org/en/latest/source/Controls4/#47-manage-default-accounts-on-enterprise-assets-and-software)
- 

## Safeguard 5.01	(IG1)	Establish and Maintain an Inventory of Accounts

The implementation of Safeguard 5.01 contributes to the defensive mitigation for _2023 Statewide Information Technology Control Standard_ AC-2.

**Assessed Elements:**

- [GV22: Inventory of Accounts](https://github.com/stateoforegon-eis-css/Oregon-CIS-Assessments/blob/main/IG1%2B%20Artifact%20Request.md#gv22-inventory-of-accounts)
- Domain Accounts discovered during Internal Testing
  - [Powershell Script to enumerate Domain Accounts from Artifact Collector](https://github.com/stateoforegon-eis-css/Oregon-CIS-Assessments/blob/main/IG1%2B%20Artifact%20Collector.md#safeguard-51-establish-and-maintain-an-inventory-of-accounts)

**Assessment Methodology**

- [CIS Controls Assessment Specification for CIS Safeguard 5.01](https://cas8.docs.cisecurity.org/en/latest/source/Controls5/#51-establish-and-maintain-an-inventory-of-accounts)
- 

## Safeguard 5.02	(IG1)	Use Unique Passwords

The implementation of Safeguard 5.02 contributes to the defensive mitigation for _2023 Statewide Information Technology Control Standard_ IA-5(1).

**Assessed Elements:**

- [GV20: Unique Password Policy](https://github.com/stateoforegon-eis-css/Oregon-CIS-Assessments/blob/main/IG1%2B%20Artifact%20Request.md#gv20-unique-password-policy)
- Password settings observed during Internal Testing
  - [KQL Script to evaluate password complexity elements using Advanced Hunting in Defender](https://github.com/stateoforegon-eis-css/Oregon-CIS-Assessments/blob/main/IG1%2B%20Defender%20KQL.md#safeguard-52-use-unique-passwords)
  - [Group Policy Objects evaluated](https://github.com/stateoforegon-eis-css/Oregon-CIS-Assessments/blob/main/IG1%2B%20Group%20Policy%20Settings.md#benchmark-group-policy-settings-for-safeguard-502)

**Assessment Methodology**

- [CIS Controls Assessment Specification for CIS Safeguard 5.02](https://cas8.docs.cisecurity.org/en/latest/source/Controls5/#52-use-unique-passwords)
- 

## Safeguard 5.03	(IG1)	Disable Dormant Accounts

The implementation of Safeguard 5.03 contributes to the defensive mitigation for _2023 Statewide Information Technology Control Standard_ AC-2(3).

**Assessed Elements:**

- Domain Accounts discovered during Internal Testing (See Safeguard 5.01)
- Domain Account status observed during Internal Testing
  - [Powershell Script to enumerate Dormant Accounts and Status from Artifact Collector](https://github.com/stateoforegon-eis-css/Oregon-CIS-Assessments/blob/main/IG1%2B%20Artifact%20Collector.md#safeguard-53-disable-dormant-accounts)

**Assessment Methodology**

- [CIS Controls Assessment Specification for CIS Safeguard 5.03](https://cas8.docs.cisecurity.org/en/latest/source/Controls5/#53-disable-dormant-accounts)
- 

## Safeguard 5.04	(IG1)	Restrict Administrator Privileges to Dedicated Administrator Accounts

The implementation of Safeguard 5.04 is a critical element in the defensive mitigations for _2023 Statewide Information Technology Control Standards_ AC-6(2) and AC-6(5).

**Assessed Elements:**

- [GV22: Inventory of Accounts](https://github.com/stateoforegon-eis-css/Oregon-CIS-Assessments/blob/main/IG1%2B%20Artifact%20Request.md#gv22-inventory-of-accounts)
- Domain and Local Administrator Accounts discovered during Internal Testing
  - [KQL Script to enumerate all Local Administrative logons using Advanced Hunting in Defender](https://github.com/stateoforegon-eis-css/Oregon-CIS-Assessments/blob/main/IG1%2B%20Defender%20KQL.md#safeguard-54-restrict-administrator-privileges-to-dedicated-administrator-accounts)
  - [Powershell Script to enumerate Administrative Active Directory Groups and member Accounts from Artifact Collector](https://github.com/stateoforegon-eis-css/Oregon-CIS-Assessments/blob/main/IG1%2B%20Artifact%20Collector.md#safeguard-54-restrict-administrator-privileges-to-dedicated-administrator-accounts)

**Assessment Methodology**

- [CIS Controls Assessment Specification for CIS Safeguard 5.04](https://cas8.docs.cisecurity.org/en/latest/source/Controls5/#54-restrict-administrator-privileges-to-dedicated-administrator-accounts)
- 

## Safeguard 6.01	(IG1)	Establish an Access Granting Process

The implementation of Safeguard 6.01 contributes to the defensive mitigation for _2023 Statewide Information Technology Control Standards_ AC-1, AC-2, AC-2(1), IA-4, and IA-5.

**Assessed Elements:**

- [AD07: Process for Granting Access to Organization Assets](https://github.com/stateoforegon-eis-css/Oregon-CIS-Assessments/blob/main/IG1%2B%20Artifact%20Request.md#ad07-process-for-granting-access-to-organization-assets)

**Assessment Methodology**

- [CIS Controls Assessment Specification for CIS Safeguard 6.01](https://cas8.docs.cisecurity.org/en/latest/source/Controls6/#61-establish-an-access-granting-process)
- 

## Safeguard 6.02	(IG1)	Establish an Access Revoking Process

The implementation of Safeguard 6.02 contributes to the defensive mitigation for _2023 Statewide Information Technology Control Standards_ AC-1, AC-2, and AC-2(1).

**Assessed Elements:**

- [AD08: Process for Revoking Access to Organization Assets](https://github.com/stateoforegon-eis-css/Oregon-CIS-Assessments/blob/main/IG1%2B%20Artifact%20Request.md#ad08-process-for-revoking-access-to-organization-assets)

**Assessment Methodology**

- [CIS Controls Assessment Specification for CIS Safeguard 6.02](https://cas8.docs.cisecurity.org/en/latest/source/Controls6/#62-establish-an-access-revoking-process)
- 

## Safeguard 6.04	(IG1)	Require MFA for Remote Network Access

The implementation of Safeguard 6.04 contributes to the defensive mitigation for _2023 Statewide Information Technology Control Standards_ AC-19, IA-2(1), and IA-2(2).

**Assessed Elements:**

- [GV03.h - Configuration Standards: MFA Mechanisms for Admin Accounts & Remote Access](https://github.com/stateoforegon-eis-css/Oregon-CIS-Assessments/blob/main/IG1%2B%20Artifact%20Request.md#gv03h---configuration-standards-mfa-mechanisms-for-admin-accounts--remote-access)

**Assessment Methodology**

- [CIS Controls Assessment Specification for CIS Safeguard 6.04](https://cas8.docs.cisecurity.org/en/latest/source/Controls6/#64-require-mfa-for-remote-network-access)
- 

## Safeguard 6.05	(IG1)	Require MFA for Administrative Access

The implementation of Safeguard 6.05 is operationally equivalent to the defensive mitigation for _2023 Statewide Information Technology Control Standard_ IA-2(1).

**Assessed Elements:**

- [GV03.h - Configuration Standards: MFA Mechanisms for Admin Accounts & Remote Access](https://github.com/stateoforegon-eis-css/Oregon-CIS-Assessments/blob/main/IG1%2B%20Artifact%20Request.md#gv03h---configuration-standards-mfa-mechanisms-for-admin-accounts--remote-access)

**Assessment Methodology**

- [CIS Controls Assessment Specification for CIS Safeguard 6.05](https://cas8.docs.cisecurity.org/en/latest/source/Controls6/#65-require-mfa-for-administrative-access)
- 

## Safeguard 7.01	(IG1)	Establish and Maintain a Vulnerability Management Process

The implementation of Safeguard 7.01 is a critical element in the defensive mitigations for _2023 Statewide Information Technology Control Standard_ RA-5.

**Assessed Elements:**

- [AD09: Organization Vulnerability Management Process](https://github.com/stateoforegon-eis-css/Oregon-CIS-Assessments/blob/main/IG1%2B%20Artifact%20Request.md#ad09-organization-vulnerability-management-process)

**Assessment Methodology**

- [CIS Controls Assessment Specification for CIS Safeguard 7.01](https://cas8.docs.cisecurity.org/en/latest/source/Controls7/#71-establish-and-maintain-a-vulnerability-management-process)
- 

## Safeguard 7.02	(IG1)	Establish and Maintain a Remediation Process

The implementation of Safeguard 7.02 is a critical element in the defensive mitigations for _2023 Statewide Information Technology Control Standard_ RA-5.

**Assessed Elements:**

- [AD10: Organization Vulnerability Remediation Process](https://github.com/stateoforegon-eis-css/Oregon-CIS-Assessments/blob/main/IG1%2B%20Artifact%20Request.md#ad10-organization-vulnerability-remediation-process)

**Assessment Methodology**

- [CIS Controls Assessment Specification for CIS Safeguard 7.02](https://cas8.docs.cisecurity.org/en/latest/source/Controls7/#72-establish-and-maintain-a-remediation-process)
- 

## Safeguard 7.03	(IG1)	Perform Automated Operating System Patch Management

The implementation of Safeguard 7.03 contributes to the defensive mitigation for _2023 Statewide Information Technology Control Standards_ RA-5, RA-7, SI-2, and SI-2(2).

**Assessed Elements:**

- [GV03.a Configuration Standards: Operating Systems & Software](https://github.com/stateoforegon-eis-css/Oregon-CIS-Assessments/blob/main/IG1%2B%20Artifact%20Request.md#gv03a-configuration-standards-operating-systems--software)
- Operating System Versions observed during Internal Testing
  - [KQL Script to enumerate all Operating Systems with patches greater than 30 days using Advanced Hunting in Defender](https://github.com/stateoforegon-eis-css/Oregon-CIS-Assessments/blob/main/IG1%2B%20Defender%20KQL.md#safeguard-73-perform-automated-operating-system-patch-management)

**Assessment Methodology**

- [CIS Controls Assessment Specification for CIS Safeguard 7.03](https://cas8.docs.cisecurity.org/en/latest/source/Controls7/#73-perform-automated-operating-system-patch-management)
- 

## Safeguard 7.04	(IG1)	Perform Automated Application Patch Management

The implementation of Safeguard 7.04 contributes to the defensive mitigation for _2023 Statewide Information Technology Control Standards_ RA-5, RA-7, SI-2, and SI-2(2).

**Assessed Elements:**

- [GV24: Authorized Automated Patch Management Software](https://github.com/stateoforegon-eis-css/Oregon-CIS-Assessments/blob/main/IG1%2B%20Artifact%20Request.md#gv24-authorized-automated-patch-management-software)
- [GV03.f - Configuration Standards: Automated Patch Management Software](https://github.com/stateoforegon-eis-css/Oregon-CIS-Assessments/blob/main/IG1%2B%20Artifact%20Request.md#gv03f---configuration-standards-automated-patch-management-software)
- Application Versions observed during Internal Testing
  - [KQL Script to enumerate all Software with patches greater than 30 days using Advanced Hunting in Defender](https://github.com/stateoforegon-eis-css/Oregon-CIS-Assessments/blob/main/IG1%2B%20Defender%20KQL.md#safeguard-74-perform-automated-application-patch-management)

**Assessment Methodology**

- [CIS Controls Assessment Specification for CIS Safeguard 7.04](https://cas8.docs.cisecurity.org/en/latest/source/Controls7/#74-perform-automated-application-patch-management)
- 

## Safeguard 7.05	**_(IG2)_**	Perform Automated Vulnerability Scans of Internal Enterprise Assets

_Included in the Assessment as Enterprise Solution (Tenable) enables subscribers to automate vulnerability scanning._

The implementation of Safeguard 7.05 contributes to the defensive mitigation for _2023 Statewide Information Technology Control Standard_ RA-5.

**Assessed Elements:**

- [GV25: List of Vulnerability Scanning Software](https://github.com/stateoforegon-eis-css/Oregon-CIS-Assessments/blob/main/IG1%2B%20Artifact%20Request.md#gv25-list-of-vulnerability-scanning-software)
- [GV03.g - Configuration Standards: Vulnerability Scanners / Scanning Software](https://github.com/stateoforegon-eis-css/Oregon-CIS-Assessments/blob/main/IG1%2B%20Artifact%20Request.md#gv03g---configuration-standards-vulnerability-scanners--scanning-software)
- Internal Vulnerability Scan Coverage observed during Internal Testing

**Assessment Methodology**

- [CIS Controls Assessment Specification for CIS Safeguard 7.05](https://cas8.docs.cisecurity.org/en/latest/source/Controls7/#75-perform-automated-vulnerability-scans-of-internal-enterprise-assets)
- 

## Safeguard 7.06	**_(IG2)_**	Perform Automated Vulnerability Scans of Externally-Exposed Enterprise Assets

_Included in the Assessment as an Enterprise Solution (CISA Cyber Hygiene) enables subscribers to automate external vulnerability scanning._

The implementation of Safeguard 7.06 contributes to the defensive mitigation for _2023 Statewide Information Technology Control Standard_ RA-5.

**Assessed Elements:**

- [GV03.g - Configuration Standards: Vulnerability Scanners / Scanning Software](https://github.com/stateoforegon-eis-css/Oregon-CIS-Assessments/blob/main/IG1%2B%20Artifact%20Request.md#gv03g---configuration-standards-vulnerability-scanners--scanning-software)
- External Vulnerability Scan Coverage observed during Internal Testing

**Assessment Methodology**

- [CIS Controls Assessment Specification for CIS Safeguard 7.06](https://cas8.docs.cisecurity.org/en/latest/source/Controls7/#76-perform-automated-vulnerability-scans-of-externally-exposed-enterprise-assets)
- 

## Safeguard 8.01	(IG1)	Establish and Maintain an Audit Log Management Process

The implementation of Safeguard 8.01 is operationally equivalent to the defensive mitigation for _2023 Statewide Information Technology Control Standard_ AU-1; and a critical element in the defensive mitigations for _Standard_ AU-2.

**Assessed Elements:**

- [GV26: Agency Audit Log Management Process](https://github.com/stateoforegon-eis-css/Oregon-CIS-Assessments/blob/main/IG1%2B%20Artifact%20Request.md#gv26-agency-audit-log-management-process)

**Assessment Methodology**

- [CIS Controls Assessment Specification for CIS Safeguard 8.01](https://cas8.docs.cisecurity.org/en/latest/source/Controls8/#81-establish-and-maintain-an-audit-log-management-process)
- 

## Safeguard 8.02	(IG1)	Collect Audit Logs

The implementation of Safeguard 8.02 is operationally equivalent to the defensive mitigation for _2023 Statewide Information Technology Control Standards_ AU-2 and AU-12; and contributes to the defensive mitigation for _Standards_ AU-7.

**Assessed Elements:**

- Hardware Assets discovered during Internal Testing (See Safeguard 1.01)
- Event Log Storage Locations (CIS L1 Benchmarks) observed during Internal Testing
  - [Group Policy Objects evaluated](https://github.com/stateoforegon-eis-css/Oregon-CIS-Assessments/blob/main/IG1%2B%20Group%20Policy%20Settings.md#benchmark-group-policy-settings-for-safeguard-802)

**Assessment Methodology**

- [CIS Controls Assessment Specification for CIS Safeguard (8.02](https://cas8.docs.cisecurity.org/en/latest/source/Controls8/#82-collect-audit-logs)
- 

## Safeguard 8.03	(IG1)	Ensure Adequate Audit Log Storage

The implementation of Safeguard 8.03 is operationally equivalent to the defensive mitigation for _2023 Statewide Information Technology Control Standard_ AU-4.

**Assessed Elements:**

- Hardware Assets discovered during Internal Testing (See Safeguard 1.01)
- Event Log Storage Space (CIS L1 Benchmarks) observed during Internal Testing
  - [Group Policy Objects evaluated](https://github.com/stateoforegon-eis-css/Oregon-CIS-Assessments/blob/main/IG1%2B%20Group%20Policy%20Settings.md#benchmark-group-policy-settings-for-safeguard-803)

**Assessment Methodology**

- [CIS Controls Assessment Specification for CIS Safeguard 8.03](https://cas8.docs.cisecurity.org/en/latest/source/Controls8/#83-ensure-adequate-audit-log-storage)
- 

## Safeguard 8.04	**_(IG2)_**	Standardize Time Synchronization

_Included in the Assessment as an Enterprise Solution (NTP Servers) enables time synchronization._

The implementation of Safeguard 8.04 contributes to the defensive mitigation for _2023 Statewide Information Technology Control Standard_ AU-8.

**Assessed Elements:**

- Hardware Assets discovered during Internal Testing (See Safeguard 1.01)
- Network Time Protocol Settings observed during Internal Testing
  - [Powershell Script to extract NTP settings from Artifact Collector](https://github.com/stateoforegon-eis-css/Oregon-CIS-Assessments/blob/main/IG1%2B%20Artifact%20Collector.md#cis-control-8-audit-log-management)

**Assessment Methodology**

- [CIS Controls Assessment Specification for CIS Safeguard 8.04](https://cas8.docs.cisecurity.org/en/latest/source/Controls8/#84-standardize-time-synchronization)
- 

## Safeguard 8.05	**_(IG2)_**	Collect Detailed Audit Logs

_Included in the Assessment as an Enterprise Solution (Sentinel SIEM) enables subscribers to collect audit logs._

The implementation of Safeguard 8.05 is operationally equivalent to the defensive mitigation for _2023 Statewide Information Technology Control Standard_ AU-3; and contributes to the defensive mitigation for _Standards_ AU-3(1), AU-7, and AU-12.

**Assessed Elements:**

- [GV26: Agency Audit Log Management Process](https://github.com/stateoforegon-eis-css/Oregon-CIS-Assessments/blob/main/IG1%2B%20Artifact%20Request.md#gv26-agency-audit-log-management-process)
- Hardware Assets discovered during Internal Testing (See Safeguard 1.01)
- Event Log Generation Settings (CIS L1 Benchmarks) observed during Internal Testing
  - [Group Policy Objects evaluated](https://github.com/stateoforegon-eis-css/Oregon-CIS-Assessments/blob/main/IG1%2B%20Group%20Policy%20Settings.md#benchmark-group-policy-settings-for-safeguard-805)

**Assessment Methodology**

- [CIS Controls Assessment Specification for CIS Safeguard 8.05](https://cas8.docs.cisecurity.org/en/latest/source/Controls8/#85-collect-detailed-audit-logs)
- 

## Safeguard 8.09	**_(IG2)_**	Centralize Audit Logs

_Included in the Assessment as an Enterprise Solution (Sentinel SIEM) enables subscribers to centralize audit logs._

The implementation of Safeguard 8.09 contributes to the defensive mitigation for _2023 Statewide Information Technology Control Standard_ AU-6(3).

**Assessed Elements:**

- Hardware Assets discovered during Internal Testing (See Safeguard 1.01)
- Log Aggregation Implementation observed during Internal Testing

**Assessment Methodology**

- [CIS Controls Assessment Specification for CIS Safeguard 8.09](https://cas8.docs.cisecurity.org/en/latest/source/Controls8/#89-centralize-audit-logs)
- 

## Safeguard 8.10	**_(IG2)_**	Retain Audit Logs

_Included in the Assessment as an Enterprise Solution (Sentinel SIEM) enables subscribers to retain audit logs._

The implementation of Safeguard 8.10 is operationally equivalent to the defensive mitigation for _2023 Statewide Information Technology Control Standard_ AU-11.

**Assessed Elements:**

- Hardware Assets discovered during Internal Testing (See Safeguard 1.01)
- Audit Record Retention observed during Internal Testing

**Assessment Methodology**

- [CIS Controls Assessment Specification for CIS Safeguard 8.10](https://cas8.docs.cisecurity.org/en/latest/source/Controls8/#810-retain-audit-logs)
- 

## Safeguard 8.11	**_(IG2)_**	Conduct Audit Log Reviews

_Included in the Assessment as an Enterprise Solution (Sentinel SIEM) provides subscribers with triage services and review capabilities._

The implementation of Safeguard 8.11 is operationally equivalent to the defensive mitigation for _2023 Statewide Information Technology Control Standard_ AU-6; and contributes to the defensive mitigation for _Standard_ AU-6(1).

**Assessed Elements:**

- Audit Record Review Schedule observed during Internal Testing

**Assessment Methodology**

- [CIS Controls Assessment Specification for CIS Safeguard 8.11](https://cas8.docs.cisecurity.org/en/latest/source/Controls8/#811-conduct-audit-log-reviews)
- 

## Safeguard 9.01	(IG1)	Ensure Use of Only Fully Supported Browsers and Email Clients

The implementation of Safeguard 9.01 contributes to the defensive mitigation for _2023 Statewide Information Technology Control Standards_ CM-10 and SC-18.

**Assessed Elements:**

- [GV05: Authorized Software Inventory](https://github.com/stateoforegon-eis-css/Oregon-CIS-Assessments/blob/main/IG1%2B%20Artifact%20Request.md#gv05-authorized-software-inventory)
- Unsupported Browsers and Email Clients discovered during Internal Testing
  - [KQL Script to enumerate unsupported Email Clients and Web Browsers using Advanced Hunting in Defender](https://github.com/stateoforegon-eis-css/Oregon-CIS-Assessments/blob/main/IG1%2B%20Defender%20KQL.md#safeguard-91-ensure-use-of-only-fully-supported-browsers-and-email-clients)

**Assessment Methodology**

- [CIS Controls Assessment Specification for CIS Safeguard 9.01](https://cas8.docs.cisecurity.org/en/latest/source/Controls9/#91-ensure-use-of-only-fully-supported-browsers-and-email-clients)
- 

## Safeguard 9.02	(IG1)	Use DNS Filtering Services

The implementation of Safeguard 9.02 is a critical element in the defensive mitigations for _2023 Statewide Information Technology Control Standard_ SI-8.

**Assessed Elements:**

- [GV01: Detailed Hardware Asset Inventory](https://github.com/stateoforegon-eis-css/Oregon-CIS-Assessments/blob/main/IG1%2B%20Artifact%20Request.md#gv01-detailed-hardware-asset-inventory)
- [GV03.d - Configuration Standards: DNS Servers](https://github.com/stateoforegon-eis-css/Oregon-CIS-Assessments/blob/main/IG1%2B%20Artifact%20Request.md#gv03d---configuration-standards-dns-servers)
- DNS Filtering observed during Internal Testing
  - [KQL Script to extract the DNS Filtering for each system using Advanced Hunting in Defender](https://github.com/stateoforegon-eis-css/Oregon-CIS-Assessments/blob/main/IG1%2B%20Defender%20KQL.md#safeguard-92-use-dns-filtering-services)

**Assessment Methodology**

- [CIS Controls Assessment Specification for CIS Safeguard 9.02](https://cas8.docs.cisecurity.org/en/latest/source/Controls9/#92-use-dns-filtering-services)
- 

## Safeguard 10.01	(IG1)	Deploy and Maintain Anti-Malware Software

The implementation of Safeguard 10.01 contributes to the defensive mitigation for _2023 Statewide Information Technology Control Standard_ SI-3.

**Assessed Elements:**

- [GV31: List of Authorized Anti‐malware Software](https://github.com/stateoforegon-eis-css/Oregon-CIS-Assessments/blob/main/IG1%2B%20Artifact%20Request.md#gv31-list-of-authorized-antimalware-software)
- Hardware Assets discovered during Internal Testing (See Safeguard 1.01)
- Anti-malware Deployment observed during Internal Testing
  - [KQL Script to enumerate all systems with anti-malware software using Advanced Hunting in Defender](https://github.com/stateoforegon-eis-css/Oregon-CIS-Assessments/blob/main/IG1%2B%20Defender%20KQL.md#safeguard-101-deploy-and-maintain-anti-malware-software)

**Assessment Methodology**

- [CIS Controls Assessment Specification for CIS Safeguard 10.01](https://cas8.docs.cisecurity.org/en/latest/source/Controls10/#101-deploy-and-maintain-anti-malware-software)
- 

## Safeguard 10.02	(IG1)	Configure Automatic Anti-Malware Signature Updates

The implementation of Safeguard 10.02 contributes to the defensive mitigation for _2023 Statewide Information Technology Control Standard_ SI-3.

**Assessed Elements:**

- [GV31: List of Authorized Anti‐malware Software](https://github.com/stateoforegon-eis-css/Oregon-CIS-Assessments/blob/main/IG1%2B%20Artifact%20Request.md#gv31-list-of-authorized-antimalware-software)
- Hardware Assets discovered during Internal Testing (See Safeguard 1.01)
- Anti-malware Update Settings and Implementation observed during Internal Testing
  - [KQL Script to evaluate the anti-malware status of all systems using Advanced Hunting in Defender](https://github.com/stateoforegon-eis-css/Oregon-CIS-Assessments/blob/main/IG1%2B%20Defender%20KQL.md#safeguard-102-configure-automatic-anti-malware-signature-updates)

**Assessment Methodology**

- [CIS Controls Assessment Specification for CIS Safeguard 10.02](https://cas8.docs.cisecurity.org/en/latest/source/Controls10/#102-configure-automatic-anti-malware-signature-updates)
- 

## Safeguard 10.03	(IG1)	Disable Autorun and Autoplay for Removable Media

The implementation of Safeguard 10.03 contributes to the defensive mitigation for _2023 Statewide Information Technology Control Standard_ MP-7.

**Assessed Elements:**

- Hardware Assets discovered during Internal Testing (See Safeguard 1.01)
- Removable Media Settings observed during Internal Testing
  - [KQL Script to evaluate the status of Autorun/Autoplay using Advanced Hunting in Defender](https://github.com/stateoforegon-eis-css/Oregon-CIS-Assessments/blob/main/IG1%2B%20Defender%20KQL.md#safeguard-103-disable-autorun-and-autoplay-for-removable-media)
  - [Group Policy Objects evaluated](https://github.com/stateoforegon-eis-css/Oregon-CIS-Assessments/blob/main/IG1%2B%20Group%20Policy%20Settings.md#benchmark-group-policy-settings-for-safeguard-1003)

**Assessment Methodology**

- [CIS Controls Assessment Specification for CIS Safeguard 10.03](https://cas8.docs.cisecurity.org/en/latest/source/Controls10/#103-disable-autorun-and-autoplay-for-removable-media)
- 

## Safeguard 11.01	(IG1)	Establish and Maintain a Data Recovery Process 

The implementation of Safeguard 11.01 contributes to the defensive mitigation for _2023 Statewide Information Technology Control Standards_ CP-2 and CP-10.

**Assessed Elements:**

- [AD11: Documented Data Recovery Process for the Organization](https://github.com/stateoforegon-eis-css/Oregon-CIS-Assessments/blob/main/IG1%2B%20Artifact%20Request.md#ad11-documented-data-recovery-process-for-the-organization)

**Assessment Methodology**

- [CIS Controls Assessment Specification for CIS Safeguard 11.01](https://cas8.docs.cisecurity.org/en/latest/source/Controls11/#111-establish-and-maintain-a-data-recovery-process)
- 

## Safeguard 11.02	(IG1)	Perform Automated Backups 

The implementation of Safeguard 11.02 contributes to the defensive mitigation for _2023 Statewide Information Technology Control Standards_ CP-9 and CP-10.

**Assessed Elements:**

- Hardware Assets discovered during Internal Testing (See Safeguard 1.01)
- Automated Backup Implementation observed during Internal Testing
  - [KQL Script to enumerate all systems with CommVault Agent installed using Advanced Hunting in Defender](https://github.com/stateoforegon-eis-css/Oregon-CIS-Assessments/blob/main/IG1%2B%20Defender%20KQL.md#safeguard-112-perform-automated-backups)

**Assessment Methodology**

- [CIS Controls Assessment Specification for CIS Safeguard 11.02](https://cas8.docs.cisecurity.org/en/latest/source/Controls11/#112-perform-automated-backups)
- 

## Safeguard 11.03	(IG1)	Protect Recovery Data

The implementation of Safeguard 11.03 contributes to the defensive mitigation for _2023 Statewide Information Technology Control Standards_ CP-9, CP-9(8) and SC-28.

**Assessed Elements:**

- Hardware Assets discovered during Internal Testing (See Safeguard 1.01)
- Backup Data Protections observed during Internal Testing

**Assessment Methodology**

- [CIS Controls Assessment Specification for CIS Safeguard 11.03](https://cas8.docs.cisecurity.org/en/latest/source/Controls11/#113-protect-recovery-data)
- 

## Safeguard 11.04	(IG1)	Establish and Maintain an Isolated Instance of Recovery Data 

The implementation of Safeguard 11.04 is a critical element in the defensive mitigations for _2023 Statewide Information Technology Control Standards_ CP-6 and CP-6(1).

**Assessed Elements:**

- Hardware Assets discovered during Internal Testing (See Safeguard 1.01)
- Backup Data Protections observed during Internal Testing

**Assessment Methodology**

- [CIS Controls Assessment Specification for CIS Safeguard 11.04](https://cas8.docs.cisecurity.org/en/latest/source/Controls11/#114-establish-and-maintain-an-isolated-instance-of-recovery-data)
- 

## Safeguard 13.01	**_(IG2)_**	Centralize Security Event Alerting

_Included in the Assessment as an Enterprise Solution (Sentinel SIEM) provides subscribers with triage services and review capabilities._

The implementation of Safeguard 13.01 is a critical element in the defensive mitigations for _2023 Statewide Information Technology Control Standards_ IR-4(1) and SI-4(2); and contributes to the defensive mitigation for _Standards_ AU-6(1), AU-7, and SI-4(5).

**Assessed Elements:**

- Hardware Assets discovered during Internal Testing (See Safeguard 1.01)
- Agency adoption of Defender/Sentinel SIEM Solution observed during Internal Testing
  - [Evaluate Defender's Device Inventory for 'onboarded' assets](https://security.microsoft.com/machines)

**Assessment Methodology**

- [CIS Controls Assessment Specification for CIS Safeguard 13.01](https://cas8.docs.cisecurity.org/en/latest/source/Controls13/#131-centralize-security-event-alerting)
- 

## Safeguard 13.07	**_(IG3)_**	Deploy a Host-Based Intrusion Prevention Solution

_Included in the Assessment as an Enterprise Solution (Sentinel SIEM) provides subscribers with Endpoint Detection and Response (EDR)._

The implementation of Safeguard 13.07 is not directly related to the defensive mitigation of a _2023 Statewide Information Technology Control Standard_; rather, it contributes to the organization's overall security posture.

**Assessed Elements:**

- Hardware Assets discovered during Internal Testing (See Safeguard 1.01)
- Agency adoption of Defender/Sentinel SIEM Solution observed during Internal Testing
  - [Evaluate Defender's Device Inventory for 'onboarded' assets](https://security.microsoft.com/machines)

**Assessment Methodology**

- [CIS Controls Assessment Specification for CIS Safeguard 13.07](https://cas8.docs.cisecurity.org/en/latest/source/Controls13/#137-deploy-a-host-based-intrusion-prevention-solution)
- 

## Safeguard 14.01	(IG1)	Establish and Maintain a Security Awareness Program

The implementation of Safeguard 14.01 contributes to the defensive mitigation for _2023 Statewide Information Technology Control Standards_ AT-1, AT-2, and PM-13.

**Assessed Elements:**

- [AD12: Agency Security Awareness Training Program Plan](https://github.com/stateoforegon-eis-css/Oregon-CIS-Assessments/blob/main/IG1%2B%20Artifact%20Request.md#ad12-agency-security-awareness-training-program-plan)
- [AD14: Security Awareness and Training metrics for the prior year](https://github.com/stateoforegon-eis-css/Oregon-CIS-Assessments/blob/main/IG1%2B%20Artifact%20Request.md#ad14-security-awareness-and-training-metrics-for-the-prior-year)
- Training Statistics observed during Internal Testing
  - Report available through [Workday Learning](https://wd5.myworkday.com/oregon/d/task/1422$4944.htmld) or Enterprise Iformation Security & Awareness Program

**Assessment Methodology**

- [CIS Controls Assessment Specification for CIS Safeguard 14.01](https://cas8.docs.cisecurity.org/en/latest/source/Controls14/#141-establish-and-maintain-a-security-awareness-program)
- 

## Safeguard 14.02	(IG1)	Train Workforce Members to Recognize Social Engineering Attacks

The implementation of Safeguard 14.02 is operationally equivalent to the defensive mitigation for _2023 Statewide Information Technology Control Standard_ AT-2(3).

**Assessed Elements:**

- [AD12: Agency Security Awareness Training Program Plan](https://github.com/stateoforegon-eis-css/Oregon-CIS-Assessments/blob/main/IG1%2B%20Artifact%20Request.md#ad12-agency-security-awareness-training-program-plan)
- [GV43: List of workforce members](https://github.com/stateoforegon-eis-css/Oregon-CIS-Assessments/blob/main/IG1%2B%20Artifact%20Request.md#gv43-list-of-workforce-members)
- Training Statistics observed during Internal Testing
  - Report available through [Workday Learning](https://wd5.myworkday.com/oregon/d/task/1422$4944.htmld) or Enterprise Iformation Security & Awareness Program

**Assessment Methodology**

- [CIS Controls Assessment Specification for CIS Safeguard 14.02](https://cas8.docs.cisecurity.org/en/latest/source/Controls14/#142-train-workforce-members-to-recognize-social-engineering-attacks)
- 

## Safeguard 14.03	(IG1)	Train Workforce Members on Authentication Best Practices

The implementation of Safeguard 14.03 contributes to the defensive mitigation for _2023 Statewide Information Technology Control Standard_ AT-2.

**Assessed Elements:**

- [AD12: Agency Security Awareness Training Program Plan](https://github.com/stateoforegon-eis-css/Oregon-CIS-Assessments/blob/main/IG1%2B%20Artifact%20Request.md#ad12-agency-security-awareness-training-program-plan)
- [GV43: List of workforce members](https://github.com/stateoforegon-eis-css/Oregon-CIS-Assessments/blob/main/IG1%2B%20Artifact%20Request.md#gv43-list-of-workforce-members)
- Training Statistics observed during Internal Testing
  - Report available through [Workday Learning](https://wd5.myworkday.com/oregon/d/task/1422$4944.htmld) or Enterprise Iformation Security & Awareness Program

**Assessment Methodology**

- [CIS Controls Assessment Specification for CIS Safeguard 14.03](https://cas8.docs.cisecurity.org/en/latest/source/Controls14/#143-train-workforce-members-on-authentication-best-practices)
- 

## Safeguard 14.04	(IG1)	Train Workforce on Data Handling Best Practices

The implementation of Safeguard 14.04 contributes to the defensive mitigation for _2023 Statewide Information Technology Control Standard_ AT-2.

**Assessed Elements:**

- [AD12: Agency Security Awareness Training Program Plan](https://github.com/stateoforegon-eis-css/Oregon-CIS-Assessments/blob/main/IG1%2B%20Artifact%20Request.md#ad12-agency-security-awareness-training-program-plan)
- [GV43: List of workforce members](https://github.com/stateoforegon-eis-css/Oregon-CIS-Assessments/blob/main/IG1%2B%20Artifact%20Request.md#gv43-list-of-workforce-members)
- Training Statistics observed during Internal Testing
  - Report available through [Workday Learning](https://wd5.myworkday.com/oregon/d/task/1422$4944.htmld) or Enterprise Iformation Security & Awareness Program

**Assessment Methodology**

- [CIS Controls Assessment Specification for CIS Safeguard 14.04](https://cas8.docs.cisecurity.org/en/latest/source/Controls14/#144-train-workforce-on-data-handling-best-practices)
- 

## Safeguard 14.05	(IG1)	Train Workforce Members on Causes of Unintentional Data Exposure

The implementation of Safeguard 14.05 contributes to the defensive mitigation for _2023 Statewide Information Technology Control Standard_ AC-22.

**Assessed Elements:**

- [AD12: Agency Security Awareness Training Program Plan](https://github.com/stateoforegon-eis-css/Oregon-CIS-Assessments/blob/main/IG1%2B%20Artifact%20Request.md#ad12-agency-security-awareness-training-program-plan)
- [GV43: List of workforce members](https://github.com/stateoforegon-eis-css/Oregon-CIS-Assessments/blob/main/IG1%2B%20Artifact%20Request.md#gv43-list-of-workforce-members)
- Training Statistics observed during Internal Testing
  - Report available through [Workday Learning](https://wd5.myworkday.com/oregon/d/task/1422$4944.htmld) or Enterprise Iformation Security & Awareness Program

**Assessment Methodology**

- [CIS Controls Assessment Specification for CIS Safeguard 14.05](https://cas8.docs.cisecurity.org/en/latest/source/Controls14/#145-train-workforce-members-on-causes-of-unintentional-data-exposure)
- 

## Safeguard 14.06	(IG1)	Train Workforce Members on Recognizing and Reporting Security Incidents

The implementation of Safeguard 14.06 contributes to the defensive mitigation for _2023 Statewide Information Technology Control Standard_ AT-2.

**Assessed Elements:**

- [AD12: Agency Security Awareness Training Program Plan](https://github.com/stateoforegon-eis-css/Oregon-CIS-Assessments/blob/main/IG1%2B%20Artifact%20Request.md#ad12-agency-security-awareness-training-program-plan)
- [GV43: List of workforce members](https://github.com/stateoforegon-eis-css/Oregon-CIS-Assessments/blob/main/IG1%2B%20Artifact%20Request.md#gv43-list-of-workforce-members)
- Training Statistics observed during Internal Testing
  - Report available through [Workday Learning](https://wd5.myworkday.com/oregon/d/task/1422$4944.htmld) or Enterprise Iformation Security & Awareness Program

**Assessment Methodology**

- [CIS Controls Assessment Specification for CIS Safeguard 14.06](https://cas8.docs.cisecurity.org/en/latest/source/Controls14/#146-train-workforce-members-on-recognizing-and-reporting-security-incidents)
- 

## Safeguard 14.08	(IG1)	Train Workforce on the Dangers of Connecting to and Transmitting Enterprise Data Over Insecure Networks

The implementation of Safeguard 14.08 contributes to the defensive mitigation for _2023 Statewide Information Technology Control Standard_ AT-2.

**Assessed Elements:**

- [AD12: Agency Security Awareness Training Program Plan](https://github.com/stateoforegon-eis-css/Oregon-CIS-Assessments/blob/main/IG1%2B%20Artifact%20Request.md#ad12-agency-security-awareness-training-program-plan)
- [GV43: List of workforce members](https://github.com/stateoforegon-eis-css/Oregon-CIS-Assessments/blob/main/IG1%2B%20Artifact%20Request.md#gv43-list-of-workforce-members)
- Training Statistics observed during Internal Testing
  - Report available through [Workday Learning](https://wd5.myworkday.com/oregon/d/task/1422$4944.htmld) or Enterprise Iformation Security & Awareness Program

**Assessment Methodology**

- [CIS Controls Assessment Specification for CIS Safeguard 14.08](https://cas8.docs.cisecurity.org/en/latest/source/Controls14/#148-train-workforce-on-the-dangers-of-connecting-to-and-transmitting-enterprise-data-over-insecure-networks)
- 

## Safeguard 15.01	(IG1)	Establish and Maintain an Inventory of Service Providers

The implementation of Safeguard 15.01 is a critical element in the defensive mitigations for _2023 Statewide Information Technology Control Standard_ PM-30(1).

**Assessed Elements:**

- [GV44: Service Provider Inventory List](https://github.com/stateoforegon-eis-css/Oregon-CIS-Assessments/blob/main/IG1%2B%20Artifact%20Request.md#gv44-service-provider-inventory-list)
- Service Providers identified during Internal Testing
  - [OregonBuys 'Active Blankets' Search](https://oregonbuys.gov/bso/view/search/external/advancedSearchContractBlanket.xhtml?view=activeContracts)

**Assessment Methodology**

- [CIS Controls Assessment Specification for CIS Safeguard 15.01](https://cas8.docs.cisecurity.org/en/latest/source/Controls15/#151-establish-and-maintain-an-inventory-of-service-providers)
- 

## Safeguard 17.01	(IG1)	Designate Personnel to Manage Incident Handling

The implementation of Safeguard 17.01 is a critical element in the defensive mitigations for _2023 Statewide Information Technology Control Standard_ IR-7; and contributes to the defensive mitigation for _Standards_ IR-1 and IR-8.

**Assessed Elements:**

- [GV51: Agency Incident Response Documentation](https://github.com/stateoforegon-eis-css/Oregon-CIS-Assessments/blob/main/IG1%2B%20Artifact%20Request.md#gv51-agency-incident-response-documentation)

**Assessment Methodology**

- [CIS Controls Assessment Specification for CIS Safeguard 17.01](https://cas8.docs.cisecurity.org/en/latest/source/Controls17/#171-designate-personnel-to-manage-incident-handling)
- 

## Safeguard 17.02	(IG1)	Establish and Maintain Contact Information for Reporting Security Incidents

The implementation of Safeguard 17.02 is a critical element in the defensive mitigations for _2023 Statewide Information Technology Control Standard_ IR-6(3); and contributes to the defensive mitigation for _Standard_ IR-6.

**Assessed Elements:**

- [GV51: Agency Incident Response Documentation](https://github.com/stateoforegon-eis-css/Oregon-CIS-Assessments/blob/main/IG1%2B%20Artifact%20Request.md#gv51-agency-incident-response-documentation)

**Assessment Methodology**

- [CIS Controls Assessment Specification for CIS Safeguard 17.02](https://cas8.docs.cisecurity.org/en/latest/source/Controls17/#172-establish-and-maintain-contact-information-for-reporting-security-incidents)
- 

## Safeguard 17.03	(IG1)	Establish and Maintain an Enterprise Process for Reporting Incidents

The implementation of Safeguard 17.03 is a critical element in the defensive mitigations for _2023 Statewide Information Technology Control Standard_ IR-6(1); and contributes to the defensive mitigation for _Standards_ IR-5, IR-6, and IR-8.

**Assessed Elements:**

- [GV51: Agency Incident Response Documentation](https://github.com/stateoforegon-eis-css/Oregon-CIS-Assessments/blob/main/IG1%2B%20Artifact%20Request.md#gv51-agency-incident-response-documentation)

**Assessment Methodology**

- [CIS Controls Assessment Specification for CIS Safeguard 17.03](https://cas8.docs.cisecurity.org/en/latest/source/Controls17/#173-establish-and-maintain-an-enterprise-process-for-reporting-incidents)
- 

## Safeguard 18.02	**_(IG2)_**	Perform Periodic External Penetration Tests

_Included in the Assessment as an Enterprise Solution (CISA RVA) provides subscribers with external penetration testing._

The implementation of Safeguard 18.02 contributes to the defensive mitigation for _2023 Statewide Information Technology Control Standard_ CA-8.

**Assessed Elements:**

- [GV54: Most recent external penetration test report for the organization](https://github.com/stateoforegon-eis-css/Oregon-CIS-Assessments/blob/main/IG1%2B%20Artifact%20Request.md#gv54-most-recent-external-penetration-test-report-for-the-organization)

**Assessment Methodology**

- [CIS Controls Assessment Specification for CIS Safeguard 18.02](https://cas8.docs.cisecurity.org/en/latest/source/Controls18/#182-perform-periodic-external-penetration-tests)
- 

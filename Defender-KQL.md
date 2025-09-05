# **CIS v8.0 Controls Assessment Specification Defender Measurement Scripts (BETA)**

## CIS Control #1: Inventory and Control of Enterprise Assets

### Safeguard 1.1 Establish and Maintain a Detailed Asset Inventory

**About:**
Script to extract an inventory of 'discovered' assets from Defender

```kql
DeviceNetworkInfo
| where DeviceName has_any ("domain.01", "domain.02") // Target Domains - comment out for agencies in their own tenant
| summarize
    FirstSeen = min(Timestamp), // Get the first event timestamp
    LastSeen = max(Timestamp)   // Get the last event timestamp
by DeviceId, DeviceName, MacAddress // Group by DeviceId and DeviceName
| project DeviceId, DeviceName, MacAddress, FirstSeen, LastSeen // Select relevant fields for output
| summarize take_any(*) by DeviceId // De-duplicate results to a single row for each DeviceId
```

## CIS Control #2: Inventory and Control of Software Assets

### Covered Vendor Compliance

**About:**
Script to extract "Covered Vendors" from an Agency's software inventory

```kql
DeviceTvmSoftwareInventory
| where DeviceName has_any ("domain.01", "domain.02") // Target Domains - comment out for agencies in their own tenant
| where SoftwareVendor has_any ("Ant Group", "ByteDance", "DeepSeek", "Huawei", "Kaspersky", "Tencent", "ZTE", "Hytera", "Hangzhou", "Hikvision", "Dahua", "China", "ComNet") // Covered Vendors
| project DeviceId, DeviceName, SoftwareVendor, SoftwareName, SoftwareVersion // Select relevant fields for output
| sort by SoftwareVendor asc, SoftwareName asc, SoftwareVersion asc // Multi-column sort
```

### Safeguard 2.2 Ensure Authorized Software is Currently Supported

**About:**
Script to extract an inventory of 'discovered' software from Defender with "EOS" tags

```kql
DeviceTvmSoftwareInventory
| where DeviceName has_any ("domain.01", "domain.02") // Target Domains - comment out for agencies in their own tenant
and isnotempty(EndOfSupportStatus)
| project DeviceId, DeviceName, SoftwareVendor, SoftwareName, SoftwareVersion, EndOfSupportStatus, EndOfSupportDate // Select relevant fields for output
| summarize DeviceId = count() by SoftwareVendor, SoftwareName, SoftwareVersion, EndOfSupportStatus, EndOfSupportDate // Summarize by Software info
| sort by SoftwareVendor asc, SoftwareName asc, SoftwareVersion asc // Multi-column sort
```

### Safeguard 2.3 Software Present on Enterprise Assets

**About:**
Script to extract a list of all installed software for comparison against the Authorized Inventory

```kql
DeviceTvmSoftwareInventory
| where DeviceName has_any ("domain.01", "domain.02") // Target Domains - comment out for agencies in their own tenant
| distinct DeviceName, Software=strcat(SoftwareVendor, ': ',SoftwareName) // Select relevant fields for output
| summarize DeviceName = count() by Software // Summarize by Software info
| sort by Software asc // Sort software list
```

Alternate script to extract software list based on CPE data (takes longer, but is more concise)

```kql
DeviceTvmSoftwareInventory
| where DeviceName has_any ("domain.01", "domain.02") // Target Domains - comment out for agencies in their own tenant
| where ProductCodeCpe !contains "Not Available"
| project ProductCodeCpe, DeviceName
| extend firstDelimiterPos = indexof(ProductCodeCpe, ":")
| extend secondDelimiterPos = indexof(ProductCodeCpe, ":", firstDelimiterPos + 1)
| extend Product = iif(secondDelimiterPos != -1, substring(ProductCodeCpe, 0, secondDelimiterPos), ProductCodeCpe)
| summarize DeviceName = count() by Product // Summarize by Software info
| sort by Product asc // Sort software list
```

## CIS Control #3: Data Protection

### Safeguard 3.6 Encrypt Data on End-User Devices

**About:**
Script to summarize a count of devices where supported drives are Bitlocker encrypted (SCID 2090)

```kql
DeviceTvmSecureConfigurationAssessment
| where DeviceName has_any ("domain.01", "domain.02") // Target Domains - comment out for agencies in their own tenant
| where ConfigurationId == 'scid-2090' // Limit results to Configuration ID "Encrypt all BitLocker-supported drives"
| where IsApplicable == 1 // Limit results to systems for which the configuration is applicable
| project DeviceId, DeviceName, ConfigurationId, IsCompliant // Select relevant fields for output
| summarize DeviceId = count(), CompliantSystems = countif(IsCompliant == 1), NonCompliantSystems = countif(IsCompliant == 0)
```

### Safeguard 3.12 Segment Data Processing and Storage Based on Sensitivity

**About:**
Script to identify the storage or modification of PII on enterprise devices

```kql
DeviceFileEvents
| where DeviceName has_any ("domain.01", "domain.02")
| where FileName has_any ("social security", "ssn", "passport", "birth")
| where ActionType != "FileDeleted"
| where FileName !endswith ".lnk"
| project DeviceId, DeviceName, ActionType, FolderPath, FileName
```

## CIS Control #4: Secure Configuration of Enterprise Assets and Software

### Safeguard 4.3 Configure Automatic Session Locking on Enterprise Assets

**About:**
Script to summarize a count of devices where session locks after 15 minutes of inactivity (SCID 28)

```kql
DeviceTvmSecureConfigurationAssessment
| where DeviceName has_any ("domain.01", "domain.02") // Target Domains - comment out for agencies in their own tenant
| where ConfigurationId == 'scid-28' // Limit results to Configuration ID "Set 'Interactive logon: Machine inactivity limit' to '1-900 seconds'"
| where IsApplicable == 1 // Limit results to systems for which the configuration is applicable
| project DeviceId, DeviceName, ConfigurationId, IsCompliant // Select relevant fields for output
| summarize DeviceId = count(), CompliantSystems = countif(IsCompliant == 1), NonCompliantSystems = countif(IsCompliant == 0)
```

### Safeguard 4.4 Implement and Manage a Firewall on Servers

**About:**
Script to summarize a count of server devices where Defender Firewall is turned on (SCID 2070) and properly secured (SCID 2071, 2072, 2073)

Un-comment lines 14-15 or 17 to summarize by setting or device

```kql
DeviceTvmSecureConfigurationAssessment
| where Timestamp > ago(365d) // Filter for events within the last 365 days
| where DeviceName has_any ("domain.01", "domain.02") // Target Domains - comment out for agencies in their own tenant
| where ConfigurationId == 'scid-2070' // Limit results to Configuration ID "Turn on Microsoft Defender Firewall"
| where IsApplicable == 1 // Limit results to systems for which the configuration is applicable
| join kind = leftouter (
    DeviceInfo)
        on DeviceId
| where OSPlatform contains "server"
| project DeviceId, DeviceName, OSPlatform, ConfigurationId, IsCompliant // Select relevant fields for output
| distinct DeviceId, DeviceName, OSPlatform, ConfigurationId, IsCompliant
//Summary Data
//| summarize DeviceCount = count(), CompliantSystems = countif(IsCompliant == 1), NonCompliantSystems = countif(IsCompliant == 0) by ConfigurationId
//| sort by ConfigurationId asc
//Detailed Device Info
//| summarize DefenderFirewallOn = countif(ConfigurationId == 'scid-2070' and IsCompliant == 1) by DeviceName
```

### Safeguard 4.5 Implement and Manage a Firewall on End-User Devices

**About:**
Script to summarize a count of end-user devices where Defender Firewall is turned on (SCID 2070) and properly secured (SCID 2071, 2072, 2073)

Un-comment lines 14-15 or 17 to summarize by setting or device

```kql
DeviceTvmSecureConfigurationAssessment
| where Timestamp > ago(365d) // Filter for events within the last 365 days
| where DeviceName has_any ("domain.01", "domain.02") // Target Domains - comment out for agencies in their own tenant
| where ConfigurationId == 'scid-2070' // Limit results to Configuration ID "Turn on Microsoft Defender Firewall"
| where IsApplicable == 1 // Limit results to systems for which the configuration is applicable
| join kind = leftouter (
    DeviceInfo)
        on DeviceId
| where OSPlatform !contains "server"
| project DeviceId, DeviceName, OSPlatform, ConfigurationId, IsCompliant // Select relevant fields for output
| distinct DeviceId, DeviceName, OSPlatform, ConfigurationId, IsCompliant
//Summary Data
//| summarize DeviceCount = count(), CompliantSystems = countif(IsCompliant == 1), NonCompliantSystems = countif(IsCompliant == 0) by ConfigurationId
//| sort by ConfigurationId asc
//Detailed Device Info
//| summarize DefenderFirewallOn = countif(ConfigurationId == 'scid-2070' and IsCompliant == 1) by DeviceName
```

### Safeguard 4.7 Manage Default Accounts on Enterprise Assets and Software

**About:**
Script to list all devices and whether the default administrator (SCID 3010) or guest (SCID 3011) accounts are disabled (indicated by "1").  Also indicates whether the LAPS is being utilized during login (indicated by "1").

```kql
DeviceTvmSecureConfigurationAssessment
| where Timestamp > ago(365d) // Filter for events within the last 365 days
| where DeviceName has_any ("domain.01", "domain.02") // Target Domains - comment out for agencies in their own tenant
| where ConfigurationId == 'scid-3010' // Limit results to Configuration ID "Disable the built-in Administrator account"
or ConfigurationId == 'scid-3011' // Limit results to Configuration ID "Disable the built-in Guest account" 
| where IsApplicable == 1 // Limit results to systems for which the configuration is applicable
| summarize AdminAcct = countif(ConfigurationId == 'scid-3010' and IsCompliant == 1), GuestAcct = countif(ConfigurationId == 'scid-3011' and IsCompliant == 1) by DeviceName
| join kind = leftouter (
DeviceEvents
| where InitiatingProcessFileName contains "lsass.exe" and AdditionalFields has "LAPS"
| extend LAPS = iff(AdditionalFields has "LAPS", 1, 0)
| summarize arg_max(Timestamp, LAPS) by DeviceName)
on DeviceName
| project DeviceName, GuestAcct, AdminAcct, LAPS
```

### Safeguard 4.9 Configure Trusted DNS Servers on Enterprise Assets

**About:**
Script to sample network events and extract most recent DNS information for each connected device

Note that the results are sorted by Network Adapter by default

```kql
DeviceNetworkInfo
| where Timestamp > ago(365d) // Filter for events within the last 365 days
| where DeviceName has_any ("domain.01", "domain.02") // Target Domains - comment out for agencies in their own tenant
| where NetworkAdapterStatus == "Up"
| where DnsAddresses != ""
| summarize arg_max(Timestamp, *) by DeviceName, NetworkAdapterType // limit results to most recent event for each Device/Adapter
| project DeviceName, Timestamp, MacAddress, NetworkAdapterType, DnsAddresses
| sort by NetworkAdapterType asc, DeviceName asc
```

## CIS Control #5: Account Management

### Safeguard 5.2 Use Unique Passwords

**About:**
Script to summarize a count of systems with the following password settings:
- Minimum password length = 14 characters (SCID 32)
- Password history = 24 passwords (SCID 33)
- Maximum password age = 60 days (SCID 34)
- Minimum password age = 1 day (SCID 35)

Un-comment lines 11-12 or 14 to summarize by setting or device

```kql
DeviceTvmSecureConfigurationAssessment
| where DeviceName has_any ("domain.01", "domain.02") // Target Domains - comment out for agencies in their own tenant
| where ConfigurationId == 'scid-32' // Limit results to Configuration ID "Set 'Minimum password length' to '14 or more characters'"
or ConfigurationId == 'scid-33' // Limit results to Configuration ID "Set 'Enforce password history' to '24 or more password(s)'"
or ConfigurationId == 'scid-34' // Limit results to Configuration ID "Set 'Maximum password age' to '60 or fewer days, but not 0'"
or ConfigurationId == 'scid-35' // Limit results to Configuration ID "Set 'Minimum password age' to '1 or more day(s)'"
| where IsApplicable == 1 // Limit results to systems for which the configuration is applicable
| project DeviceId, DeviceName, ConfigurationId, IsCompliant // Select relevant fields for output
//Summary Data
//| summarize DeviceCount = count(), CompliantSystems = countif(IsCompliant == 1), NonCompliantSystems = countif(IsCompliant == 0) by ConfigurationId
//| sort by ConfigurationId asc
//Detailed Device Info
//| summarize Length14 = countif(ConfigurationId == 'scid-32' and IsCompliant == 1), Hist24 = countif(ConfigurationId == 'scid-33' and IsCompliant == 1), Max60 = countif(ConfigurationId == 'scid-34' and IsCompliant == 1), Min01 = countif(ConfigurationId == 'scid-35' and IsCompliant == 1) by DeviceName
```

### Safeguard 5.4 Restrict Administrator Privileges to Dedicated Administrator Accounts

**About:**
Script to list local administrator logons and summarize the systems accessed

```kql
DeviceLogonEvents
| where DeviceName has_any ("domain.01", "domain.02") // Target Domains - comment out for agencies in their own tenant
| where LogonType == "Interactive"
or LogonType == "RemoteInteractive"
| where AccountName !contains "lenovo" // Filter to remove local administrators created during OS setup
| where IsLocalAdmin == 1 
| join kind = leftouter (
    IdentityInfo
    | project AccountName, AccountDisplayName) on AccountName // Extract display name from Idenity Info and link to Account Name
| project DeviceName, AccountName, AccountDisplayName, IsLocalAdmin // Select relevant fields for output
| summarize
    ['Local Admin Distinct Device Count']=dcountif(DeviceName, IsLocalAdmin == "true"),
    ['Local Admin Device List']=make_set_if(DeviceName, IsLocalAdmin == "true") // Consolidate list of devices into a single field
    by AccountName, AccountDisplayName
//| sort by ['Local Admin Distinct Device Count'] desc // Sort by Device Count
| sort by AccountName asc // Sort by Account Name
```

## CIS Control #7: Continuous Vulnerability Management

### Safeguard 7.3 Perform Automated Operating System Patch Management

**About:**
Script to extract a list of installed Windows operating systems (including patches over 30 days) and number of systems for each

```kql
DeviceTvmSoftwareInventory
| where DeviceName has_any ("domain.01", "domain.02") // Target Domains - comment out for agencies in their own tenant
| where SoftwareName has_any ("windows_10", "windows_11", "windows_server_2016", "windows_server_2019", "windows_server_2022", "windows_server_2025") // limit results to Windows operating systems
| distinct DeviceName, Software=strcat(SoftwareVendor, ': ',SoftwareName,'-',SoftwareVersion) // Select relevant fields for output
| join kind = leftouter (
DeviceTvmSoftwareVulnerabilities
| join kind = leftouter (
    DeviceTvmSoftwareVulnerabilitiesKB)
      on CveId // Extract published date from KB and link to Software Name
| where PublishedDate < ago(30d)
| project CveId, Software=strcat(SoftwareVendor, ': ',SoftwareName,'-',SoftwareVersion)
| summarize CVEPatchList=make_set(CveId) by Software) // Summarize all CVE records to a single field
 on Software
| summarize
    DeviceCount=dcount(DeviceName)
    by Software, tostring(CVEPatchList)
| sort by Software asc // Sort software list
```

### Safeguard 7.4 Perform Automated Application Patch Management (Numerator)

**About:**
Script to extract a list of applications (including patches more than 30 days old) and number of systems for each

```kql
DeviceTvmSoftwareInventory
| where DeviceName has_any ("domain.01", "domain.02") // Target Domains - comment out for agencies in their own tenant
| where not (SoftwareName has_any ("windows_10", "windows_11", "windows_server_2016",  "windows_server_2019", "windows_server_2022", "windows_server_2025")) // remove Windows operating systems from results
| distinct DeviceName, Software=strcat(SoftwareVendor, ': ',SoftwareName,'-',SoftwareVersion) // Select relevant fields for output
| join kind = leftouter (
DeviceTvmSoftwareVulnerabilities
| join kind = leftouter (
    DeviceTvmSoftwareVulnerabilitiesKB)
      on CveId // Extract published date from KB and link to Software Name
| where PublishedDate < ago(30d)
| project CveId, Software=strcat(SoftwareVendor, ': ',SoftwareName,'-',SoftwareVersion)
| summarize CVEPatchList=make_set(CveId) by Software) // Summarize all CVE records to a single field
 on Software
| summarize
    DeviceCount=dcount(DeviceName)
    by Software, tostring(CVEPatchList)
| sort by Software asc // Sort software list
```

## CIS Control #10: Malware Defenses

### Safeguard 10.1 Deploy and Maintain Anti-Malware Software

**About:**
Script to summarize a count of systems with Defender installed (SCID 2010) and updates are enabled (SCID 2011)

Un-comment lines 9-10 or 12 to summarize by setting or device

```kql
DeviceTvmSecureConfigurationAssessment
| where DeviceName has_any ("domain.01", "domain.02") // Target Domains - comment out for agencies in their own tenant
| where ConfigurationId == 'scid-2010' // Limit results to Configuration ID "Turn on Microsoft defender Antivirus"
or ConfigurationId == 'scid-2011' // Limit results to Configuration ID "Update Microsoft Defender Antivirus definitions"
| where IsApplicable == 1 // Limit results to systems for which the configuration is applicable
| project DeviceId, DeviceName, ConfigurationId, IsCompliant // Select relevant fields for output
//Summary Data
//| summarize DeviceCount = count(), CompliantSystems = countif(IsCompliant == 1), NonCompliantSystems = countif(IsCompliant == 0) by ConfigurationId
//| sort by ConfigurationId asc
//Detailed Device Info
//| summarize DefenderOn = countif(ConfigurationId == 'scid-2010' and IsCompliant == 1), Updates = countif(ConfigurationId == 'scid-2011' and IsCompliant == 1) by DeviceId
```

### Safeguard 10.2 Configure Automatic Anti-Malware Signature Updates

**About:**
Script to summarize a count of current and 'out of date' systems from Defender

```kql
DeviceTvmInfoGathering
| where DeviceName has_any ("domain.01", "domain.02") // Target Domains - comment out for agencies in their own tenant
| extend DataRefreshTimestamp = Timestamp,    
AvIsPlatformUpToDateTemp = tostring(AdditionalFields.AvIsPlatformUptodate),
AvSignatureDataRefreshTime = todatetime(AdditionalFields.AvSignatureDataRefreshTime), 
AvSignaturePublishTime = todatetime(AdditionalFields.AvSignaturePublishTime),
AvPlatformVersion = tostring(AdditionalFields.AvPlatformVersion) 
| extend AvPlatformVersion = iif(AvPlatformVersion == "", "Unknown", AvPlatformVersion)
| project DeviceId, DeviceName, OSPlatform, AvPlatformVersion, DataRefreshTimestamp, AvSignaturePublishTime, AvSignatureDataRefreshTime
| summarize DeviceCount = count(), DataRefreshTimestamp = max(DataRefreshTimestamp), PlatformUpToDateDeviceCount = countif(datetime_diff('hour',AvSignatureDataRefreshTime,AvSignaturePublishTime) <= 24),  PlatformNotUpToDateDeviceCount = countif(datetime_diff('hour',AvSignatureDataRefreshTime,AvSignaturePublishTime) > 24), NoData = countif(isnull(AvSignaturePublishTime)) by OSPlatform,AvPlatformVersion
```

### Safeguard 10.3 Disable Autorun and Autoplay for Removable Media

**About:**
Script to summarize a count of systems with autoplay disabled for non-volume devices (SCID 67)

```kql
DeviceTvmSecureConfigurationAssessment
| where DeviceName has_any ("domain.01", "domain.02") // Target Domains - comment out for agencies in their own tenant
| where ConfigurationId == 'scid-67' // Limit results to Configuration ID "Disable 'Autoplay for non-volume devices'"
| where IsApplicable == 1 // Limit results to systems for which the configuration is applicable
| project DeviceId, DeviceName, ConfigurationId, IsCompliant // Select relevant fields for output
| summarize DeviceId = count(), CompliantSystems = countif(IsCompliant == 1), NonCompliantSystems = countif(IsCompliant == 0)
```

## CIS Control #11: Data Recovery

### Safeguard 11.2 Perform Automated Backups

**About:**
Script to summarize a count of systems with CommVault Agent installed

```kql
DeviceTvmSoftwareInventory
| where DeviceName has_any ("domain.01", "domain.02") // Target Domains - comment out for agencies in their own tenant
| where SoftwareVendor contains "commvault" // Evaluate for the presence of CommVault software
| project DeviceId, DeviceName, OSPlatform, OSVersion, SoftwareVendor, SoftwareName, SoftwareVersion // Select relevant fields for output
| sort by OSPlatform asc, SoftwareVendor asc, SoftwareName asc, SoftwareVersion asc // Multi-column sort
```

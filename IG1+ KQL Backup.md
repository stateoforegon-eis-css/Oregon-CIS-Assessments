# **CIS v8.0 Controls Assessment Specification Defender Measurement Scripts**

## CIS Control #1: Inventory and Control of Enterprise Assets

### Safeguard 1.1 Establish and Maintain a Detailed Asset Inventory (Updated)

```kql
declare query_parameters (Acronym1:string = "ABCD", Acronym2:string = "WXYZ");
DeviceInfo
| where Timestamp > ago(90d) // Filter for events within the last 90 days
| where MachineGroup has_any (Acronym1, Acronym2)
or RegistryDeviceTag has_any (Acronym1, Acronym2)
or DeviceDynamicTags has_any (Acronym1, Acronym2)
or DeviceManualTags has_any (Acronym1, Acronym2)
| summarize
    FirstSeen = min(Timestamp), // Get the first event timestamp
    LastSeen = max(Timestamp)   // Get the last event timestamp
by DeviceName, MachineGroup, RegistryDeviceTag // Group by DeviceId and DeviceName
| project DeviceName, MachineGroup, RegistryDeviceTag, FirstSeen, LastSeen // Select relevant fields for output
| summarize arg_max(LastSeen, *) by DeviceName // De-duplicate results to a single row for each DeviceName based on the most recent record
| sort by DeviceName asc // Sort device list
```

## CIS Control #2: Inventory and Control of Software Assets

### Covered Vendor Compliance (Updated)

```kql
declare query_parameters (Acronym1:string = "ABCD", Acronym2:string = "WXYZ");
DeviceInfo
| where Timestamp > ago(90d) // Filter for events within the last 90 days
| where MachineGroup has_any (Acronym1, Acronym2)
or RegistryDeviceTag has_any (Acronym1, Acronym2)
or DeviceDynamicTags has_any (Acronym1, Acronym2)
or DeviceManualTags has_any (Acronym1, Acronym2)
| project Timestamp, DeviceId, DeviceName, MachineGroup, RegistryDeviceTag
| summarize arg_max(Timestamp, *) by DeviceName
| join kind = leftouter (DeviceTvmSoftwareInventory) on DeviceName
| where Timestamp > ago(90d) // Filter for events within the last 90 days
| where SoftwareVendor has_any ("Ant Group", "ByteDance", "DeepSeek", "Huawei", "Kaspersky", "Tencent", "ZTE", "Hytera", "Hangzhou", "Hikvision", "Dahua", "China", "ComNet") // Covered Vendors
| project DeviceName, SoftwareVendor, SoftwareName, SoftwareVersion // Select relevant fields for output
| sort by SoftwareVendor asc, SoftwareName asc, SoftwareVersion asc // Multi-column sort
```

### Safeguard 2.2 Ensure Authorized Software is Currently Supported (Updated)

```kql
declare query_parameters (Acronym1:string = "ABCD", Acronym2:string = "WXYZ");
DeviceInfo
| where Timestamp > ago(90d) // Filter for events within the last 90 days
| where MachineGroup has_any (Acronym1, Acronym2)
or RegistryDeviceTag has_any (Acronym1, Acronym2)
or DeviceDynamicTags has_any (Acronym1, Acronym2)
or DeviceManualTags has_any (Acronym1, Acronym2)
| project Timestamp, DeviceId, DeviceName, MachineGroup, RegistryDeviceTag
| summarize arg_max(Timestamp, *) by DeviceName
| join kind = leftouter (DeviceTvmSoftwareInventory) on DeviceName
| where Timestamp > ago(90d) // Filter for events within the last 90 days
| where isnotempty(EndOfSupportStatus)
| project DeviceName, MachineGroup, RegistryDeviceTag, SoftwareVendor, SoftwareName, SoftwareVersion, EndOfSupportStatus, EndOfSupportDate // Select relevant fields for output
//| summarize DeviceName = count() by MachineGroup, RegistryDeviceTag, SoftwareVendor, SoftwareName, SoftwareVersion, EndOfSupportStatus, EndOfSupportDate // Summarize by Software info
| summarize DeviceName = count() by SoftwareVendor, SoftwareName, SoftwareVersion, EndOfSupportStatus, EndOfSupportDate // Summarize by Software info
| sort by SoftwareVendor asc, SoftwareName asc, SoftwareVersion asc // Multi-column sort
```

### Safeguard 2.3 Software Present on Enterprise Assets (Updated)

```kql
declare query_parameters (Acronym1:string = "ABCD", Acronym2:string = "WXYZ");
DeviceInfo
| where Timestamp > ago(90d) // Filter for events within the last 90 days
| where MachineGroup has_any (Acronym1, Acronym2)
or RegistryDeviceTag has_any (Acronym1, Acronym2)
or DeviceDynamicTags has_any (Acronym1, Acronym2)
or DeviceManualTags has_any (Acronym1, Acronym2)
| project Timestamp, DeviceId, DeviceName, MachineGroup, RegistryDeviceTag
| summarize arg_max(Timestamp, *) by DeviceName
| join kind = leftouter (DeviceTvmSoftwareInventory) on DeviceName
| where Timestamp > ago(90d) // Filter for events within the last 90 days
| where ProductCodeCpe !contains "Not Available"
| project ProductCodeCpe, DeviceName
| extend firstDelimiterPos = indexof(ProductCodeCpe, ":")
| extend secondDelimiterPos = indexof(ProductCodeCpe, ":", firstDelimiterPos + 1)
| extend Product = iif(secondDelimiterPos != -1, substring(ProductCodeCpe, 0, secondDelimiterPos), ProductCodeCpe)
//| summarize DeviceName = count() by Product, MachineGroup, RegistryDeviceTag // Summarize by Software info
| summarize DeviceName = count() by Product // Summarize by Software info
| sort by Product asc // Sort software list
```

## CIS Control #3: Data Protection

### Safeguard 3.6 Encrypt Data on End-User Devices (updated)

```kql
declare query_parameters (Acronym1:string = "DOR", Acronym2:string = "DOR");
DeviceInfo
| where Timestamp > ago(90d) // Filter for events within the last 90 days
| where MachineGroup has_any (Acronym1, Acronym2)
or RegistryDeviceTag has_any (Acronym1, Acronym2)
or DeviceDynamicTags has_any (Acronym1, Acronym2)
or DeviceManualTags has_any (Acronym1, Acronym2)
| project Timestamp, DeviceId, DeviceName, MachineGroup, RegistryDeviceTag
| summarize arg_max(Timestamp, *) by DeviceName
| join kind = leftouter (DeviceTvmSecureConfigurationAssessment) on DeviceName
| where Timestamp > ago(90d) // Filter for events within the last 90 days
| where ConfigurationId == 'scid-2090' // Limit results to Configuration ID "Encrypt all BitLocker-supported drives"
| where IsApplicable == 1 // Limit results to systems for which the configuration is applicable
//| summarize BitlockerOn = countif(ConfigurationId == 'scid-2090' and IsCompliant == 1) by DeviceName, MachineGroup, RegistryDeviceTag // Select relevant fields for output
| summarize BitlockerOn = countif(ConfigurationId == 'scid-2090' and IsCompliant == 1) by DeviceName // Select relevant fields for output
| sort by DeviceName asc
```

### Safeguard 3.12 Segment Data Processing and Storage Based on Sensitivity (Updated)

```kql
declare query_parameters (Acronym1:string = "ABCD", Acronym2:string = "WXYZ");
DeviceInfo
| where Timestamp > ago(90d) // Filter for events within the last 90 days
| where MachineGroup has_any (Acronym1, Acronym2)
or RegistryDeviceTag has_any (Acronym1, Acronym2)
or DeviceDynamicTags has_any (Acronym1, Acronym2)
or DeviceManualTags has_any (Acronym1, Acronym2)
| project Timestamp, DeviceId, DeviceName, MachineGroup, RegistryDeviceTag
| summarize arg_max(Timestamp, *) by DeviceName
| join kind = leftouter (DeviceFileEvents) on DeviceName
| where Timestamp > ago(90d) // Filter for events within the last 90 days
| where FileName has_any ("social security", "ssn", "passport", "birth")
| where ActionType != "FileDeleted"
| where FileName !endswith ".lnk"
//| project DeviceName, MachineGroup, RegistryDeviceTag, ActionType, FolderPath, FileName
| project DeviceName, ActionType, FolderPath, FileName, Timestamp1
| sort by DeviceName asc, FileName asc, ActionType asc // Multi-column sort
```

## CIS Control #4: Secure Configuration of Enterprise Assets and Software

### Safeguard 4.3 Configure Automatic Session Locking on Enterprise Assets (Updated)

```kql
declare query_parameters (Acronym1:string = "ABCD", Acronym2:string = "WXYZ");
DeviceInfo
| where Timestamp > ago(90d) // Filter for events within the last 90 days
| where MachineGroup has_any (Acronym1, Acronym2)
or RegistryDeviceTag has_any (Acronym1, Acronym2)
or DeviceDynamicTags has_any (Acronym1, Acronym2)
or DeviceManualTags has_any (Acronym1, Acronym2)
| project Timestamp, DeviceId, DeviceName, MachineGroup, RegistryDeviceTag
| summarize arg_max(Timestamp, *) by DeviceName
| join kind = leftouter (DeviceTvmSecureConfigurationAssessment) on DeviceName
| where Timestamp > ago(90d) // Filter for events within the last 90 days
| where ConfigurationId == 'scid-28' // Limit results to Configuration ID "Set 'Interactive logon: Machine inactivity limit' to '1-900 seconds'"
| where IsApplicable == 1 // Limit results to systems for which the configuration is applicable
//| summarize 15MinLock = countif(ConfigurationId == 'scid-28' and IsCompliant == 1) by DeviceName, MachineGroup, RegistryDeviceTag // Select relevant fields for output
| summarize 15MinLock = countif(ConfigurationId == 'scid-28' and IsCompliant == 1) by DeviceName // Select relevant fields for output
| sort by DeviceName asc // Sort device list
```

### Safeguard 4.4 Implement and Manage a Firewall on Servers (Updated)

```kql
declare query_parameters (Acronym1:string = "ABCD", Acronym2:string = "WXYZ");
DeviceInfo
| where Timestamp > ago(90d) // Filter for events within the last 90 days
| where OSPlatform contains "server"
| where MachineGroup has_any (Acronym1, Acronym2)
or RegistryDeviceTag has_any (Acronym1, Acronym2)
or DeviceDynamicTags has_any (Acronym1, Acronym2)
or DeviceManualTags has_any (Acronym1, Acronym2)
| project Timestamp, DeviceId, DeviceName, MachineGroup, RegistryDeviceTag
| summarize arg_max(Timestamp, *) by DeviceName
| join kind = leftouter (DeviceTvmSecureConfigurationAssessment) on DeviceName
| where Timestamp > ago(90d) // Filter for events within the last 90 days
| where ConfigurationId == 'scid-2070' // Limit results to Configuration ID "Turn on Microsoft Defender Firewall"
| where IsApplicable == 1 // Limit results to systems for which the configuration is applicable
//| summarize FirewallOn = countif(ConfigurationId == 'scid-2070' and IsCompliant == 1) by DeviceName, MachineGroup, RegistryDeviceTag // Select relevant fields for output
| summarize FirewallOn = countif(ConfigurationId == 'scid-2070' and IsCompliant == 1) by DeviceName // Select relevant fields for output
| sort by DeviceName asc // Sort device list
```

### Safeguard 4.5 Implement and Manage a Firewall on End-User Devices (Updated)

```kql
declare query_parameters (Acronym1:string = "ABCD", Acronym2:string = "WXYZ");
DeviceInfo
| where Timestamp > ago(90d) // Filter for events within the last 90 days
| where OSPlatform !contains "server"
| where MachineGroup has_any (Acronym1, Acronym2)
or RegistryDeviceTag has_any (Acronym1, Acronym2)
or DeviceDynamicTags has_any (Acronym1, Acronym2)
or DeviceManualTags has_any (Acronym1, Acronym2)
| project Timestamp, DeviceId, DeviceName, MachineGroup, RegistryDeviceTag
| summarize arg_max(Timestamp, *) by DeviceName
| join kind = leftouter (DeviceTvmSecureConfigurationAssessment) on DeviceName
| where Timestamp > ago(90d) // Filter for events within the last 90 days
| where ConfigurationId == 'scid-2070' // Limit results to Configuration ID "Turn on Microsoft Defender Firewall"
| where IsApplicable == 1 // Limit results to systems for which the configuration is applicable
//| summarize FirewallOn = countif(ConfigurationId == 'scid-2070' and IsCompliant == 1) by DeviceName, MachineGroup, RegistryDeviceTag // Select relevant fields for output
| summarize FirewallOn = countif(ConfigurationId == 'scid-2070' and IsCompliant == 1) by DeviceName // Select relevant fields for output
| sort by DeviceName asc // Sort device list
```

### Safeguard 4.7 Manage Default Accounts on Enterprise Assets and Software (Updated)

```kql
declare query_parameters (Acronym1:string = "ABCD", Acronym2:string = "WXYZ");
DeviceInfo
| where Timestamp > ago(90d) // Filter for events within the last 90 days
| where MachineGroup has_any (Acronym1, Acronym2)
or RegistryDeviceTag has_any (Acronym1, Acronym2)
or DeviceDynamicTags has_any (Acronym1, Acronym2)
or DeviceManualTags has_any (Acronym1, Acronym2)
| project Timestamp, DeviceId, DeviceName, MachineGroup, RegistryDeviceTag
| summarize arg_max(Timestamp, *) by DeviceName
| join kind = leftouter (DeviceTvmSecureConfigurationAssessment) on DeviceName
| where Timestamp > ago(90d) // Filter for events within the last 90 days
| where ConfigurationId == 'scid-3010' // Limit results to Configuration ID "Disable the built-in Administrator account"
or ConfigurationId == 'scid-3011' // Limit results to Configuration ID "Disable the built-in Guest account" 
| where IsApplicable == 1 // Limit results to systems for which the configuration is applicable
| summarize AdminAcct = countif(ConfigurationId == 'scid-3010' and IsCompliant == 1), GuestAcct = countif(ConfigurationId == 'scid-3011' and IsCompliant == 1) by DeviceName, MachineGroup, RegistryDeviceTag
| join kind = leftouter (
DeviceEvents
| where Timestamp > ago(90d) // Filter for events within the last 90 days
| where InitiatingProcessFileName contains "lsass.exe" and AdditionalFields has "LAPS"
| extend LAPS = iff(AdditionalFields has "LAPS", 1, 0)
| summarize arg_max(Timestamp, LAPS) by DeviceName)
on DeviceName
//| project DeviceName, MachineGroup, RegistryDeviceTag, GuestAcct, AdminAcct, LAPS
| project DeviceName, GuestAcct, AdminAcct, LAPS
| sort by DeviceName asc // Sort device list
```

## CIS Control #5: Account Management

### Safeguard 5.2 Use Unique Passwords (Updated)

```kql
declare query_parameters (Acronym1:string = "ABCD", Acronym2:string = "WXYZ");
DeviceInfo
| where Timestamp > ago(90d) // Filter for events within the last 90 days
| where MachineGroup has_any (Acronym1, Acronym2)
or RegistryDeviceTag has_any (Acronym1, Acronym2)
or DeviceDynamicTags has_any (Acronym1, Acronym2)
or DeviceManualTags has_any (Acronym1, Acronym2)
| project Timestamp, DeviceId, DeviceName, MachineGroup, RegistryDeviceTag
| summarize arg_max(Timestamp, *) by DeviceName
| join kind = leftouter (DeviceTvmSecureConfigurationAssessment) on DeviceName
| where Timestamp > ago(90d) // Filter for events within the last 90 days
| where ConfigurationId == 'scid-32' // Limit results to Configuration ID "Set 'Minimum password length' to '14 or more characters'"
or ConfigurationId == 'scid-33' // Limit results to Configuration ID "Set 'Enforce password history' to '24 or more password(s)'"
or ConfigurationId == 'scid-34' // Limit results to Configuration ID "Set 'Maximum password age' to '60 or fewer days, but not 0'"
or ConfigurationId == 'scid-35' // Limit results to Configuration ID "Set 'Minimum password age' to '1 or more day(s)'"
| where IsApplicable == 1 // Limit results to systems for which the configuration is applicable
//| summarize Length14 = countif(ConfigurationId == 'scid-32' and IsCompliant == 1), Hist24 = countif(ConfigurationId == 'scid-33' and IsCompliant == 1), Max60 = countif(ConfigurationId == 'scid-34' and IsCompliant == 1), Min01 = countif(ConfigurationId == 'scid-35' and IsCompliant == 1) by DeviceName, MachineGroup, RegistryDeviceTag
| summarize Length14 = countif(ConfigurationId == 'scid-32' and IsCompliant == 1), Hist24 = countif(ConfigurationId == 'scid-33' and IsCompliant == 1), Max60 = countif(ConfigurationId == 'scid-34' and IsCompliant == 1), Min01 = countif(ConfigurationId == 'scid-35' and IsCompliant == 1) by DeviceName
| sort by DeviceName asc // Sort device list
```

### Safeguard 5.4 Restrict Administrator Privileges to Dedicated Administrator Accounts (Updated)

```kql
declare query_parameters (Acronym1:string = "ABCD", Acronym2:string = "WXYZ");
DeviceInfo
| where Timestamp > ago(90d) // Filter for events within the last 90 days
| where MachineGroup has_any (Acronym1, Acronym2)
or RegistryDeviceTag has_any (Acronym1, Acronym2)
or DeviceDynamicTags has_any (Acronym1, Acronym2)
or DeviceManualTags has_any (Acronym1, Acronym2)
| project Timestamp, DeviceId, DeviceName, MachineGroup, RegistryDeviceTag
| summarize arg_max(Timestamp, *) by DeviceName
| join kind = leftouter (DeviceLogonEvents) on DeviceName
| where Timestamp > ago(90d) // Filter for events within the last 90 days
| where LogonType == "Interactive"
or LogonType == "RemoteInteractive"
| where AccountName !contains "lenovo" // Filter to remove local administrators created during OS setup
| where IsLocalAdmin == 1 
| join kind = leftouter (
    IdentityInfo
    | project AccountName, AccountDisplayName) on AccountName // Extract display name from Idenity Info and link to Account Name
| project DeviceName, MachineGroup, RegistryDeviceTag, AccountName, AccountDisplayName, IsLocalAdmin // Select relevant fields for output
//| extend Device = strcat(DeviceName,"|",MachineGroup,"|",RegistryDeviceTag)
| extend Device = strcat(DeviceName,"|",MachineGroup)
| summarize
    ['Local Admin Distinct Device Count']=dcountif(Device, IsLocalAdmin == "true"),
    ['Local Admin Device List']=make_set_if(Device, IsLocalAdmin == "true") // Consolidate list of devices into a single field
    by AccountName, AccountDisplayName // Admin User List
| sort by AccountName asc // Sort by Account Name
```

## CIS Control #7: Continuous Vulnerability Management

### Safeguard 7.3 Perform Automated Operating System Patch Management (Updated)

```kql
declare query_parameters (Acronym1:string = "ABCD", Acronym2:string = "WXYZ");
DeviceInfo
| where Timestamp > ago(90d) // Filter for events within the last 90 days
| where MachineGroup has_any (Acronym1, Acronym2)
or RegistryDeviceTag has_any (Acronym1, Acronym2)
or DeviceDynamicTags has_any (Acronym1, Acronym2)
or DeviceManualTags has_any (Acronym1, Acronym2)
| project Timestamp, DeviceId, DeviceName, MachineGroup, RegistryDeviceTag
| summarize arg_max(Timestamp, *) by DeviceName
| join kind = leftouter (DeviceTvmSoftwareInventory) on DeviceName
| where Timestamp > ago(90d) // Filter for events within the last 90 days
| where SoftwareName has_any ("windows_10", "windows_11", "windows_server_2016",  "windows_server_2019", "windows_server_2022", "windows_server_2025") // limit results to Windows operating systems
//| distinct Device=strcat(DeviceName,"|",MachineGroup,"|",RegistryDeviceTag), OperatingSystem=strcat(SoftwareVendor, ': ',SoftwareName,'-',SoftwareVersion) // Select relevant fields for output
| distinct Device=DeviceName, OperatingSystem=strcat(SoftwareVendor, ': ',SoftwareName,'-',SoftwareVersion) // Select relevant fields for output
| join kind = leftouter (
DeviceTvmSoftwareVulnerabilities
| join kind = leftouter (
    DeviceTvmSoftwareVulnerabilitiesKB)
      on CveId // Extract published date from KB and link to Software Name
| where PublishedDate < ago(30d)
| project CveId, OperatingSystem=strcat(SoftwareVendor, ': ',SoftwareName,'-',SoftwareVersion)
| summarize CVEPatchList=make_set(CveId) by OperatingSystem) // Summarize all CVE records to a single field
 on OperatingSystem
| summarize
    DeviceCount=dcount(Device)
    by OperatingSystem, tostring(CVEPatchList)
| sort by OperatingSystem asc // Sort OperatingSystem list
```

### Safeguard 7.4 Perform Automated Application Patch Management (Updated)

```kql
declare query_parameters (Acronym1:string = "ABCD", Acronym2:string = "WXYZ");
DeviceInfo
| where Timestamp > ago(90d) // Filter for events within the last 90 days
| where MachineGroup has_any (Acronym1, Acronym2)
or RegistryDeviceTag has_any (Acronym1, Acronym2)
or DeviceDynamicTags has_any (Acronym1, Acronym2)
or DeviceManualTags has_any (Acronym1, Acronym2)
| project Timestamp, DeviceId, DeviceName, MachineGroup, RegistryDeviceTag
| summarize arg_max(Timestamp, *) by DeviceName
| join kind = leftouter (DeviceTvmSoftwareInventory) on DeviceName
| where Timestamp > ago(90d) // Filter for events within the last 90 days
| where not (SoftwareName has_any ("windows_10", "windows_11", "windows_server_2016",  "windows_server_2019", "windows_server_2022", "windows_server_2025")) // limit results to Windows operating systems
//| distinct Device=strcat(DeviceName,"|",MachineGroup,"|",RegistryDeviceTag), Software=strcat(SoftwareVendor, ': ',SoftwareName,'-',SoftwareVersion) // Select relevant fields for output
| distinct Device=DeviceName, Software=strcat(SoftwareVendor, ': ',SoftwareName,'-',SoftwareVersion) // Select relevant fields for output
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
    DeviceCount=dcount(Device)
    by Software, tostring(CVEPatchList)
| sort by Software asc // Sort software list
```

## CIS Control #9: Email and Web Browser Protections

### Safeguard 9.1 Ensure Use of Only Fully Supported Browsers and Email Clients (Updated)

By Device

```kql
declare query_parameters (Acronym1:string = "ABCD", Acronym2:string = "WXYZ");
DeviceInfo
| where Timestamp > ago(90d) // Filter for events within the last 90 days
| where MachineGroup has_any (Acronym1, Acronym2)
or RegistryDeviceTag has_any (Acronym1, Acronym2)
or DeviceDynamicTags has_any (Acronym1, Acronym2)
or DeviceManualTags has_any (Acronym1, Acronym2)
| project Timestamp, DeviceId, DeviceName, MachineGroup, RegistryDeviceTag
| summarize arg_max(Timestamp, *) by DeviceName
| join kind = leftouter (DeviceTvmSoftwareInventory) on DeviceName
| where Timestamp > ago(90d) // Filter for events within the last 90 days
| where isnotempty(EndOfSupportStatus)
| where SoftwareName has_any ("Brave", "Chrome", "Chromium", "Edge", "Firefox", "IE", "Mozilla", "Opera", "PaleMoon", "Safari", "SeaMonkey", "Vivaldi", "Waterfox") //Search for Browsers
or SoftwareName has_any ("Apple Mail", "Claws Mail", "eM Client", "Evolution", "Kmail", "Mailbird", "Mailspring", "Office", "Outlook", "Postbox", "Sylpheed", "Thunderbird",  "Windows Mail") //Search for Email Clients
//| project DeviceName, MachineGroup, RegistryDeviceTag, SoftwareVendor, SoftwareName, SoftwareVersion, EndOfSupportStatus, EndOfSupportDate // Select relevant fields for output
| project DeviceName, SoftwareVendor, SoftwareName, SoftwareVersion, EndOfSupportStatus, EndOfSupportDate // Select relevant fields for output
| sort by DeviceName asc // Multi-column sort
```

By Software

```kql
declare query_parameters (Acronym1:string = "ABCD", Acronym2:string = "WXYZ");
DeviceInfo
| where Timestamp > ago(90d) // Filter for events within the last 90 days
| where MachineGroup has_any (Acronym1, Acronym2)
or RegistryDeviceTag has_any (Acronym1, Acronym2)
or DeviceDynamicTags has_any (Acronym1, Acronym2)
or DeviceManualTags has_any (Acronym1, Acronym2)
| project Timestamp, DeviceId, DeviceName, MachineGroup, RegistryDeviceTag
| summarize arg_max(Timestamp, *) by DeviceName
| join kind = leftouter (DeviceTvmSoftwareInventory) on DeviceName
| where Timestamp > ago(90d) // Filter for events within the last 90 days
| where isnotempty(EndOfSupportStatus)
| where SoftwareName has_any ("Brave", "Chrome", "Chromium", "Edge", "Firefox", "IE", "Mozilla", "Opera", "PaleMoon", "Safari", "SeaMonkey", "Vivaldi", "Waterfox") //Search for Browsers
or SoftwareName has_any ("Apple Mail", "Claws Mail", "eM Client", "Evolution", "Kmail", "Mailbird", "Mailspring", "Office", "Outlook", "Postbox", "Sylpheed", "Thunderbird",  "Windows Mail") //Search for Email Clients
//| project DeviceName, MachineGroup, RegistryDeviceTag, SoftwareVendor, SoftwareName, SoftwareVersion, EndOfSupportStatus, EndOfSupportDate // Select relevant fields for output
| project DeviceName, SoftwareVendor, SoftwareName, SoftwareVersion, EndOfSupportStatus, EndOfSupportDate // Select relevant fields for output
| summarize DeviceName = count() by SoftwareVendor, SoftwareName, SoftwareVersion, EndOfSupportStatus, EndOfSupportDate // Summarize by Software info
| sort by SoftwareVendor asc, SoftwareName asc, SoftwareVersion asc // Multi-column sort
```

### Safeguard 9.2 Use DNS Filtering Services (Updated)

```kql
declare query_parameters (Acronym1:string = "ABCD", Acronym2:string = "WXYZ");
DeviceInfo
| where Timestamp > ago(90d) // Filter for events within the last 90 days
| where MachineGroup has_any (Acronym1, Acronym2)
or RegistryDeviceTag has_any (Acronym1, Acronym2)
or DeviceDynamicTags has_any (Acronym1, Acronym2)
or DeviceManualTags has_any (Acronym1, Acronym2)
| project Timestamp, DeviceId, DeviceName, MachineGroup, RegistryDeviceTag
| summarize arg_max(Timestamp, *) by DeviceName
| join kind = leftouter (DeviceNetworkInfo) on DeviceName
| where Timestamp > ago(90d) // Filter for events within the last 90 days
| where NetworkAdapterStatus == "Up"
| where DnsAddresses != ""
//| summarize AllDns = make_set(DnsAddresses) by DeviceName, MachineGroup, RegistryDeviceTag
//| project DeviceName, MachineGroup, RegistryDeviceTag, AllDns
| summarize AllDns = make_set(DnsAddresses) by DeviceName
| project DeviceName, AllDns
| sort by DeviceName asc
```

## CIS Control #10: Malware Defenses

### Safeguard 10.1 Deploy and Maintain Anti-Malware Software (Updated)

```kql
declare query_parameters (Acronym1:string = "ABCD", Acronym2:string = "WXYZ");
DeviceInfo
| where Timestamp > ago(90d) // Filter for events within the last 90 days
| where MachineGroup has_any (Acronym1, Acronym2)
or RegistryDeviceTag has_any (Acronym1, Acronym2)
or DeviceDynamicTags has_any (Acronym1, Acronym2)
or DeviceManualTags has_any (Acronym1, Acronym2)
| project Timestamp, DeviceId, DeviceName, MachineGroup, RegistryDeviceTag
| summarize arg_max(Timestamp, *) by DeviceName
| join kind = leftouter (DeviceTvmSecureConfigurationAssessment) on DeviceName
| where Timestamp > ago(90d) // Filter for events within the last 90 days
| where ConfigurationId == 'scid-2010' // Limit results to Configuration ID "Turn on Microsoft defender Antivirus"
or ConfigurationId == 'scid-2011' // Limit results to Configuration ID "Update Microsoft Defender Antivirus definitions"
| where IsApplicable == 1 // Limit results to systems for which the configuration is applicable
//| summarize DefenderOn = countif(ConfigurationId == 'scid-2010' and IsCompliant == 1), UpdatesOn = countif(ConfigurationId == 'scid-2011' and IsCompliant == 1) by DeviceName, MachineGroup, RegistryDeviceTag
| summarize DefenderOn = countif(ConfigurationId == 'scid-2010' and IsCompliant == 1), UpdatesOn = countif(ConfigurationId == 'scid-2011' and IsCompliant == 1) by DeviceName
| sort by DeviceName asc // Sort device list
```

### Safeguard 10.2 Configure Automatic Anti-Malware Signature Updates (Updated)

```kql
declare query_parameters (Acronym1:string = "ABCD", Acronym2:string = "WXYZ");
DeviceInfo
| where Timestamp > ago(90d) // Filter for events within the last 90 days
| where MachineGroup has_any (Acronym1, Acronym2)
or RegistryDeviceTag has_any (Acronym1, Acronym2)
or DeviceDynamicTags has_any (Acronym1, Acronym2)
or DeviceManualTags has_any (Acronym1, Acronym2)
| project Timestamp, DeviceId, DeviceName, MachineGroup, RegistryDeviceTag
| summarize arg_max(Timestamp, *) by DeviceName
| join kind = leftouter (DeviceTvmInfoGathering) on DeviceName
| where Timestamp > ago(90d) // Filter for events within the last 90 days
| extend DataRefreshTimestamp = Timestamp,    
AvIsPlatformUpToDateTemp = tostring(AdditionalFields.AvIsPlatformUptodate),
AvSignatureDataRefreshTime = todatetime(AdditionalFields.AvSignatureDataRefreshTime), 
AvSignaturePublishTime = todatetime(AdditionalFields.AvSignaturePublishTime),
AvPlatformVersion = tostring(AdditionalFields.AvPlatformVersion) 
| extend AvPlatformVersion = iif(AvPlatformVersion == "", "Unknown", AvPlatformVersion)
| summarize arg_max (Timestamp, *) by DeviceName
//| summarize DataRefreshTimestamp = max(DataRefreshTimestamp), PlatformUpToDate = countif(datetime_diff('hour',AvSignatureDataRefreshTime,AvSignaturePublishTime) <= 24), NoData = countif(isnull(AvSignaturePublishTime)) by DeviceName, MachineGroup, RegistryDeviceTag, AvPlatformVersion
| summarize DataRefreshTimestamp = max(DataRefreshTimestamp), PlatformUpToDate = countif(datetime_diff('hour',AvSignatureDataRefreshTime,AvSignaturePublishTime) <= 24), NoData = countif(isnull(AvSignaturePublishTime)) by DeviceName, AvPlatformVersion
| sort by DeviceName asc // Sort device list
```

### Safeguard 10.3 Disable Autorun and Autoplay for Removable Media (Updated)

```kql
declare query_parameters (Acronym1:string = "ABCD", Acronym2:string = "WXYZ");
DeviceInfo
| where Timestamp > ago(90d) // Filter for events within the last 90 days
| where MachineGroup has_any (Acronym1, Acronym2)
or RegistryDeviceTag has_any (Acronym1, Acronym2)
or DeviceDynamicTags has_any (Acronym1, Acronym2)
or DeviceManualTags has_any (Acronym1, Acronym2)
| project Timestamp, DeviceId, DeviceName, MachineGroup, RegistryDeviceTag
| summarize arg_max(Timestamp, *) by DeviceName
| join kind = leftouter (DeviceTvmSecureConfigurationAssessment) on DeviceName
| where Timestamp > ago(90d) // Filter for events within the last 90 days
| where ConfigurationId == 'scid-67' // Limit results to Configuration ID "Disable 'Autoplay for non-volume devices'"
| where IsApplicable == 1 // Limit results to systems for which the configuration is applicable
//| summarize AutoplayDisabled = countif(ConfigurationId == 'scid-67' and IsCompliant == 1) by DeviceName, MachineGroup, RegistryDeviceTag // Select relevant fields for output
| summarize AutoplayDisabled = countif(ConfigurationId == 'scid-67' and IsCompliant == 1) by DeviceName // Select relevant fields for output
| sort by DeviceName asc // Sort device list
```

## CIS Control #11: Data Recovery

### Safeguard 11.2 Perform Automated Backups (Updated)

```kql
declare query_parameters (Acronym1:string = "ABCD", Acronym2:string = "WXYZ");
DeviceInfo
| where Timestamp > ago(90d) // Filter for events within the last 90 days
| where MachineGroup has_any (Acronym1, Acronym2)
or RegistryDeviceTag has_any (Acronym1, Acronym2)
or DeviceDynamicTags has_any (Acronym1, Acronym2)
or DeviceManualTags has_any (Acronym1, Acronym2)
| project Timestamp, DeviceId, DeviceName, MachineGroup, RegistryDeviceTag
| summarize arg_max(Timestamp, *) by DeviceName
| join kind = leftouter (DeviceTvmSoftwareInventory) on DeviceName
| where Timestamp > ago(90d) // Filter for events within the last 90 days
| where SoftwareVendor contains "commvault" // Evaluate for the presence of CommVault software
| summarize arg_max(Timestamp, *) by DeviceName
//| distinct DeviceName, MachineGroup, RegistryDeviceTag, OSPlatform, OSVersion, SoftwareVendor, SoftwareName, SoftwareVersion // Select relevant fields for output
| distinct DeviceName, OSPlatform, OSVersion, SoftwareVendor, SoftwareName, SoftwareVersion // Select relevant fields for output
| sort by DeviceName asc // Sort device list
```

## Configuration Compliance Statistics

### Safeguards 3.6, 4.3, 4.4, 4.5, 4.7, 5.2, 10.1, 10.3 (Updated)

```kql
declare query_parameters (Acronym1:string = "ABCD", Acronym2:string = "WXYZ");
DeviceInfo
| where Timestamp > ago(90d) // Filter for events within the last 90 days
| where MachineGroup has_any (Acronym1, Acronym2)
or RegistryDeviceTag has_any (Acronym1, Acronym2)
or DeviceDynamicTags has_any (Acronym1, Acronym2)
or DeviceManualTags has_any (Acronym1, Acronym2)
| project Timestamp, DeviceId, DeviceName, MachineGroup, RegistryDeviceTag
| summarize arg_max(Timestamp, *) by DeviceName
| join kind = leftouter(DeviceTvmSecureConfigurationAssessment) on DeviceName
| where Timestamp > ago(90d) // Filter for events within the last 90 days
| where ConfigurationId == 'scid-2090' // Limit results to Configuration ID "Encrypt all BitLocker-supported drives"
or ConfigurationId == 'scid-28' // Limit results to Configuration ID "Set 'Interactive logon: Machine inactivity limit' to '1-900 seconds'"
or ConfigurationId == 'scid-2070' // Limit results to Configuration ID "Turn on Microsoft Defender Firewall"
or ConfigurationId == 'scid-3010' // Limit results to Configuration ID "Disable the built-in Administrator account"
or ConfigurationId == 'scid-3011' // Limit results to Configuration ID "Disable the built-in Guest account" 
or ConfigurationId == 'scid-32' // Limit results to Configuration ID "Set 'Minimum password length' to '14 or more characters'"
or ConfigurationId == 'scid-33' // Limit results to Configuration ID "Set 'Enforce password history' to '24 or more password(s)'"
or ConfigurationId == 'scid-34' // Limit results to Configuration ID "Set 'Maximum password age' to '60 or fewer days, but not 0'"
or ConfigurationId == 'scid-35' // Limit results to Configuration ID "Set 'Minimum password age' to '1 or more day(s)'"
or ConfigurationId == 'scid-2010' // Limit results to Configuration ID "Turn on Microsoft defender Antivirus"
or ConfigurationId == 'scid-2011' // Limit results to Configuration ID "Update Microsoft Defender Antivirus definitions"
or ConfigurationId == 'scid-67' // Limit results to Configuration ID "Disable 'Autoplay for non-volume devices'"
| where IsApplicable == 1
| extend ConfigurationId = case(
ConfigurationId == "scid-2090", "03.06 - Bitlocker Encryption Enabled",
ConfigurationId == "scid-28", "04.03 - Machine Inactivity Limit 1-900 seconds",
ConfigurationId == "scid-2070" and OSPlatform contains "server", "04.04 - Microsoft Defender Server Firewall Enabled",
ConfigurationId == "scid-2070" and OSPlatform !contains "server", "04.05 - Microsoft Defender Endpoint Firewall Enabled",
ConfigurationId == "scid-3010", "04.07a - Built In Administrator Account Disabled",
ConfigurationId == "scid-3011", "04.07b - Built In Guest Account Disabled", 
ConfigurationId == "scid-32", "05.02a - Minimum Password Length 14 or More Characters",
ConfigurationId == "scid-33", "05.02b - Password History 24 or More Passwords",
ConfigurationId == "scid-34", "05.02c - Maximum Password Age 60 or Fewer Days, but Not 0",
ConfigurationId == "scid-35", "05.02d - Minimum Password Age 1 or More Days",
ConfigurationId == "scid-2010", "10.01a - Microsoft Defender Antivirus On",
ConfigurationId == "scid-2011", "10.01b - Microsoft Defender Antivirus Definition Updates On",
"10.03 - Disable Autoplay for Non-Volume Devices")
| summarize DeviceCount = count(), CompliantSystems = countif(IsCompliant == 1), NonCompliantSystems = countif(IsCompliant == 0) by ConfigurationId
| sort by ConfigurationId asc
```

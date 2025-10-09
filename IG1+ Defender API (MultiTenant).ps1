[CmdletBinding()]

param (

  $TenantId,

  $ClientId,

  $ClientSecret,

  $Acronym1,

  $Acronym2

) #param

if (-not $PSBoundParameters.ContainsKey('TenantId')) {

  $TenantId = Read-Host 'Enter the Azure AD Tenant ID'

} #if

if (-not $PSBoundParameters.ContainsKey('ClientId')) {

  $ClientId = Read-Host 'Enter the App Client ID'

} #if

if (-not $PSBoundParameters.ContainsKey('ClientSecret')) {

  $ClientSecret = Read-Host -AsSecureString 'Enter the Client Secret'

} #if

if (-not $PSBoundParameters.ContainsKey('Acronym1')) {

  $Acronym1 = Read-Host 'Enter the agency acronym'

} #if

if (-not $PSBoundParameters.ContainsKey('Acronym2')) {

  $Answer = Read-Host 'Do you require an alternate agency acronym? (Y/N)'

  if ($Answer -match 'Y') {

    $Acronym2 = Read-Host 'Enter the alternate agency acronym'

  } elseif ($Answer -match 'N') {

    $Acronym2 = '---'

  } else {

    $Acronym2 = '---'

  } #if

} #if

Write-Verbose '# ===== Get token (GCC) ====='

$Body = @{
  client_id     = $ClientId
  client_secret = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($ClientSecret))
  scope         = "https://api-gcc.securitycenter.microsoft.us/.default"
  grant_type    = "client_credentials"
}

Write-Verbose '# ===== Token Response ====='

$TokenResp = Invoke-RestMethod -Method Post `
  -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" `
  -Body $Body -ContentType "application/x-www-form-urlencoded"

$DefenderAccessToken = $TokenResp.access_token

Write-Verbose '# ===== Advanced Hunting API (GCC) ====='

$HuntingUri = "https://api-gcc.securitycenter.microsoft.us/api/advancedqueries/run"

New-Item -ItemType Directory -Force -Path $PWD/Defender | Out-Null

Write-Verbose '# ===== Covered Vendor Compliance ====='

$KqlQuery = @'
declare query_parameters (Acronym1:string = "ACR1", Acronym2:string = "ACR2");
DeviceInfo
| where Timestamp > ago(90d)
| where MachineGroup has_any (Acronym1, Acronym2)
   or RegistryDeviceTag has_any (Acronym1, Acronym2)
   or DeviceDynamicTags has_any (Acronym1, Acronym2)
   or DeviceManualTags has_any (Acronym1, Acronym2)
| project Timestamp, DeviceId, DeviceName, MachineGroup, RegistryDeviceTag
| summarize arg_max(Timestamp, *) by DeviceName
| join kind=leftouter (DeviceTvmSoftwareInventory) on DeviceName
| where Timestamp > ago(90d)
| where SoftwareVendor has_any ("Ant Group","ByteDance","DeepSeek","Huawei","Kaspersky","Tencent","ZTE","Hytera","Hangzhou","Hikvision","Dahua","China","ComNet")
| project DeviceName, SoftwareVendor, SoftwareName, SoftwareVersion
| sort by SoftwareVendor asc, SoftwareName asc, SoftwareVersion asc
'@.Replace('ACR1', $Acronym1).Replace('ACR2', $Acronym2)

$Headers = @{ Authorization = "Bearer $DefenderAccessToken" }
$Payload = @{ Query = $KqlQuery } | ConvertTo-Json -Depth 6

try {

  $Params = @{
    Method = "Post"
    Uri = $HuntingUri
    Headers = $Headers
    ContentType = "application/json"
    Body = $Payload
    ErrorAction = "Stop"
  }

  $Response = Invoke-RestMethod @Params

  $Results = $Response.Results

  if (-not $Results) {
  
    Write-Warning "No rows returned for Covered Vendor Compliance."
  
  } #if

  Write-Verbose '# ===== Export to CSV ====='
  $CsvPath = Join-Path $PWD/Defender "CoveredVendor.csv"
  $Results | Export-Csv -NoTypeInformation -Path $CsvPath
  Write-Host "Results exported to $CsvPath"

} catch {

  Write-Error ("Advanced Hunting call failed: {0}" -f $_.Exception.Message)

  if ($_.Exception.Response -and $_.Exception.Response.GetResponseStream) {
    $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
    $errBody = $reader.ReadToEnd()
    Write-Warning "Server response body: $errBody"
  }

} #try

####################
$SafeGuard = '01.01'
####################
Write-Verbose "# ===== Safeguard $SafeGuard ====="
$KqlQuery = @"
declare query_parameters (Acronym1:string = "ACR1", Acronym2:string = "ACR2");
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
"@.Replace('ACR1', $Acronym1).Replace('ACR2', $Acronym2)

$Headers = @{ Authorization = "Bearer $DefenderAccessToken" }
$Payload = @{ Query = $KqlQuery } | ConvertTo-Json

try {

  $Params = @{
    Method = "Post"
    Uri = $HuntingUri
    Headers = $Headers
    ContentType = "application/json"
    Body = $Payload
    ErrorAction = "Stop"
  }

  $Response = Invoke-RestMethod @Params

  $Results = $Response.Results

  if (-not $Results) {
    Write-Warning "No rows returned for Safeguard $SafeGuard."
  } #if

  Write-Verbose '# ===== Export results to CSV ====='
  $CsvPath = Join-Path $PWD/Defender "Safeguard_$SafeGuard.csv"
  $Results | Export-Csv -NoTypeInformation -Path $CsvPath
  Write-Verbose "Results exported to $CsvPath"
} catch {
  Write-Error ("Advanced Hunting call failed: {0}" -f $_.Exception.Message)
} #try

####################
$SafeGuard = '02.02'
####################
Write-Verbose "# ===== Safeguard $SafeGuard ====="
$KqlQuery = @"
declare query_parameters (Acronym1:string = "ACR1", Acronym2:string = "ACR2");
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
| summarize DeviceName = count() by SoftwareVendor, SoftwareName, SoftwareVersion, EndOfSupportStatus, EndOfSupportDate // Summarize by Software info
| sort by SoftwareVendor asc, SoftwareName asc, SoftwareVersion asc // Multi-column sort
"@.Replace('ACR1', $Acronym1).Replace('ACR2', $Acronym2)

$Headers = @{ Authorization = "Bearer $DefenderAccessToken" }
$Payload = @{ Query = $KqlQuery } | ConvertTo-Json

try {

  $Params = @{
    Method = "Post"
    Uri = $HuntingUri
    Headers = $Headers
    ContentType = "application/json"
    Body = $Payload
    ErrorAction = "Stop"
  }

  $Response = Invoke-RestMethod @Params

  $Results = $Response.Results

  if (-not $Results) {
    Write-Warning "No rows returned for Safeguard $SafeGuard."
  } #if

  Write-Verbose '# ===== Export to CSV ====='
  $CsvPath = Join-Path $PWD/Defender "Safeguard_$SafeGuard.csv"
  $Results | Export-Csv -NoTypeInformation -Path $CsvPath
  Write-Host "Results exported to $CsvPath"
} catch {
  Write-Error ("Advanced Hunting call failed: {0}" -f $_.Exception.Message)
} #try

####################
$SafeGuard = '02.03'
####################
Write-Verbose "# ===== Safeguard $SafeGuard ====="
$KqlQuery = @"
declare query_parameters (Acronym1:string = "ACR1", Acronym2:string = "ACR2");
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
| summarize DeviceName = count() by Product // Summarize by Software info
| sort by Product asc // Sort software list
"@.Replace('ACR1', $Acronym1).Replace('ACR2', $Acronym2)

$Headers = @{ Authorization = "Bearer $DefenderAccessToken" }
$Payload = @{ Query = $KqlQuery } | ConvertTo-Json

try {

  $Params = @{
    Method = "Post"
    Uri = $HuntingUri
    Headers = $Headers
    ContentType = "application/json"
    Body = $Payload
    ErrorAction = "Stop"
  }

  $Response = Invoke-RestMethod @Params

  $Results = $Response.Results

  if (-not $Results) {
    Write-Warning "No rows returned for Safeguard $SafeGuard."
  } #if

  Write-Verbose '# Remap the summarized column (DeviceName holds the count) to a clearer name'
  $shaped = $Results | Select-Object `
              @{Name='Product';      Expression={$_.'Product'}},
              @{Name='DeviceCount';  Expression={$_.'DeviceName'}}

Write-Verbose '# ===== Export to CSV ====='
  $CsvPath = Join-Path $PWD/Defender "Safeguard_$SafeGuard.csv"
  $shaped | Export-Csv -NoTypeInformation -Path $CsvPath
  Write-Host "Results exported to $CsvPath"
} catch {
  Write-Error ("Advanced Hunting call failed: {0}" -f $_.Exception.Message)
} #try

####################
$SafeGuard = '03.06'
####################
Write-Verbose "# ===== Safeguard $SafeGuard ====="
$KqlQuery = @"
declare query_parameters (Acronym1:string = "ACR1", Acronym2:string = "ACR2");
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
| summarize BitlockerOn = countif(ConfigurationId == 'scid-2090' and IsCompliant == 1), BitlockerOff = countif(ConfigurationId == 'scid-2090' and IsCompliant == 0) by DeviceName // Select relevant fields for output
| sort by DeviceName asc
"@.Replace('ACR1', $Acronym1).Replace('ACR2', $Acronym2)

$Headers = @{ Authorization = "Bearer $DefenderAccessToken" }
$Payload = @{ Query = $KqlQuery } | ConvertTo-Json

try {

  $Params = @{
    Method = "Post"
    Uri = $HuntingUri
    Headers = $Headers
    ContentType = "application/json"
    Body = $Payload
    ErrorAction = "Stop"
  }

  $Response = Invoke-RestMethod @Params

  $Results = $Response.Results
  
  if (-not $Results) {
    Write-Warning "No rows returned for Safeguard $SafeGuard."
  } #if

  Write-Verbose '# ===== Export to CSV ====='
  $CsvPath = Join-Path $PWD/Defender "Safeguard_$SafeGuard.csv"
  $Results | Export-Csv -NoTypeInformation -Path $CsvPath
  Write-Host "Results exported to $CsvPath"
} catch {
  Write-Error ("Advanced Hunting call failed: {0}" -f $_.Exception.Message)
} #try

####################
$SafeGuard = '04.03'
####################
Write-Verbose "# ===== Safeguard $SafeGuard ====="
$KqlQuery = @"
declare query_parameters (Acronym1:string = "ACR1", Acronym2:string = "ACR2");
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
| summarize MinLock15 = countif(ConfigurationId == 'scid-28' and IsCompliant == 1), No15MinLock = countif(ConfigurationId == 'scid-28' and IsCompliant == 0) by DeviceName // Select relevant fields for output
| sort by DeviceName asc // Sort device list
"@.Replace('ACR1', $Acronym1).Replace('ACR2', $Acronym2)

$Headers = @{ Authorization = "Bearer $DefenderAccessToken" }
$Payload = @{ Query = $KqlQuery } | ConvertTo-Json

try {

  $Params = @{
    Method = "Post"
    Uri = $HuntingUri
    Headers = $Headers
    ContentType = "application/json"
    Body = $Payload
    ErrorAction = "Stop"
  }

  $Response = Invoke-RestMethod @Params

  $Results = $Response.Results

  if (-not $Results) {
    Write-Warning "No rows returned for Safeguard $SafeGuard."
  } #if

  Write-Verbose '# Shape results & add compliance rate'
  $shaped = $Results | ForEach-Object {
    $DeviceName = $_.DeviceName
    $MinLock15  = [int]$_.MinLock15
    $No15MinLock = [int]$_.No15MinLock

   [pscustomobject]@{
      DeviceName  = $DeviceName
      MinLock15   = $MinLock15
      No15MinLock = $No15MinLock
    }
  }

  Write-Verbose '# ===== Export to CSV ====='
  $CsvPath = Join-Path $PWD/Defender "Safeguard_$SafeGuard.csv"
  $shaped | Export-Csv -NoTypeInformation -Path $CsvPath
  Write-Host "Results exported to $CsvPath"
} catch {
  Write-Error ("Advanced Hunting call failed: {0}" -f $_.Exception.Message)
} #try

####################
$SafeGuard = '04.04'
####################
Write-Verbose "# ===== Safeguard $SafeGuard ====="
$KqlQuery = @"
declare query_parameters (Acronym1:string = "ACR1", Acronym2:string = "ACR2");
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
| summarize FirewallOn = countif(ConfigurationId == 'scid-2070' and IsCompliant == 1), FirewallOff = countif(ConfigurationId == 'scid-2070' and IsCompliant == 0) by DeviceName // Select relevant fields for output
| sort by DeviceName asc // Sort device list
"@.Replace('ACR1', $Acronym1).Replace('ACR2', $Acronym2)

$Headers = @{ Authorization = "Bearer $DefenderAccessToken" }
$Payload = @{ Query = $KqlQuery } | ConvertTo-Json

try {

  $Params = @{
    Method = "Post"
    Uri = $HuntingUri
    Headers = $Headers
    ContentType = "application/json"
    Body = $Payload
    ErrorAction = "Stop"
  }

  $Response = Invoke-RestMethod @Params

  $Results = $Response.Results

  if (-not $Results) {
    Write-Warning "No rows returned for Safeguard $SafeGuard."
  } #if

  Write-Verbose '# ===== Export to CSV ====='
  $CsvPath = Join-Path $PWD/Defender "Safeguard_$SafeGuard.csv"
  $Results | Export-Csv -NoTypeInformation -Path $CsvPath
  Write-Host "Results exported to $CsvPath"
} catch {
  Write-Error ("Advanced Hunting call failed: {0}" -f $_.Exception.Message)
} #try

####################
$SafeGuard = '04.05'
####################
Write-Verbose "# ===== Safeguard $SafeGuard ====="
$KqlQuery = @"
declare query_parameters (Acronym1:string = "ACR1", Acronym2:string = "ACR2");
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
| summarize FirewallOn = countif(ConfigurationId == 'scid-2070' and IsCompliant == 1), FirewallOff = countif(ConfigurationId == 'scid-2070' and IsCompliant == 0) by DeviceName // Select relevant fields for output
| sort by DeviceName asc // Sort device list
"@.Replace('ACR1', $Acronym1).Replace('ACR2', $Acronym2)

$Headers = @{ Authorization = "Bearer $DefenderAccessToken" }
$Payload = @{ Query = $KqlQuery } | ConvertTo-Json

try {

  $Params = @{
    Method = "Post"
    Uri = $HuntingUri
    Headers = $Headers
    ContentType = "application/json"
    Body = $Payload
    ErrorAction = "Stop"
  }

  $Response = Invoke-RestMethod @Params

  $Results = $Response.Results

  if (-not $Results) {
    Write-Warning "No rows returned for Safeguard $SafeGuard."
  } #if

  Write-Verbose '# ===== Export to CSV ====='
  $CsvPath = Join-Path $PWD/Defender "Safeguard_$SafeGuard.csv"
  $Results | Export-Csv -NoTypeInformation -Path $CsvPath
  Write-Host "Results exported to $CsvPath"
} catch {
  Write-Error ("Advanced Hunting call failed: {0}" -f $_.Exception.Message)
} #try

####################
$SafeGuard = '04.07'
####################
Write-Verbose "# ===== Safeguard $SafeGuard ====="
$KqlQuery = @"
declare query_parameters (Acronym1:string = "ACR1", Acronym2:string = "ACR2");
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
| summarize AdminAcctOff = countif(ConfigurationId == 'scid-3010' and IsCompliant == 1), AdminAcctOn = countif(ConfigurationId == 'scid-3010' and IsCompliant == 0), GuestAcctOff = countif(ConfigurationId == 'scid-3011' and IsCompliant == 1), GuestAcctOn = countif(ConfigurationId == 'scid-3011' and IsCompliant == 0) by DeviceName
| join kind = leftouter (
DeviceEvents
| where Timestamp > ago(90d) // Filter for events within the last 90 days
| where InitiatingProcessFileName contains "lsass.exe" and AdditionalFields has "LAPS"
| extend LAPS = iff(AdditionalFields has "LAPS", 1, 0)
| summarize arg_max(Timestamp, LAPS) by DeviceName)
on DeviceName
| project DeviceName, GuestAcctOff, GuestAcctOn, AdminAcctOff, AdminAcctOn, LAPS
| sort by DeviceName asc // Sort device list
"@.Replace('ACR1', $Acronym1).Replace('ACR2', $Acronym2)

$Headers = @{ Authorization = "Bearer $DefenderAccessToken" }
$Payload = @{ Query = $KqlQuery } | ConvertTo-Json

try {

  $Params = @{
    Method = "Post"
    Uri = $HuntingUri
    Headers = $Headers
    ContentType = "application/json"
    Body = $Payload
    ErrorAction = "Stop"
  }

  $Response = Invoke-RestMethod @Params

  $Results = $Response.Results

  if (-not $Results) {

    Write-Warning "No rows returned for Safeguard $SafeGuard."

  } #if

  Write-Verbose '# ===== Export to CSV ====='
  $CsvPath = Join-Path $PWD/Defender "Safeguard_$SafeGuard.csv"
  $Results | Export-Csv -NoTypeInformation -Path $CsvPath
  Write-Host "Results exported to $CsvPath"

} catch {

  Write-Error ("Advanced Hunting call failed: {0}" -f $_.Exception.Message)

} #try

####################
$SafeGuard = '05.02'
####################
Write-Verbose "# ===== Safeguard $SafeGuard ====="
$KqlQuery = @"
declare query_parameters (Acronym1:string = "ACR1", Acronym2:string = "ACR2");
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
| summarize Length14 = countif(ConfigurationId == 'scid-32' and IsCompliant == 1), LengthNot14 = countif(ConfigurationId == 'scid-32' and IsCompliant == 0), Hist24 = countif(ConfigurationId == 'scid-33' and IsCompliant == 1), HistNot24 = countif(ConfigurationId == 'scid-33' and IsCompliant == 0), Max60 = countif(ConfigurationId == 'scid-34' and IsCompliant == 1), MaxNot60 = countif(ConfigurationId == 'scid-34' and IsCompliant == 0), Min01 = countif(ConfigurationId == 'scid-35' and IsCompliant == 1), MinNot01 = countif(ConfigurationId == 'scid-35' and IsCompliant == 0) by DeviceName
| sort by DeviceName asc // Sort device list
"@.Replace('ACR1', $Acronym1).Replace('ACR2', $Acronym2)

$Headers = @{ Authorization = "Bearer $DefenderAccessToken" }
$Payload = @{ Query = $KqlQuery } | ConvertTo-Json

try {

  $Params = @{
    Method = "Post"
    Uri = $HuntingUri
    Headers = $Headers
    ContentType = "application/json"
    Body = $Payload
    ErrorAction = "Stop"
  }

  $Response = Invoke-RestMethod @Params

  $Results = $Response.Results
  
  if (-not $Results) {
    Write-Warning "No rows returned for Safeguard $SafeGuard."
  } #if

  Write-Verbose '# ===== Export to CSV ====='
  $CsvPath = Join-Path $PWD/Defender "Safeguard_$SafeGuard.csv"
  $Results | Export-Csv -NoTypeInformation -Path $CsvPath
  Write-Host "Results exported to $CsvPath"
} catch {
  Write-Error ("Advanced Hunting call failed: {0}" -f $_.Exception.Message)
} #try 05.02

####################
$SafeGuard = '05.04'
####################
Write-Verbose '# ===== KQL for Safeguard 05.04 ====='
$KqlQuery = @"
declare query_parameters (Acronym1:string = "ACR1", Acronym2:string = "ACR2");
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
| project DeviceName, MachineGroup, RegistryDeviceTag, AccountName, IsLocalAdmin // Select relevant fields for output
| extend Device = strcat(DeviceName,"|",MachineGroup)
| summarize
    ['Local Admin Distinct Device Count']=dcountif(Device, IsLocalAdmin == "true"),
    ['Local Admin Device List']=make_set_if(Device, IsLocalAdmin == "true") // Consolidate list of devices into a single field
    by AccountName // Admin User List
| sort by AccountName asc // Sort by Account Name
"@.Replace('ACR1', $Acronym1).Replace('ACR2', $Acronym2)

$Headers = @{ Authorization = "Bearer $DefenderAccessToken" }
$Payload = @{ Query = $KqlQuery } | ConvertTo-Json

try {

  $Params = @{
    Method = "Post"
    Uri = $HuntingUri
    Headers = $Headers
    ContentType = "application/json"
    Body = $Payload
    ErrorAction = "Stop"
  }

  $Response = Invoke-RestMethod @Params

  $Results = $Response.Results

  if (-not $Results) {
    Write-Warning "No rows returned for Safeguard 05.04."
  } #if

  $Results.ForEach({$_.'Local Admin Device List' = [string]($_.'Local Admin Device List' -join "`r`n")})

  Write-Verbose '# ===== Export raw rows to CSV ====='
  $CsvPath = Join-Path $PWD/Defender "Safeguard_05.04.csv"
  $Results | Export-Csv -NoTypeInformation -Path $CsvPath
  Write-Host "Results exported to $CsvPath"
} catch {
  Write-Error ("Advanced Hunting call failed: {0}" -f $_.Exception.Message)
} #try 05.04

####################
$SafeGuard = '07.03'
####################
Write-Verbose "# ===== Safeguard $SafeGuard ====="
$KqlQuery = @"
declare query_parameters (Acronym1:string = "ACR1", Acronym2:string = "ACR2");
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
"@.Replace('ACR1', $Acronym1).Replace('ACR2', $Acronym2)

$Headers = @{ Authorization = "Bearer $DefenderAccessToken" }
$Payload = @{ Query = $KqlQuery } | ConvertTo-Json -Depth 5

try {

  $Params = @{
    Method = "Post"
    Uri = $HuntingUri
    Headers = $Headers
    ContentType = "application/json"
    Body = $Payload
    ErrorAction = "Stop"
  }

  $Response = Invoke-RestMethod @Params

  $Results = $Response.Results

  if (-not $Results) {
    Write-Warning "No rows returned for Safeguard 07.03."
  } #if

  Write-Verbose '# ===== Export to CSV ====='
  $CsvPath = Join-Path $PWD/Defender "Safeguard_07.03.csv"
  $Results | Export-Csv -NoTypeInformation -Path $CsvPath
  Write-Host "Results exported to $CsvPath"
} catch {
  Write-Error ("Advanced Hunting call failed: {0}" -f $_.Exception.Message)
  if ($_.Exception.Response -and $_.Exception.Response.GetResponseStream) {
    $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
    $errBody = $reader.ReadToEnd()
    Write-Warning "Server response body: $errBody"
  } #if
} #try 07.03

####################
$SafeGuard = '07.04'
####################
Write-Verbose "# ===== Safeguard $SafeGuard ====="
$KqlQuery = @"
declare query_parameters (Acronym1:string = "ACR1", Acronym2:string = "ACR2");
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
"@.Replace('ACR1', $Acronym1).Replace('ACR2', $Acronym2)

$Headers = @{ Authorization = "Bearer $DefenderAccessToken" }
$Payload = @{ Query = $KqlQuery } | ConvertTo-Json -Depth 5

try {

  $Params = @{
    Method = "Post"
    Uri = $HuntingUri
    Headers = $Headers
    ContentType = "application/json"
    Body = $Payload
    ErrorAction = "Stop"
  }

  $Response = Invoke-RestMethod @Params

  $Results = $Response.Results

  if (-not $Results) {
    Write-Warning "No rows returned for Safeguard $SafeGuard."
  }

 Write-Verbose '# ===== Export to CSV ====='
  $CsvPath = Join-Path $PWD/Defender "Safeguard_$SafeGuard.csv"
  $Results | Export-Csv -NoTypeInformation -Path $CsvPath
  Write-Host "Results exported to $CsvPath"
} catch {
  Write-Error ("Advanced Hunting call failed: {0}" -f $_.Exception.Message)
  if ($_.Exception.Response -and $_.Exception.Response.GetResponseStream) {
    $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
    $errBody = $reader.ReadToEnd()
    Write-Warning "Server response body: $errBody"
  }
}

####################
$SafeGuard = '09.01'
####################
Write-Verbose "# ===== Safeguard $SafeGuard By Device====="
$KqlQuery = @"
declare query_parameters (Acronym1:string = "ACR1", Acronym2:string = "ACR2");
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
| project DeviceName, SoftwareVendor, SoftwareName, SoftwareVersion, EndOfSupportStatus, EndOfSupportDate // Select relevant fields for output
| sort by DeviceName asc // Multi-column sort
"@.Replace('ACR1', $Acronym1).Replace('ACR2', $Acronym2)

$Headers = @{ Authorization = "Bearer $DefenderAccessToken" }
$Payload = @{ Query = $KqlQuery } | ConvertTo-Json -Depth 5

try {

  $Params = @{
    Method = "Post"
    Uri = $HuntingUri
    Headers = $Headers
    ContentType = "application/json"
    Body = $Payload
    ErrorAction = "Stop"
  }

  $Response = Invoke-RestMethod @Params

  $Results = $Response.Results

  if (-not $Results) {
    Write-Warning "No rows returned for Safeguard $SafeGuard By Device."
  }

  Write-Verbose '# ===== Export to CSV ====='
  $CsvPath = Join-Path $PWD/Defender "Safeguard_$SafeGuard-ByDevice.csv"
  $Results | Export-Csv -NoTypeInformation -Path $CsvPath
  Write-Host "Results exported to $CsvPath"
} catch {
  Write-Error ("Advanced Hunting call failed: {0}" -f $_.Exception.Message)
  if ($_.Exception.Response -and $_.Exception.Response.GetResponseStream) {
    $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
    $errBody = $reader.ReadToEnd()
    Write-Warning "Server response body: $errBody"
  }
}

####################
$SafeGuard = '09.01'
####################
Write-Verbose "# ===== Safeguard $SafeGuard By Software====="
$KqlQuery = @"
declare query_parameters (Acronym1:string = "ACR1", Acronym2:string = "ACR2");
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
| project DeviceName, SoftwareVendor, SoftwareName, SoftwareVersion, EndOfSupportStatus, EndOfSupportDate // Select relevant fields for output
| summarize DeviceName = count() by SoftwareVendor, SoftwareName, SoftwareVersion, EndOfSupportStatus, EndOfSupportDate // Summarize by Software info
| sort by SoftwareVendor asc, SoftwareName asc, SoftwareVersion asc // Multi-column sort
"@.Replace('ACR1', $Acronym1).Replace('ACR2', $Acronym2)

$Headers = @{ Authorization = "Bearer $DefenderAccessToken" }
$Payload = @{ Query = $KqlQuery } | ConvertTo-Json -Depth 5

try {

  $Params = @{
    Method = "Post"
    Uri = $HuntingUri
    Headers = $Headers
    ContentType = "application/json"
    Body = $Payload
    ErrorAction = "Stop"
  }

  $Response = Invoke-RestMethod @Params

  $Results = $Response.Results

  if (-not $Results) {
    Write-Warning "No rows returned for Safeguard $SafeGuard By Software."
  }

  Write-Verbose '# ===== Export to CSV ====='
  $CsvPath = Join-Path $PWD/Defender "Safeguard_$SafeGuard-BySoftware.csv"
  $Results | Export-Csv -NoTypeInformation -Path $CsvPath
  Write-Host "Results exported to $CsvPath"
} catch {
  Write-Error ("Advanced Hunting call failed: {0}" -f $_.Exception.Message)
  if ($_.Exception.Response -and $_.Exception.Response.GetResponseStream) {
    $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
    $errBody = $reader.ReadToEnd()
    Write-Warning "Server response body: $errBody"
  }
}

####################
$SafeGuard = '09.02'
####################
Write-Verbose "# ===== Safeguard $SafeGuard ====="
$KqlQuery = @"
declare query_parameters (Acronym1:string = "ACR1", Acronym2:string = "ACR2");
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
| summarize AllDns = make_set(DnsAddresses) by DeviceName
| project DeviceName, AllDns
| sort by DeviceName asc
"@.Replace('ACR1', $Acronym1).Replace('ACR2', $Acronym2)

$Headers = @{ Authorization = "Bearer $DefenderAccessToken" }
$Payload = @{ Query = $KqlQuery } | ConvertTo-Json -Depth 5

try {

  $Params = @{
    Method = "Post"
    Uri = $HuntingUri
    Headers = $Headers
    ContentType = "application/json"
    Body = $Payload
    ErrorAction = "Stop"
  }

  $Response = Invoke-RestMethod @Params

  $Results = $Response.Results

  if (-not $Results) {
    Write-Warning "No rows returned for Safeguard $SafeGuard."
  }

  $Results.ForEach({$_.AllDns = [string]($_.AllDns -join "`r`n")})

  Write-Verbose '# ===== Export to CSV ====='
  $CsvPath = Join-Path $PWD/Defender "Safeguard_$SafeGuard.csv"
  $Results | Export-Csv -NoTypeInformation -Path $CsvPath
  Write-Host "Results exported to $CsvPath"
} catch {
  Write-Error ("Advanced Hunting call failed: {0}" -f $_.Exception.Message)
  if ($_.Exception.Response -and $_.Exception.Response.GetResponseStream) {
    $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
    $errBody = $reader.ReadToEnd()
    Write-Warning "Server response body: $errBody"
  }
}

####################
$SafeGuard = '10.01'
####################
Write-Verbose "# ===== Safeguard $SafeGuard ====="
$KqlQuery = @"
declare query_parameters (Acronym1:string = "ACR1", Acronym2:string = "ACR2");
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
| summarize DefenderOn = countif(ConfigurationId == 'scid-2010' and IsCompliant == 1), DefenderOff = countif(ConfigurationId == 'scid-2010' and IsCompliant == 0), UpdatesOn = countif(ConfigurationId == 'scid-2011' and IsCompliant == 1), UpdatesOff = countif(ConfigurationId == 'scid-2011' and IsCompliant == 0) by DeviceName
| sort by DeviceName asc // Sort device list
"@.Replace('ACR1', $Acronym1).Replace('ACR2', $Acronym2)

$Headers = @{ Authorization = "Bearer $DefenderAccessToken" }
$Payload = @{ Query = $KqlQuery } | ConvertTo-Json -Depth 5

try {

  $Params = @{
    Method = "Post"
    Uri = $HuntingUri
    Headers = $Headers
    ContentType = "application/json"
    Body = $Payload
    ErrorAction = "Stop"
  }

  $Response = Invoke-RestMethod @Params

  $Results = $Response.Results

  if (-not $Results) {
    Write-Warning "No rows returned for Safeguard $SafeGuard."
  }

  Write-Verbose '# ===== Export to CSV ====='
  $CsvPath = Join-Path $PWD/Defender "Safeguard_$SafeGuard.csv"
  $Results | Export-Csv -NoTypeInformation -Path $CsvPath
  Write-Host "Results exported to $CsvPath"
} catch {
  Write-Error ("Advanced Hunting call failed: {0}" -f $_.Exception.Message)
  if ($_.Exception.Response -and $_.Exception.Response.GetResponseStream) {
    $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
    $errBody = $reader.ReadToEnd()
    Write-Warning "Server response body: $errBody"
  }
}

####################
$SafeGuard = '10.02'
####################
Write-Verbose "# ===== Safeguard $SafeGuard ====="
$KqlQuery = @"
declare query_parameters (Acronym1:string = "ACR1", Acronym2:string = "ACR2");
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
| summarize DataRefreshTimestamp = max(DataRefreshTimestamp), PlatformUpToDate = countif(datetime_diff('hour',AvSignatureDataRefreshTime,AvSignaturePublishTime) <= 24), NoData = countif(isnull(AvSignaturePublishTime)) by DeviceName, AvPlatformVersion
| sort by DeviceName asc // Sort device list
"@.Replace('ACR1', $Acronym1).Replace('ACR2', $Acronym2)

$Headers = @{ Authorization = "Bearer $DefenderAccessToken" }
$Payload = @{ Query = $KqlQuery } | ConvertTo-Json -Depth 5

try {

  $Params = @{
    Method = "Post"
    Uri = $HuntingUri
    Headers = $Headers
    ContentType = "application/json"
    Body = $Payload
    ErrorAction = "Stop"
  }

  $Response = Invoke-RestMethod @Params

  $Results = $Response.Results

  if (-not $Results) {
    Write-Warning "No rows returned for Safeguard $SafeGuard."
  }

  Write-Verbose '# ===== Export to CSV ====='
  $CsvPath = Join-Path $PWD/Defender "Safeguard_$SafeGuard.csv"
  $Results | Export-Csv -NoTypeInformation -Path $CsvPath
  Write-Host "Results exported to $CsvPath"
} catch {
  Write-Error ("Advanced Hunting call failed: {0}" -f $_.Exception.Message)
  if ($_.Exception.Response -and $_.Exception.Response.GetResponseStream) {
    $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
    $errBody = $reader.ReadToEnd()
    Write-Warning "Server response body: $errBody"
  }
}

####################
$SafeGuard = '10.03'
####################
Write-Verbose '# ===== Safeguard $SafeGuard ====='
$KqlQuery = @"
declare query_parameters (Acronym1:string = "ACR1", Acronym2:string = "ACR2");
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
| summarize AutoplayDisabled = countif(ConfigurationId == 'scid-67' and IsCompliant == 1), AutoplayEnabled = countif(ConfigurationId == 'scid-67' and IsCompliant == 0) by DeviceName // Select relevant fields for output
| sort by DeviceName asc // Sort device list
"@.Replace('ACR1', $Acronym1).Replace('ACR2', $Acronym2)

$Headers = @{ Authorization = "Bearer $DefenderAccessToken" }
$Payload = @{ Query = $KqlQuery } | ConvertTo-Json -Depth 5

try {

  $Params = @{
    Method = "Post"
    Uri = $HuntingUri
    Headers = $Headers
    ContentType = "application/json"
    Body = $Payload
    ErrorAction = "Stop"
  }

  $Response = Invoke-RestMethod @Params

  $Results = $Response.Results

  if (-not $Results) {
    Write-Warning "No rows returned for Safeguard $SafeGuard."
  }

  Write-Verbose '# ===== Export to CSV ====='
  $CsvPath = Join-Path $PWD/Defender "Safeguard_$SafeGuard.csv"
  $Results | Export-Csv -NoTypeInformation -Path $CsvPath
  Write-Host "Results exported to $CsvPath"
} catch {
  Write-Error ("Advanced Hunting call failed: {0}" -f $_.Exception.Message)
  if ($_.Exception.Response -and $_.Exception.Response.GetResponseStream) {
    $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
    $errBody = $reader.ReadToEnd()
    Write-Warning "Server response body: $errBody"
  }
}

####################
$SafeGuard = '11.02'
####################
Write-Verbose "# ===== Safeguard $SafeGuard ====="
$KqlQuery = @"
declare query_parameters (Acronym1:string = "ACR1", Acronym2:string = "ACR2");
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
| distinct DeviceName, OSPlatform, OSVersion, SoftwareVendor, SoftwareName, SoftwareVersion // Select relevant fields for output
| sort by DeviceName asc // Sort device list
"@.Replace('ACR1', $Acronym1).Replace('ACR2', $Acronym2)

$Headers = @{ Authorization = "Bearer $DefenderAccessToken" }
$Payload = @{ Query = $KqlQuery } | ConvertTo-Json -Depth 5

try {

  $Params = @{
    Method = "Post"
    Uri = $HuntingUri
    Headers = $Headers
    ContentType = "application/json"
    Body = $Payload
    ErrorAction = "Stop"
  }

  $Response = Invoke-RestMethod @Params

  $Results = $Response.Results

  if (-not $Results) {
    Write-Warning "No rows returned for Safeguard $SafeGuard."
  }

  Write-Verbose '# ===== Export to CSV ====='
  $CsvPath = Join-Path $PWD/Defender "Safeguard_$SafeGuard.csv"
  $Results | Export-Csv -NoTypeInformation -Path $CsvPath
  Write-Host "Results exported to $CsvPath"
} catch {
  Write-Error ("Advanced Hunting call failed: {0}" -f $_.Exception.Message)
  if ($_.Exception.Response -and $_.Exception.Response.GetResponseStream) {
    $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
    $errBody = $reader.ReadToEnd()
    Write-Warning "Server response body: $errBody"
  }
}

####################
$SafeGuard = 'ConfigurationSummary'
####################
Write-Verbose "# ===== $SafeGuard ====="
$KqlQuery = @"
declare query_parameters (Acronym1:string = "ACR1", Acronym2:string = "ACR2");
DeviceInfo
| where Timestamp > ago(90d) // Filter for events within the last 90 days
| where MachineGroup has_any (Acronym1, Acronym2)
or RegistryDeviceTag has_any (Acronym1, Acronym2)
or DeviceDynamicTags has_any (Acronym1, Acronym2)
or DeviceManualTags has_any (Acronym1, Acronym2)
| project Timestamp, DeviceId, DeviceName, OSPlatform, MachineGroup, RegistryDeviceTag
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
"@.Replace('ACR1', $Acronym1).Replace('ACR2', $Acronym2)

$Headers = @{ Authorization = "Bearer $DefenderAccessToken" }
$Payload = @{ Query = $KqlQuery } | ConvertTo-Json -Depth 5

try {

  $Params = @{
    Method = "Post"
    Uri = $HuntingUri
    Headers = $Headers
    ContentType = "application/json"
    Body = $Payload
    ErrorAction = "Stop"
  }

  $Response = Invoke-RestMethod @Params

  $Results = $Response.Results

  if (-not $Results) {
    Write-Warning "No rows returned for $SafeGuard."
  }

  Write-Verbose '# ===== Export to CSV ====='
  $CsvPath = Join-Path $PWD/Defender "$SafeGuard.csv"
  $Results | Export-Csv -NoTypeInformation -Path $CsvPath
  Write-Host "Results exported to $CsvPath"
} catch {
  Write-Error ("Advanced Hunting call failed: {0}" -f $_.Exception.Message)
  if ($_.Exception.Response -and $_.Exception.Response.GetResponseStream) {
    $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
    $errBody = $reader.ReadToEnd()
    Write-Warning "Server response body: $errBody"
  }
}

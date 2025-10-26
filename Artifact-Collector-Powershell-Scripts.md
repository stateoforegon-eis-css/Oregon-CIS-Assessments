Browser Notes: To open the any of the hyperlinks found on this page in a new tab, Ctrl+Click or right-click and select ‘Open link in new tab.’”

# **IG1+ Artifact Collector Powershell scripts**

## CIS Control #1: Inventory and Control of Enterprise Assets
Note - You will need to run each of these PowerShell scripts in the same directory/folder where your Artifact Collector result files are saved.

### Safeguard 1.1 Establish and Maintain a Detailed Asset Inventory

**About:**
Script to extract Active Directory inventory of 'discovered' assets from Artifact Collector. Script will output one file listing all enabled computers from A/D: [AgencyAcronym]-1-01-M2-enabled-AD-Computers.csv

```powershell
$AgencyAcronym = Read-Host "What is the Agency Acronym?"
$ad = Import-Clixml .\ActiveDirectory.xml
$EnabledComputers = $ad.computers | Where-Object { $_.Enabled -eq $true }
$DisabledComputers = $ad.computers | Where-Object { $_.Enabled -eq $false }
$EnabledComputers | Export-Csv -NoTypeinformation .\$AgencyAcronym-1.01-M2-enabled-AD-Computers.csv
Write-Host "Report saved to $AgencyAcronym-1.01-M2-enabled-AD-Computers.csv"
Write-Host 'Safeguard 1.01, M3 = Enabled Computers found in AD' - $EnabledComputers.count
Write-Host 'Disabled Computers found in AD' - $DisabledComputers.count
Write-Host 'Total Computers found in AD' - $AD.Computers.count

```
### Safeguard 1.2 Address Unauthorized Assets

**About:**
Script to extract the Count of Assets in GV02 with a "First Seen" date greater than M3 days prior to the Assessment.  Script will output one file listing all unauthorized Computers from A/D: [AgencyAcronym]-1.02-M4-Unauthorized-Computers.csv

```powershell
$ad = Import-Clixml .\ActiveDirectory.xml
$M3 = Read-Host "What is the Enterprise Defined Timeframe (in days) for Addressing Unauthorized Assets?"
$M3 = [int]$M3
$AssessmentDateStr = Read-Host "What is the date of the assessment? (YYYY-MM-DD)"
$AssessmentDate = [datetime]$AssessmentDateStr
$CutoffDate = $AssessmentDate.AddDays(-$M3)
$M4 = $ad.Computers | Where-Object {
    $_.Enabled -eq $true -and
    [datetime]$_.whenCreated -gt $CutoffDate
} | Measure-Object | Select-Object -ExpandProperty Count
Write-Output "Safeguard 1.02, M4 = Number of enabled assets with 'first seen' (whenCreated) after ${CutoffDate}: ${M4}"
$M4 |  Export-Csv -NoTypeinformation .\$AgencyAcronym-1.02-M4-Unauthorized-Computers.csv
Write-Host "Report saved to $AgencyAcronym-1.02-M4-Unauthorized-Computers.csv"
```
## CIS Control #5: Account Management

### Safeguard 5.1 Establish and Maintain an Inventory of Accounts

**About:**
Script to extract Active Directory inventory of 'discovered' Users from Artifact Collector.  User list from Active Directory is exported to [AgencyAcronym]-UserAccounts.csv. (Includes MFA tags for 6.4 and 6.5)

```Powershell
    $AgencyAcronym = Read-Host "What is the Agency Acronym?"
    $GV22M7 = Import-Clixml .\ActiveDirectory.xml
    $csvFile = "$AgencyAcronym-UserAccounts.csv"
    $GV22M7.users |
        Select-Object SamAccountName, SmartcardLogonRequired |
        Export-Csv -Path $csvFile -NoTypeInformation -Encoding UTF8
    Write-Host "Export complete: $csvFile"	
```
### Safeguard 5.3 Disable Dormant Accounts

**About:**
Save Script as a .ps1 file, then execute from the same directory/folder where your Artifact Collector result files are saved.  This Script will extract Active Directory inventory of 'dormant accounts' from Artifact Collector and export two files: [AgencyAcronym]-cis-5.3-M6-dormant-accts-enabled.csv and [AgencyAcronym]+CIS_CAS_5.3_Measures.txt.

```Powershell
$AgencyAcronym = Read-Host "What is the Agency Acronym?"
$M2 = Read-Host "What is the timeframe of dormant threshold in days (Statewide Standards require 90)?"
$GV22 = Import-Clixml .\ActiveDirectory.xml |
	Select-Object -ExpandProperty Users | 
		Select-Object @{n="Name";e={$_.Name}},
		@{n="LastLogon";e={$_.LastLogonDate}},
		@{n="Enabled";e={$_.Enabled}},
		@{n="PwdLastSet";e={$_.PasswordLastSet}},
		@{n="PwdNeverExpire";e={$_.PasswordNeverExpires}}
	$M1 = $GV22.count
	$M3 = $GV22 | Where-Object {
		($_.LastLogon -ne $NULL) -and
		($_.LastLogon -lt (Get-Date).AddDays(-$M2))
		} |
	Measure-Object | Select-Object -ExpandProperty Count
	$M4 = $GV22 | Where-Object {$_.Enabled -like "True"} |
	Measure-Object | Select-Object -ExpandProperty Count
	$M5 = $GV22 | Where-Object {
		($_.LastLogon -ne $NULL) -and
		($_.Enabled -like "False") -and
		($_.LastLogon -lt (Get-Date).AddDays(-$M2))
		} |
	Measure-Object | Select-Object -ExpandProperty Count
	$M6 = $GV22 |
	Where-Object {
		($_.LastLogon -ne $NULL) -and
		($_.Enabled -like "True") -and
		($_.LastLogon -lt (Get-Date).AddDays(-$M2))
		} | 
	Measure-Object | Select-Object -ExpandProperty Count
	$Metric = [math]::round((($M6/$M3)*100),1)
	$output = [PSCustomObject][ordered]@{
		"M1 Accts In GV22" = $M1
		"M2 Dormant Threshold Days" = $M2
		"M3 Count of Dormant Accts" = $M3
		"M4 Count of Active Accts" = $M4
		"M5 Count of Disabled Dormant Accts" = $M5
		"M6 Count of Dormant Accts Not Disabled" = $M6
		"Percent Dormant Accts Not Disabled" = $Metric
	}
	$output | Format-List | 
	Tee-Object ./$AgencyAcronym+CIS_CAS_5.3_Measures.txt
	$GV22 | Where-Object {
		($_.LastLogon -ne $NULL) -and
		($_.LastLogon -lt (Get-Date).AddDays(-$M2))
		} | Sort-Object -Descending -Property LastLogon |
	Export-Csv -NoTypeinformation .\$AgencyAcronym-cis-5.3-M6-dormant-accts-enabled.csv
	Write-Host "Report saved to $AgencyAcronym-cis-5.3-M6-dormant-accts-enabled.csv"
```
### Safeguard 5.4: Restrict Administrator Privileges to Dedicated Administrator Accounts

**About:**
Save Script as a .ps1 file, then execute from the same directory/folder where your Artifact Collector result files are saved.  This Script will extract Active Directory Groups that are likely to contain or be configured with Administrative permissions and exports one file: [AgencyAcronym]-admin_groups_report.xlsx.

```Powershell
# Get Agency Acronym
$acy = Read-Host -Prompt "Agency Acronym: "

# Function to load and parse XML serialized with Export-Clixml
function Load-ClixmlFile {
    param (
        [string]$filePath
    )
    return Import-Clixml -Path $filePath
}

# Function to extract admin groups and their members from new XML format
function Get-AdminGroups {
    param (
        [array]$groups,
        [array]$users
    )

    $adminGroupMembers = @()

    foreach ($group in $groups | Where-Object { 
        ($_.SamAccountName -match "admin") -or ($_.Description -match "admin")
    }) {
        foreach ($memberDN in $group.Member) {
            # Look up the member in users by DN for SAMAccountName
            $memberSAM = ($users | Where-Object { $_.DistinguishedName -eq $memberDN }).SamAccountName

            $adminGroupMembers += [PSCustomObject]@{
                Group       = $group.SamAccountName
                Type        = $group.GroupType
                Description = $group.Description
                DN          = $group.DistinguishedName
                Member      = $memberDN
                MemberSAM   = $memberSAM
            }
        }
    }

    # Ensure unique rows based on Group + Member
    $adminGroupMembers = $adminGroupMembers |
        Sort-Object Group, Member -Unique

    return $adminGroupMembers
}

# Main
$groupClixmlFile = ".\ActiveDirectory.xml"

# Load serialized XML content
$clixmlData = Load-ClixmlFile -filePath $groupClixmlFile

# Extract admin groups from the .groups property and resolve member SAM names from .users
$adminGroupMembers = Get-AdminGroups -groups $clixmlData.groups -users $clixmlData.users

# Export to CSV
$adminGroupMembers | Export-Csv -NoTypeinformation .\$Acy-admin-groups-report.csv
Write-Host "Report saved to $Acy-admin-groups-report.csv"
```
## CIS Control #8: Audit Log Management

### Safeguard 8.4 Standardize Time Synchronization

**About:**
Script to extract NTP configuration from Artifact Collector.  The NTP configuration is exported to [AgencyAcronym]-8.04-M2-NTP-Config.txt.

```Powershell
$AgencyAcronym = Read-Host "What is the Agency Acronym?"
$ntp = import-Clixml .\NTP\NtpConfig.xml
$Pattern1 = [regex]::Escape('Getting AD DC list for default domain...')
$Pattern2 = [regex]::Escape('Analyzing:')
$filteredOutput = $ntp.W32tmMonitorOutput | Where-Object {
    -not [string]::IsNullOrWhiteSpace($_) -and $_ -notmatch "$Pattern1|$Pattern2"
}
$regNtpServerLine = "RegNtpServer: $($ntp.RegNtpServer)"
$finalOutput = $filteredOutput + $regNtpServerLine
$finalOutput | Out-File -FilePath ".\$AgencyAcronym-8.04-M2-NTP-Config.txt"
Write-Host "Report saved to $AgencyAcronym-8.04-M2-NTP-Config.txt"
```

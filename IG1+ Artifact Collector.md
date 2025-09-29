# **IG1+ Artifact Collector Powershell scripts**

## CIS Control #1: Inventory and Control of Enterprise Assets
Note - You will need to run each of these PowerShell scripts in the same directory/folder where your Artifact Collector result files are saved.

### Safeguard 1.1 Establish and Maintain a Detailed Asset Inventory

**About:**
Script to extract Active Directory inventory of 'discovered' assets from Artifact Collector. To see the list of Computers, remove the ".count" from the script. 

```powershell
$ad = Import-Clixml .\ActiveDirectory.xml
$EnabledComputers = $ad.computers | Where-Object { $_.Enabled -eq $true }
$DisabledComputers = $ad.computers | Where-Object { $_.Enabled -eq $false }
Write-Host 'Safeguard 1.01, M3 = Enabled Computers found in AD' - $EnabledComputers.count
Write-Host 'Disabled Computers found in AD' - $DisabledComputers.count
Write-Host 'Total Computers found in AD' - $AD.Computers.count

```
### Safeguard 1.2 Address Unauthorized Assets

**About:**
Script to extract the Count of Assets in GV02 with a "First Seen" date greater than M3 days prior to the Assessment.  

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
```
## CIS Control #5: Account Management

### Safeguard 5.1 Establish and Maintain an Inventory of Accounts

**About:**
Script to extract Active Directory inventory of 'discovered' Users from Artifact Collector.  User list from Active Directory is exported to [AgencyAcronym]-UserAccounts.csv.

```Powershell
    $AgencyAcronym = Read-Host "What is the Agency Acronym?"
    $GV22M7 = Import-Clixml .\ActiveDirectory.xml
    $csvFile = "$AgencyAcronym-UserAccounts.csv"
    $GV22M7.users |
        Select-Object SamAccountName |
        Export-Csv -Path $csvFile -NoTypeInformation -Encoding UTF8
    Write-Host "Export complete: $csvFile"

```
### Safeguard 5.3 Disable Dormant Accounts

**About:**
Save Script to a .ps1 file, then execute.  This Script will extract Active Directory inventory of 'dormant accounts' from Artifact Collector and export two files: [AgencyAcronym]-cis-5.3-M6-dormant-accts-enabled.csv and [AgencyAcronym]+CIS_CAS_5.3_Measures.txt.

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




$ad = Import-Clixml .\ActiveDirectory.xml
$EnabledUsers = $ad.Users | Where-Object { $_.Enabled -eq $true }
$DisabledUsers = $ad.Users | Where-Object { $_.Enabled -eq $false }
Write-Host 'Safeguard 5.01, M6 = Enabled Users found in AD' - $EnabledUsers.count
Write-Host 'Disabled Users found in AD' - $DisabledUsers.count
Write-Host 'Total Users found in AD' - $AD.Users.count
```

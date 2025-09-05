# **CIS v8.0 Controls Assessment Specification PowerShell Scripts (BETA)**

## CIS Control #5: Account Management

### Safeguard 5.1 Establish and Maintain an Inventory of Accounts

**About:**
Script to identify users collected from ArtifactCollector

```
param (
        [parameter(Mandatory=$true)]
        [string] $AgencyAcronym
    )

    # Import data
    $GV22M7 = Import-Clixml .\ActiveDirectory.xml

    # Build output filename
    $csvFile = "$AgencyAcronym-UserAccounts.csv"

    # Export users to CSV
    $GV22M7.users |
        Select-Object SamAccountName |
        Export-Csv -Path $csvFile -NoTypeInformation -Encoding UTF8

    Write-Host "Export complete: $csvFile"
```

### CIS Safgeguard 5.3: Disable Dormant Accounts

**About:**
Script to identify users collected from ArtifactCollector

```
param (

		[parameter(Mandatory=$true)]
		[string] $AgencyAcronym,

		[parameter(Mandatory=$true)]
		[string] $DormantThreshold

			
	) #param
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
		($_.LastLogon -lt (Get-Date).AddDays(-$DormantThreshold))
		} |
	Measure-Object | Select-Object -ExpandProperty Count
	$M4 = $GV22 | Where-Object {$_.Enabled -like "True"} |
	Measure-Object | Select-Object -ExpandProperty Count
	$M5 = $GV22 | Where-Object {
		($_.LastLogon -ne $NULL) -and
		($_.Enabled -like "False") -and
		($_.LastLogon -lt (Get-Date).AddDays(-$DormantThreshold))
		} |
	Measure-Object | Select-Object -ExpandProperty Count
	$M6 = $GV22 |
	Where-Object {
		($_.LastLogon -ne $NULL) -and
		($_.Enabled -like "True") -and
		($_.LastLogon -lt (Get-Date).AddDays(-$DormantThreshold))
		} | 
	Measure-Object | Select-Object -ExpandProperty Count
	$Metric = [math]::round((($M6/$M3)*100),1)
	$output = [PSCustomObject][ordered]@{
		"M1 Accts In GV22" = $M1
		"M2 Dormant Threshold Days" = $DormantThreshold
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
		($_.LastLogon -lt (Get-Date).AddDays(-$DormantThreshold))
		} | Sort-Object -Descending -Property LastLogon |
	Export-Csv -NoTypeinformation .\$AgencyAcronym-cis-5.3-M6-dormant-accts-enabled.csv
---

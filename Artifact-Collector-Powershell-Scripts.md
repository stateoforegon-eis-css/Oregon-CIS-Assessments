Browser Notes: To open the any of the hyperlinks found on this page in a new tab, Ctrl+Click or right-click and select ‘Open link in new tab.’”

# **IG1+ Artifact Collector Powershell scripts**

**Note:** The powershell module below is designed to utilize the output from [Artifact Collector](https://github.com/stateoforegon-eis-css/ArtifactCollector). The module can be run from any directory, and will ask for the directory of your unzipped ArtifactCollector output. Detailed information about each of the extracts can be found below the script.

```powershell
function Measure-ArtifactCollector {
	$dir = Read-Host "Where is the ArtifactCollector source file (directory)?"
	$AgencyAcronym = ($dir.Split('\')[-1]).Split('_')[0]
	$ad = Import-Clixml $dir\ActiveDirectory.xml

# CIS Control 01, Safeguard 01
	Write-Host "Extracting Computers ..."
	$ad.computers |
	Select-Object ComputerName, OperatingSystem, OSVersion, Description, WhenCreated, Enabled |
	Export-Csv -NoTypeinformation .\$AgencyAcronym-01.01.M2-Computers.csv
	Write-Host "     Export complete: 01.01.M2-Computers (You'll also use this for 01.02)."

# CIS Control 05, Safeguard 01
	Write-Host "Extracting User Accounts ..."
	$ad.users |
    Select-Object UserPrincipalName, SamAccountName, Name, Description, WhenCreated, Enabled |
    Export-Csv -NoTypeinformation .\$AgencyAcronym-05.01.M6-UserAccounts.csv
	Write-Host "     Export complete: 05.01.M6-UserAccounts."

# CIS Control 05, Safeguard 02
	Write-Host "Copying Fine-Grained Password Policy ..."
	Copy-Item -Path $dir\PasswordPolicies\FineGrainedPasswordPolicies.txt -Destination .\$AgencyAcronym-05.02-FGPasswordPolicy.txt
	Write-Host "     Copy complete: 05.02-FGPasswordPolicy."

# CIS Control 05, Safeguard 03
	Write-Host "Extracting Dormant Accounts ..."
	$ACDate = (($dir.Split('_')[-2]).Split('_')[0]).Insert(4,"-").Insert(7,"-")
    $Today = Get-Date
	$M2 = '90'
	$DateOffset = (New-Timespan -Start $ACDate -End $Today) + $M2
	$GV22 = $ad |
	Select-Object -ExpandProperty Users | 
		Select-Object @{n="UserPrincipalName";e={$_.UserPrincipalName}},
		@{n="SAMAccountName";e={$_.SAMAccountName}},
		@{n="Name";e={$_.Name}},
		@{n="LastLogon";e={$_.LastLogonDate}},
		@{n="Enabled";e={$_.Enabled}},
		@{n="PwdLastSet";e={$_.PasswordLastSet}},
		@{n="PwdNeverExpire";e={$_.PasswordNeverExpires}}
	$M1 = $GV22.count
	$M3 = $GV22 | Where-Object {
		($NULL -ne $_.LastLogon) -and
		($_.LastLogon -lt (Get-Date).AddDays(-$DateOffset.Days))
		} |
	Measure-Object | Select-Object -ExpandProperty Count
	$M4 = $GV22 | Where-Object {$_.Enabled -like "True"} |
	Measure-Object | Select-Object -ExpandProperty Count
	$M5 = $GV22 | Where-Object {
		($NULL -ne $_.LastLogon) -and
		($_.Enabled -like "False") -and
		($_.LastLogon -lt (Get-Date).AddDays(-$DateOffset.Days))
		} |
	Measure-Object | Select-Object -ExpandProperty Count
	$M6 = $GV22 |
	Where-Object {
		($NULL -ne $_.LastLogon) -and
		($_.Enabled -like "True") -and
		($_.LastLogon -lt (Get-Date).AddDays(-$DateOffset.Days))
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
	Out-File -FilePath ".\$AgencyAcronym-05.03-Measures.txt"
	$GV22 | Where-Object {
		($NULL -ne $_.LastLogon) -and
		($_.LastLogon -lt (Get-Date).AddDays(-$DateOffset.Days))
		} | Sort-Object -Descending -Property LastLogon |
	Export-Csv -NoTypeinformation .\$AgencyAcronym-05.03.M6-DormantAccounts.csv
	Write-Host "     Export complete: 05.03.M6-DormantAccounts."

# CIS Control 05, Safeguard 04 
	Write-Host "Extracting Admin Group Memberships. This might take a bit; please be patient ..."
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
        	    $memberUPN = ($users | Where-Object { $_.DistinguishedName -eq $memberDN }).UserPrincipalName
				$memberSAM = ($users | Where-Object { $_.DistinguishedName -eq $memberDN }).SamAccountName
				$memberName = ($users | Where-Object { $_.DistinguishedName -eq $memberDN }).Name
	            $adminGroupMembers += [PSCustomObject]@{
    	            Group       = $group.SamAccountName
        	        Type        = $group.GroupType
            	    Description = $group.Description
                	DN          = $group.DistinguishedName
                	Member      = $memberDN
					MemberUPN   = $memberUPN
                	MemberSAM   = $memberSAM
					MemberName  = $memberName
	            }
    	    }
	    }
    	$adminGroupMembers = $adminGroupMembers |
        	Sort-Object Group, Member -Unique
    	return $adminGroupMembers
	}
	$adminGroupMembers = Get-AdminGroups -groups $ad.groups -users $ad.users
	$adminGroupMembers | Export-Csv -NoTypeinformation .\$AgencyAcronym-05.04-AdminGroupMembers.csv
	Write-Host "     Export complete: 05.04-AdminGroupMembers."

# CIS Control 06, Safeguard 04
	Write-Host "Extracting Enabled User Accounts with MFA Info..."
	$ad.users |
	Select-Object UserPrincipalName, SamAccountName, Name, SmartcardLogonRequired, Enabled |
	    Where-Object { $_.Enabled -eq "true" } |
    Export-Csv -NoTypeinformation .\$AgencyAcronym-06.04.M2-UserAccountsMFA.csv
	Write-Host "     Export complete: 06.04.M2-UserAccountsMFA (You'll also use this for 06.05)."

# CIS Control 08, Safeguard 04
	Write-Host "Extracting NTP Configuration ..."
	$ntp = import-Clixml $dir\NTP\NtpConfig.xml
	$Pattern1 = [regex]::Escape('Getting AD DC list for default domain...')
	$Pattern2 = [regex]::Escape('Analyzing:')
	$filteredOutput = $ntp.W32tmMonitorOutput | Where-Object {
    	-not [string]::IsNullOrWhiteSpace($_) -and $_ -notmatch "$Pattern1|$Pattern2"
	}
	$regNtpServerLine = "RegNtpServer: $($ntp.RegNtpServer)"
	$finalOutput = $filteredOutput + $regNtpServerLine
	$finalOutput | Out-File -FilePath ".\$AgencyAcronym-08.04.M2-NTPConfig.txt"
	Write-Host "     Export complete: 08.04.M2-NTPConfig."
}
```



## CIS Control 1: Inventory and Control of Enterprise Assets

### Safeguard 1.01 Establish and Maintain a Detailed Asset Inventory

**About:** 
Script to extract Active Directory inventory of 'discovered' assets from Artifact Collector. Script will output one file listing all enabled computers from A/D: [AgencyAcronym]-01.01.M2-Computers.csv

## CIS Control 5: Account Management

### Safeguard 5.01 Establish and Maintain an Inventory of Accounts

**About:** 
Script to extract Active Directory inventory of 'discovered' Users from Artifact Collector.  The user list is exported to [AgencyAcronym]-05.01.M6-UserAccounts.csv.

### Safeguard 5.02 Use Unique Passwords

**About:** 
Script to extract the Fine-Grained Password Policy for the domain (will be blank if password complexity is enforced via Group Policy). Policy is exported to [AgencyAcronym]-05.02-FGPasswordPolicy.txt

### Safeguard 5.03 Disable Dormant Accounts

**About:** 
This Script will extract Active Directory inventory of 'dormant accounts' from Artifact Collector and export two files: [AgencyAcronym]-05.03.M6-DormantAccounts.csv and [AgencyAcronym]-05.03-Measures.txt.

### Safeguard 5.04: Restrict Administrator Privileges to Dedicated Administrator Accounts

**About:** 
This Script will extract Active Directory Groups that are likely to contain or be configured with Administrative permissions and exports one file: [AgencyAcronym]-05.04-AdminGroupMembers.csv.

## CIS Control 6: Access Control Management

### Safeguard 6.04: Require MFA for Remote Network Access & 6.05: Require MFA for Administrative Access

**About:** 
Script to extract an inventory of 'discovered' accounts from Active Directory. User list includes the SmartCardLogonRequired attribute as an indicator of whether MFA is required for the named user. The user list is exported to [AgencyAcronym]--06.04.M2-UserAccountsMFA.csv.

## CIS Control 8: Audit Log Management

### Safeguard 8.04 Standardize Time Synchronization

**About: **
Script to extract NTP configuration for Domain Controllers.  The NTP configuration is exported to [AgencyAcronym]-08.04.M2-NTPConfig.txt.


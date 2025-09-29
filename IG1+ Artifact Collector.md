# **IG1+ Artifact Collector Powershell scripts**

## CIS Control #1: Inventory and Control of Enterprise Assets
Note - You will need to run each of these PowerShell scripts in the same directory/folder where your Artifact Collector result files are saved.

### Safeguard 1.1 Establish and Maintain a Detailed Asset Inventory

**About:**
Script to extract Active Directory inventory of 'discovered' assets from Artifact Collector.  

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
Script to extract Active Directory inventory of 'discovered' Users from Artifact Collector.  

```Powershell
$ad = Import-Clixml .\ActiveDirectory.xml
$EnabledUsers = $ad.Users | Where-Object { $_.Enabled -eq $true }
$DisabledUsers = $ad.Users | Where-Object { $_.Enabled -eq $false }
Write-Host 'Safeguard 5.01, M6 = Enabled Users found in AD' - $EnabledUsers.count
Write-Host 'Disabled Users found in AD' - $DisabledUsers.count
Write-Host 'Total Users found in AD' - $AD.Users.count
```

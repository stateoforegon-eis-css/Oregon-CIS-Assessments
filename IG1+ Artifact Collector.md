# **IG1+ Artifact Collector Powershell scripts**

## CIS Control #1: Inventory and Control of Enterprise Assets

### Safeguard 1.1 Establish and Maintain a Detailed Asset Inventory

**About:**
Script to extract an inventory of 'discovered' assets from Artifact Collector.  Note - You will need to run these commands in the same directory/folder where your artifacxt Collector result files are located.

```powershell
$ad = Import-Clixml .\ActiveDirectory.xml
$EnabledComputers = $ad.computers | Where-Object { $_.Enabled -eq $true }
$DisabledComputers = $ad.computers | Where-Object { $_.Enabled -eq $false }
Write-Host 'Enabled Computers found in AD' - $EnabledComputers.count
Write-Host 'Disabled Computers found in AD' - $DisabledComputers.count
Write-Host 'Total Computers found in AD' - $AD.Computers.count

```

## CIS Control #2: Inventory and Control of Software Assets

### Covered Vendor Compliance

**About:**


```Powershell
$script
```

### Safeguard 2.2 Ensure Authorized Software is Currently Supported

**About:**

```Powershell
$script
```

Browser Notes: To open the any of the hyperlinks found on this page in a new tab, Ctrl+Click or right-click and select ‘Open link in new tab.’”

# Applicability

The Group Policy settings below can be assessed using a number of methods; however, we find PolicyAnalyzer tool from the [Microsoft Security Compliance Toolkit](https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/windows-security-configuration-framework/security-compliance-toolkit-10) to be the most efficient.  Each is formatted as follows:

**_Benchmark Description_**
- Registry Key | Policy Setting | Benchmark

------
### _Benchmark Group Policy Settings for Safeguard 3.06_

**_(BL) Ensure 'Choose how BitLocker-protected fixed drives can be recovered' is set to 'Enabled'_**
- SOFTWARE\Policies\Microsoft\FVE | FDVRecovery | 1

**_(BL) Ensure 'Choose how BitLocker-protected fixed drives can be recovered: Allow data recovery agent' is set to 'Enabled: True'_**
- SOFTWARE\Policies\Microsoft\FVE | FDVManageDRA | 1

**_(BL) Ensure 'Choose how BitLocker-protected fixed drives can be recovered: Recovery Password' is set to 'Enabled: Allow 48-digit recovery password' or higher_**
- SOFTWARE\Policies\Microsoft\FVE | FDVRecoveryPassword | 2

**_(BL) Ensure 'Choose how BitLocker-protected fixed drives can be recovered: Recovery Key' is set to 'Enabled: Allow 256-bit recovery key' or higher_**
- SOFTWARE\Policies\Microsoft\FVE | FDVRecoveryKey | 2

**_(BL) Ensure 'Choose how BitLocker-protected fixed drives can be recovered: Omit recovery options from the BitLocker setup wizard' is set to 'Enabled: True'_**
- SOFTWARE\Policies\Microsoft\FVE | FDVHideRecoveryPage | 1

**_(BL) Ensure 'Choose how BitLocker-protected fixed drives can be recovered: Save BitLocker recovery information to AD DS for fixed data drives' is set to 'Enabled: False'_**
- SOFTWARE\Policies\Microsoft\FVE | FDVActiveDirectoryBackup | 0

**_(BL) Ensure 'Choose how BitLocker-protected fixed drives can be recovered: Configure storage of BitLocker recovery information to AD DS' is set to 'Enabled: Backup recovery passwords and key packages'_**
- SOFTWARE\Policies\Microsoft\FVE | FDVActiveDirectoryInfoToStore | 1

**_(BL) Ensure 'Choose how BitLocker-protected fixed drives can be recovered: Do not enable BitLocker until recovery information is stored to AD DS for fixed data drives' is set to 'Enabled: False'_**
- SOFTWARE\Policies\Microsoft\FVE | FDVRequireActiveDirectoryBackup | 0

**_(BL) Ensure 'Choose how BitLocker-protected operating system drives can be recovered' is set to 'Enabled'_**
- SOFTWARE\Policies\Microsoft\FVE | OSRecovery | 1

**_(BL) Ensure 'Choose how BitLocker-protected operating system drives can be recovered: Allow data recovery agent' is set to 'Enabled: False'_**
- SOFTWARE\Policies\Microsoft\FVE | OSManageDRA | 0

**_(BL) Ensure 'Choose how BitLocker-protected operating system drives can be recovered: Recovery Password' is set to 'Enabled: Require 48-digit recovery password'_**
- SOFTWARE\Policies\Microsoft\FVE | OSRecoveryPassword | 1

**_(BL) Ensure 'Choose how BitLocker-protected operating system drives can be recovered: Recovery Key' is set to 'Enabled: Do not allow 256-bit recovery key'_**
- SOFTWARE\Policies\Microsoft\FVE | OSRecoveryKey | 0

**_(BL) Ensure 'Choose how BitLocker-protected operating system drives can be recovered: Omit recovery options from the BitLocker setup wizard' is set to 'Enabled: True'_**
- SOFTWARE\Policies\Microsoft\FVE | OSHideRecoveryPage | 1

**_(BL) Ensure 'Choose how BitLocker-protected operating system drives can be recovered: Save BitLocker recovery information to AD DS for operating system drives' is set to 'Enabled: True'_**
- SOFTWARE\Policies\Microsoft\FVE | OSActiveDirectoryBackup | 1

**_(BL) Ensure 'Choose how BitLocker-protected operating system drives can be recovered: Configure storage of BitLocker recovery information to AD DS:' is set to 'Enabled: Store recovery passwords and key packages'_**
- SOFTWARE\Policies\Microsoft\FVE | OSActiveDirectoryInfoToStore | 1

**_(BL) Ensure 'Choose how BitLocker-protected operating system drives can be recovered: Do not enable BitLocker until recovery information is stored to AD DS for operating system drives' is set to 'Enabled: True'_**
- SOFTWARE\Policies\Microsoft\FVE | OSRequireActiveDirectoryBackup | 1

------
### _Benchmark Group Policy Settings for Safeguard 3.09_

**_(BL) Ensure 'Choose how BitLocker-protected removable drives can be recovered' is set to 'Enabled'_**
- SOFTWARE\Policies\Microsoft\FVE | RDVRecovery | 1

**_(BL) Ensure 'Choose how BitLocker-protected removable drives can be recovered: Allow data recovery agent' is set to 'Enabled: True'_**
- SOFTWARE\Policies\Microsoft\FVE | RDVManageDRA | 1

**_(BL) Ensure 'Choose how BitLocker-protected removable drives can be recovered: Recovery Password' is set to 'Enabled: Do not allow 48-digit recovery password'_**
- SOFTWARE\Policies\Microsoft\FVE | RDVRecoveryPassword | 0

**_(BL) Ensure 'Choose how BitLocker-protected removable drives can be recovered: Recovery Key' is set to 'Enabled: Do not allow 256-bit recovery key'_**
- SOFTWARE\Policies\Microsoft\FVE | RDVRecoveryKey | 0

**_(BL) Ensure 'Choose how BitLocker-protected removable drives can be recovered: Omit recovery options from the BitLocker setup wizard' is set to 'Enabled: True'_**
- SOFTWARE\Policies\Microsoft\FVE | RDVHideRecoveryPage | 1

**_(BL) Ensure 'Choose how BitLocker-protected removable drives can be recovered: Save BitLocker recovery information to AD DS for removable data drives' is set to 'Enabled: False'_**
- SOFTWARE\Policies\Microsoft\FVE | RDVActiveDirectoryBackup | 0

**_(BL) Ensure 'Choose how BitLocker-protected removable drives can be recovered: Configure storage of BitLocker recovery information to AD DS:' is set to 'Enabled: Backup recovery passwords and key packages'_**
- SOFTWARE\Policies\Microsoft\FVE | RDVActiveDirectoryInfoToStore | 1

**_(BL) Ensure 'Choose how BitLocker-protected removable drives can be recovered: Do not enable BitLocker until recovery information is stored to AD DS for removable data drives' is set to 'Enabled: False'_**
- SOFTWARE\Policies\Microsoft\FVE | RDVRequireActiveDirectoryBackup | 0

**_(BL) Ensure 'Deny write access to removable drives not protected by BitLocker' is set to 'Enabled'_**
- SYSTEM\CurrentControlSet\Policies\Microsoft\FVE | RDVDenyWriteAccess | 1

**_(BL) Ensure 'Deny write access to removable drives not protected by BitLocker: Do not allow write access to devices configured in another organization' is set to 'Enabled: False'_**
- SOFTWARE\Policies\Microsoft\FVE | RDVDenyCrossOrg | 0

------
### _Benchmark Group Policy Settings for Safeguard 4.03_

**_(L1) Ensure 'Interactive logon: Machine inactivity limit' is set to '900 or fewer second(s), but not 0'_**
- SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System | InactivityTimeoutSecs | 900

**_(L1) Ensure 'Interactive logon: Smart card removal behavior' is set to 'Lock Workstation' or higher_**
- SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon | ScRemoveOption | 1

**_(L1) Ensure 'MSS: (ScreenSaverGracePeriod) The time in seconds before the screen saver grace period expires' is set to 'Enabled: 5 or fewer seconds'_**
- SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon | ScreenSaverGracePeriod | 5

**_Time (in seconds) before a computer sleeps (on battery)_**
- Software\Policies\Microsoft\Power\PowerSettings\9D7815A6-7EE4-497E-8888-515A05F02364 | DCSettingIndex | 900 (alternative to "Machine inactivity limit", above)

**_(L1) Ensure 'Require a password when a computer wakes (on battery)' is set to 'Enabled'_**
- Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51 | DCSettingIndex | 1

**_Time (in seconds) before a computer sleeps (plugged in)_**
- Software\Policies\Microsoft\Power\PowerSettings\9D7815A6-7EE4-497E-8888-515A05F02364 | ACSettingIndex | 900 (alternative to "Machine inactivity limit", above)

**_(L1) Ensure 'Require a password when a computer wakes (plugged in)' is set to 'Enabled'_**
- Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51 | ACSettingIndex | 1

------
### _Benchmark Group Policy Settings for Safeguard 4.05_

**_(L1) Ensure 'Windows Firewall: Domain: Firewall state' is set to 'On (recommended)'_**
- SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile | EnableFirewall | 1

**_(L1) Ensure 'Windows Firewall: Domain: Inbound connections' is set to 'Block (default)'_**
- SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile | DefaultInboundAction | 1

**_(L1) Ensure 'Windows Firewall: Private: Firewall state' is set to 'On (recommended)'_**
- SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile | EnableFirewall | 1

**_(L1) Ensure 'Windows Firewall: Private: Inbound connections' is set to 'Block (default)'_**
- SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile | DefaultInboundAction | 1

**_(L1) Ensure 'Windows Firewall: Public: Firewall state' is set to 'On (recommended)'_**
- SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile | EnableFirewall | 1

**_(L1) Ensure 'Windows Firewall: Public: Inbound connections' is set to 'Block (default)'_**
- SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile | DefaultInboundAction | 1

**_(L1) Ensure 'Windows Firewall: Public: Settings: Apply local firewall rules' is set to 'No'_**
- SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile | AllowLocalPolicyMerge | 0

**_(L1) Ensure 'Windows Firewall: Public: Settings: Apply local connection security rules' is set to 'No'_**
- SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile | AllowLocalIPsecPolicyMerge | 0

------
### _Benchmark Group Policy Settings for Safeguard 4.07_

**_(L1) Ensure 'Accounts: Guest account status' is set to 'Disabled'_**
- System Access | EnableGuestAccount | 0

**_Ensure 'Accounts: Admin account status' is set to 'Disabled'_**
- System Access | EnableAdminAccount | 0 (alternative to LAPS settings, below)

**_(L1) Configure 'Accounts: Rename guest account'_**
- System Access | NewGuestName | "CISGUEST"

**_(L1) Configure 'Accounts: Rename administrator account'_**
- System Access | NewAdministratorName | "CISADMIN"

**_(L1) Ensure 'Configure password backup directory' is set to 'Enabled: Active Directory' or 'Enabled: Azure Active Directory'_**
- SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS | BackupDirectory | 2

**_(L1) Ensure 'Do not allow password expiration time longer than required by policy' is set to 'Enabled'_**
- SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS | PasswordExpirationProtectionEnabled | 1

**_(L1) Ensure 'Enable password encryption' is set to 'Enabled'_**
- SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS | ADPasswordEncryptionEnabled | 1

**_(L1) Ensure 'Password Settings: Password Age (Days)' is set to 'Enabled: 30 or fewer'_**
- SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS | PasswordAgeDays | 30

**_(L1) Ensure 'Password Settings: Password Complexity' is set to 'Enabled: Large letters + small letters + numbers + special characters'_**
- SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS | PasswordComplexity | 4

**_(L1) Ensure 'Password Settings: Password Length' is set to 'Enabled: 15 or more'_**
- SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS | PasswordLength | 15

**_(L1) Ensure 'Post-authentication actions: Grace period (hours)' is set to 'Enabled: 8 or fewer hours, but not 0'_**
- SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS | PostAuthenticationActions | 3

**_(L1) Ensure 'Post-authentication actions: Actions' is set to 'Enabled: Reset the password and logoff the managed account' or higher_**
- SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS | PostAuthenticationResetDelay | 8

------
### _Benchmark Group Policy Settings for Safeguard 5.02_

**_(L1) Ensure 'Minimum password length' is set to '14 or more character(s)'_**
- System Access | MinimumPasswordLength | 14

**_(L1) Ensure 'Enforce password history' is set to '24 or more password(s)'_**
- System Access | PasswordHistorySize | 24

**_(L1) Ensure 'Maximum password age' is set to '60 or fewer days, but not 0'_**
- System Access | MaximumPasswordAge | 365

**_(L1) Ensure 'Minimum password age' is set to '1 or more day(s)'_**
- System Access | MinimumPasswordAge | 1

**_(L1) Ensure 'Password must meet complexity requirements' is set to 'Enabled'_**
- System Access | PasswordComplexity | 1

------
### _Benchmark Group Policy Settings for Safeguard 8.02_

**_(L1) Ensure 'Windows Firewall: Domain: Logging: Name' is set to '%SystemRoot%\System32\logfiles\firewall\domainfw.log'_**
- SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging | LogFilePath | %systemroot%\system32\logfiles\firewall\domainfw.log

**_(L1) Ensure 'Windows Firewall: Private: Logging: Name' is set to '%SystemRoot%\System32\logfiles\firewall\privatefw.log'_**
- SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging | LogFilePath | %systemroot%\system32\logfiles\firewall\privatefw.log

**_(L1) Ensure 'Windows Firewall: Public: Logging: Name' is set to '%SystemRoot%\System32\logfiles\firewall\publicfw.log'_**
- SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging | LogFilePath | %systemroot%\system32\logfiles\firewall\publicfw.log

------
### _Benchmark Group Policy Settings for Safeguard 8.03_

**_(L1) Ensure 'Windows Firewall: Domain: Logging: Size limit (KB)' is set to '16,384 KB or greater'_**
- SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging | LogFileSize | 16384

**_(L1) Ensure 'Windows Firewall: Private: Logging: Size limit (KB)' is set to '16,384 KB or greater'_**
- SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging | LogFileSize | 16384

**_(L1) Ensure 'Windows Firewall: Public: Logging: Size limit (KB)' is set to '16,384 KB or greater'_**
- SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging | LogFileSize | 16384

**_(L1) Ensure 'Application: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'_**
- SOFTWARE\Policies\Microsoft\Windows\EventLog\Application | MaxSize | 32768

**_(L1) Ensure 'Security: Specify the maximum log file size (KB)' is set to 'Enabled: 196,608 or greater'_**
- SOFTWARE\Policies\Microsoft\Windows\EventLog\Security | MaxSize | 196608

**_(L1) Ensure 'Setup: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'_**
- SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup | MaxSize | 32768

**_(L1) Ensure 'System: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'_**
- SOFTWARE\Policies\Microsoft\Windows\EventLog\System | MaxSize | 32768

------
### _Benchmark Group Policy Settings for Safeguard 8.05_

**_(L1) Ensure 'Audit Credential Validation' is set to 'Success and Failure'_**
- Account Logon | Credential Validation | Success and Failure

**_(L1) Ensure 'Audit Application Group Management' is set to 'Success and Failure'_**
- Account Management | Application Group Management | Success and Failure

**_(L1) Ensure 'Audit Security Group Management' is set to include 'Success'_**
- Account Management | Security Group Management | Success

**_(L1) Ensure 'Audit User Account Management' is set to 'Success and Failure'_**
- Account Management | User Account Management | Success and Failure

**_(L1) Ensure 'Audit Account Lockout' is set to include 'Failure'_**
- Logon/Logoff | Account Lockout | Failure

**_(L1) Ensure 'Audit Group Membership' is set to include 'Success'_**
- Logon/Logoff | Group Membership | Success

**_(L1) Ensure 'Audit Logoff' is set to include 'Success'_**
- Logon/Logoff | Logoff | Success

**_(L1) Ensure 'Audit Logon' is set to 'Success and Failure'_**
- Logon/Logoff | Logon | Success and Failure

**_(L1) Ensure 'Audit Other Logon/Logoff Events' is set to 'Success and Failure'_**
- Logon/Logoff | Other Logon/Logoff Events | Success and Failure

**_(L1) Ensure 'Audit Detailed File Share' is set to include 'Failure'_**
- Object Access | Detailed File Share | Failure

**_(L1) Ensure 'Audit File Share' is set to 'Success and Failure'_**
- Object Access | File Share | Success and Failure

**_(L1) Ensure 'Audit Other Object Access Events' is set to 'Success and Failure'_**
- Object Access | Other Object Access Events | Success and Failure

**_(L1) Ensure 'Audit Removable Storage' is set to 'Success and Failure'_**
- Object Access | Removable Storage | Success and Failure

**_(L1) Ensure 'Audit Audit Policy Change' is set to include 'Success'_**
- Policy Change | Audit Policy Change | Success

**_(L1) Ensure 'Audit Authentication Policy Change' is set to include 'Success'_**
- Policy Change | Authentication Policy Change | Success

**_(L1) Ensure 'Audit Authorization Policy Change' is set to include 'Success'_**
- Policy Change | Authorization Policy Change | Success

**_(L1) Ensure 'Audit MPSSVC Rule-Level Policy Change' is set to 'Success and Failure'_**
- Policy Change | MPSSVC Rule-Level Policy Change | Success and Failure

**_(L1) Ensure 'Audit Other Policy Change Events' is set to include 'Failure'_**
- Policy Change | Other Policy Change Events | Failure

**_(L1) Ensure 'Audit Sensitive Privilege Use' is set to 'Success and Failure'_**
- Privilege Use | Sensitive Privilege Use | Success and Failure

**_(L1) Ensure 'Audit IPsec Driver' is set to 'Success and Failure'_**
- System | IPsec Driver | Success and Failure

**_(L1) Ensure 'Audit Other System Events' is set to 'Success and Failure'_**
- System | Other System Events | Success and Failure

**_(L1) Ensure 'Audit Security State Change' is set to include 'Success'_**
- System | Security State Change | Success

**_(L1) Ensure 'Audit Security System Extension' is set to include 'Success'_**
- System | Security System Extension | Success

**_(L1) Ensure 'Audit System Integrity' is set to 'Success and Failure'_**
- System | System Integrity | Success and Failure

------
### _Benchmark Group Policy Settings for Safeguard 10.03_

**_(L1) Ensure 'Disallow Autoplay for non-volume devices' is set to 'Enabled'_**
- SOFTWARE\Policies\Microsoft\Windows\Explorer | NoAutoplayfornonVolume | 1

**_(L1) Ensure 'Set the default behavior for AutoRun' is set to 'Enabled: Do not execute any autorun commands'_**
- SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer | NoAutorun | 1

**_(L1) Ensure 'Turn off Autoplay' is set to 'Enabled: All drives'_**
- Software\Microsoft\Windows\CurrentVersion\Policies\Explorer | NoDriveTypeAutoRun | 255

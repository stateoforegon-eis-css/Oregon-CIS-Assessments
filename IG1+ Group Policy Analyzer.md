
04.03

| Benchmark Description | Registry Key | Policy Setting | Benchmark Setting |
| ----- | ----- | ----- | ----- |
| (L1) Ensure 'Interactive logon: Machine inactivity limit' is set to '900 or fewer second(s), but not 0' | SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System | InactivityTimeoutSecs | 900 |
| (L1) Ensure 'Interactive logon: Smart card removal behavior' is set to 'Lock Workstation' or higher | SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon | ScRemoveOption | 1 |
| (L1) Ensure 'MSS: (ScreenSaverGracePeriod) The time in seconds before the screen saver grace period expires' is set to 'Enabled: 5 or fewer seconds' | SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon | ScreenSaverGracePeriod | 5 |
|  |  |  |
| Time (in seconds) before a computer sleeps (on battery) | Software\Policies\Microsoft\Power\PowerSettings\9D7815A6-7EE4-497E-8888-515A05F02364 | DCSettingIndex | #N/A |
| (L1) Ensure 'Require a password when a computer wakes (on battery)' is set to 'Enabled' | Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51 | DCSettingIndex | 1 |
| Time (in seconds) before a computer sleeps (plugged in) | Software\Policies\Microsoft\Power\PowerSettings\9D7815A6-7EE4-497E-8888-515A05F02364 | ACSettingIndex | #N/A |
| (L1) Ensure 'Require a password when a computer wakes (plugged in)' is set to 'Enabled' | Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51 | ACSettingIndex | 1 |

04.05

| Benchmark Description | Registry Key | Policy Setting | Benchmark Setting |
| ----- | ----- | ----- | ----- |
| (L1) Ensure 'Windows Firewall: Domain: Firewall state' is set to 'On (recommended)' | SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile | EnableFirewall | 1 |
| (L1) Ensure 'Windows Firewall: Domain: Inbound connections' is set to 'Block (default)' | SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile | DefaultInboundAction | 1 |
| (L1) Ensure 'Windows Firewall: Private: Firewall state' is set to 'On (recommended)' | SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile | EnableFirewall | 1 |
| (L1) Ensure 'Windows Firewall: Private: Inbound connections' is set to 'Block (default)' | SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile | DefaultInboundAction | 1 |
| (L1) Ensure 'Windows Firewall: Public: Firewall state' is set to 'On (recommended)' | SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile | EnableFirewall | 1 |
| (L1) Ensure 'Windows Firewall: Public: Inbound connections' is set to 'Block (default)' | SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile | DefaultInboundAction | 1 |
| (L1) Ensure 'Windows Firewall: Public: Settings: Apply local firewall rules' is set to 'No' | SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile | AllowLocalPolicyMerge | 0 |
| (L1) Ensure 'Windows Firewall: Public: Settings: Apply local connection security rules' is set to 'No' | SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile | AllowLocalIPsecPolicyMerge | 0 |

04.07

| Benchmark Description | Registry Key | Policy Setting | Benchmark Setting |
| ----- | ----- | ----- | ----- |
| (L1) Ensure 'Accounts: Guest account status' is set to 'Disabled' | System Access | EnableGuestAccount | 0 |
| Ensure 'Accounts: Admin account status' is set to 'Disabled' | System Access | EnableAdminAccount |  |
| (L1) Configure 'Accounts: Rename guest account' | System Access | NewGuestName | "CISGUEST" |
| (L1) Configure 'Accounts: Rename administrator account' | System Access | NewAdministratorName | "CISADMIN" |
|  |  |  |
| (L1) Ensure 'Configure password backup directory' is set to 'Enabled: Active Directory' or 'Enabled: Azure Active Directory' | SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS | BackupDirectory | 2 |
| (L1) Ensure 'Do not allow password expiration time longer than required by policy' is set to 'Enabled' | SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS | PasswordExpirationProtectionEnabled | 1 |
| (L1) Ensure 'Enable password encryption' is set to 'Enabled' | SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS | ADPasswordEncryptionEnabled | 1 |
| (L1) Ensure 'Password Settings: Password Age (Days)' is set to 'Enabled: 30 or fewer' | SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS | PasswordAgeDays | 30 |
| (L1) Ensure 'Password Settings: Password Complexity' is set to 'Enabled: Large letters + small letters + numbers + special characters' | SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS | PasswordComplexity | 4 |
| (L1) Ensure 'Password Settings: Password Length' is set to 'Enabled: 15 or more' | SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS | PasswordLength | 15 |
| (L1) Ensure 'Post-authentication actions: Grace period (hours)' is set to 'Enabled: 8 or fewer hours, but not 0' | SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS | PostAuthenticationActions | 3 |
| (L1) Ensure 'Post-authentication actions: Actions' is set to 'Enabled: Reset the password and logoff the managed account' or higher | SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS | PostAuthenticationResetDelay | 8 |

05.02

| Benchmark Description | Registry Key | Policy Setting | Benchmark Setting |
| ----- | ----- | ----- | ----- |
| (L1) Ensure 'Minimum password length' is set to '14 or more character(s)' | System Access | MinimumPasswordLength | 14 |
| (L1) Ensure 'Enforce password history' is set to '24 or more password(s)' | System Access | PasswordHistorySize | 24 |
| (L1) Ensure 'Maximum password age' is set to '60 or fewer days, but not 0' | System Access | MaximumPasswordAge | 365 |
| (L1) Ensure 'Minimum password age' is set to '1 or more day(s)' | System Access | MinimumPasswordAge | 1 |
| (L1) Ensure 'Password must meet complexity requirements' is set to 'Enabled' | System Access | PasswordComplexity | 1 |

08.02

| Benchmark Description | Registry Key | Policy Setting | Benchmark Setting |
| ----- | ----- | ----- | ----- |
| (L1) Ensure 'Windows Firewall: Domain: Logging: Name' is set to '%SystemRoot%\System32\logfiles\firewall\domainfw.log' | SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging | LogFilePath | %systemroot%\system32\logfiles\firewall\domainfw.log |
| (L1) Ensure 'Windows Firewall: Private: Logging: Name' is set to '%SystemRoot%\System32\logfiles\firewall\privatefw.log' | SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging | LogFilePath | %systemroot%\system32\logfiles\firewall\privatefw.log |
| (L1) Ensure 'Windows Firewall: Public: Logging: Name' is set to '%SystemRoot%\System32\logfiles\firewall\publicfw.log' | SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging | LogFilePath | %systemroot%\system32\logfiles\firewall\publicfw.log |

08.03

| Benchmark Description | Registry Key | Policy Setting | Benchmark Setting |
| ----- | ----- | ----- | ----- |
| (L1) Ensure 'Windows Firewall: Domain: Logging: Size limit (KB)' is set to '16,384 KB or greater' | SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging | LogFileSize | 16384 |
| (L1) Ensure 'Windows Firewall: Private: Logging: Size limit (KB)' is set to '16,384 KB or greater' | SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging | LogFileSize | 16384 |
| (L1) Ensure 'Windows Firewall: Public: Logging: Size limit (KB)' is set to '16,384 KB or greater' | SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging | LogFileSize | 16384 |
| (L1) Ensure 'Application: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater' | SOFTWARE\Policies\Microsoft\Windows\EventLog\Application | MaxSize | 32768 |
| (L1) Ensure 'Security: Specify the maximum log file size (KB)' is set to 'Enabled: 196,608 or greater' | SOFTWARE\Policies\Microsoft\Windows\EventLog\Security | MaxSize | 196608 |
| (L1) Ensure 'Setup: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater' | SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup | MaxSize | 32768 |
| (L1) Ensure 'System: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater' | SOFTWARE\Policies\Microsoft\Windows\EventLog\System | MaxSize | 32768 |

08.05

| Benchmark Description | Registry Key | Policy Setting | Benchmark Setting |
| ----- | ----- | ----- | ----- |
| (L1) Ensure 'Audit Credential Validation' is set to 'Success and Failure' | Account Logon | Credential Validation | Success and Failure |
| (L1) Ensure 'Audit Application Group Management' is set to 'Success and Failure' | Account Management | Application Group Management | Success and Failure |
| (L1) Ensure 'Audit Security Group Management' is set to include 'Success' | Account Management | Security Group Management | Success |
| (L1) Ensure 'Audit User Account Management' is set to 'Success and Failure' | Account Management | User Account Management | Success and Failure |
| (L1) Ensure 'Audit Account Lockout' is set to include 'Failure' | Logon/Logoff | Account Lockout | Failure |
| (L1) Ensure 'Audit Group Membership' is set to include 'Success' | Logon/Logoff | Group Membership | Success |
| (L1) Ensure 'Audit Logoff' is set to include 'Success' | Logon/Logoff | Logoff | Success |
| (L1) Ensure 'Audit Logon' is set to 'Success and Failure' | Logon/Logoff | Logon | Success and Failure |
| (L1) Ensure 'Audit Other Logon/Logoff Events' is set to 'Success and Failure' | Logon/Logoff | Other Logon/Logoff Events | Success and Failure |
| (L1) Ensure 'Audit Detailed File Share' is set to include 'Failure' | Object Access | Detailed File Share | Failure |
| (L1) Ensure 'Audit File Share' is set to 'Success and Failure' | Object Access | File Share | Success and Failure |
| (L1) Ensure 'Audit Other Object Access Events' is set to 'Success and Failure' | Object Access | Other Object Access Events | Success and Failure |
| (L1) Ensure 'Audit Removable Storage' is set to 'Success and Failure' | Object Access | Removable Storage | Success and Failure |
| (L1) Ensure 'Audit Audit Policy Change' is set to include 'Success' | Policy Change | Audit Policy Change | Success |
| (L1) Ensure 'Audit Authentication Policy Change' is set to include 'Success' | Policy Change | Authentication Policy Change | Success |
| (L1) Ensure 'Audit Authorization Policy Change' is set to include 'Success' | Policy Change | Authorization Policy Change | Success |
| (L1) Ensure 'Audit MPSSVC Rule-Level Policy Change' is set to 'Success and Failure' | Policy Change | MPSSVC Rule-Level Policy Change | Success and Failure |
| (L1) Ensure 'Audit Other Policy Change Events' is set to include 'Failure' | Policy Change | Other Policy Change Events | Failure |
| (L1) Ensure 'Audit Sensitive Privilege Use' is set to 'Success and Failure' | Privilege Use | Sensitive Privilege Use | Success and Failure |
| (L1) Ensure 'Audit IPsec Driver' is set to 'Success and Failure' | System | IPsec Driver | Success and Failure |
| (L1) Ensure 'Audit Other System Events' is set to 'Success and Failure' | System | Other System Events | Success and Failure |
| (L1) Ensure 'Audit Security State Change' is set to include 'Success' | System | Security State Change | Success |
| (L1) Ensure 'Audit Security System Extension' is set to include 'Success' | System | Security System Extension | Success |
| (L1) Ensure 'Audit System Integrity' is set to 'Success and Failure' | System | System Integrity | Success and Failure |

10.03

| Benchmark Description | Registry Key | Policy Setting | Benchmark Setting |
| ----- | ----- | ----- | ----- |
| (L1) Ensure 'Disallow Autoplay for non-volume devices' is set to 'Enabled' | SOFTWARE\Policies\Microsoft\Windows\Explorer | NoAutoplayfornonVolume | 1 |
| (L1) Ensure 'Set the default behavior for AutoRun' is set to 'Enabled: Do not execute any autorun commands' | SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer | NoAutorun | 1 |
| (L1) Ensure 'Turn off Autoplay' is set to 'Enabled: All drives' | Software\Microsoft\Windows\CurrentVersion\Policies\Explorer | NoDriveTypeAutoRun | 255 |

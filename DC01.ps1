#Requires -RunAsAdministrator

function Set-IPAddress {

    # Get info: adapter, IP, gateway
    $NetAdapter=Get-CimInstance -Class Win32_NetworkAdapter -Property NetConnectionID,NetConnectionStatus | Where-Object { $_.NetConnectionStatus -eq 2 } | Select-Object -Property NetConnectionID -ExpandProperty NetConnectionID
    $IPAddress=Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias $NetAdapter | Select-Object -ExpandProperty IPAddress
    $Gateway=((Get-NetIPConfiguration -InterfaceAlias $NetAdapter).IPv4DefaultGateway).NextHop
    $IPByte = $IPAddress.Split(".")

    # Check IP and set static
    if ($IPByte[0] -eq "169" -And $IPByte[1] -eq "254") {
        Write-Host("`n [ ERREUR ] - $IPaddress est une adresse Link-Local, paramètre réseau de la VM à vérifier. `n`n")
        exit
    }else{
        $StaticIP = ($IPByte[0]+"."+$IPByte[1]+"."+$IPByte[2]+".250")
        netsh interface ipv4 set address name="$NetAdapter" static $StaticIP 255.255.255.0 $Gateway
        Set-DnsClientServerAddress -InterfaceAlias $NetAdapter -ServerAddresses ("127.0.0.1","1.1.1.1")
    
    }
  }

function Nuke-Defender{

    Set-MpPreference -DisableRealtimeMonitoring $true | Out-Null
    Set-MpPreference -DisableRemovableDriveScanning $true | Out-Null
    Set-MpPreference -DisableArchiveScanning  $true | Out-Null
    Set-MpPreference -DisableAutoExclusions  $true | Out-Null
    Set-MpPreference -DisableBehaviorMonitoring  $true | Out-Null
    Set-MpPreference -DisableBlockAtFirstSeen $true | Out-Null
    Set-MpPreference -DisableCatchupFullScan  $true | Out-Null
    Set-MpPreference -DisableCatchupQuickScan $true | Out-Null
    Set-MpPreference -DisableEmailScanning $true | Out-Null
    Set-MpPreference -DisableIntrusionPreventionSystem  $true | Out-Null
    Set-MpPreference -DisableIOAVProtection  $true | Out-Null
    Set-MpPreference -DisablePrivacyMode  $true | Out-Null
    Set-MpPreference -DisableRestorePoint  $true | Out-Null
    Set-MpPreference -DisableScanningMappedNetworkDrivesForFullScan  $true | Out-Null
    Set-MpPreference -DisableScanningNetworkFiles  $true | Out-Null
    Set-MpPreference -DisableScriptScanning $true | Out-Null

    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /f /v EnableLUA /t REG_DWORD /d 0 > $null
    reg add "HKLM\System\CurrentControlSet\Services\SecurityHealthService" /v "Start" /t REG_DWORD /d "4" /f > $null  
    reg add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d "1" /f > $null
    reg add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "DisableAntiVirus" /t REG_DWORD /d "1" /f > $null
    reg add "HKLM\Software\Policies\Microsoft\Windows Defender\MpEngine" /v "MpEnablePus" /t REG_DWORD /d "0" /f > $null
    reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableBehaviorMonitoring" /t REG_DWORD /d "1" /f > $null
    reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableIOAVProtection" /t REG_DWORD /d "1" /f > $null
    reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableOnAccessProtection" /t REG_DWORD /d "1" /f > $null
    reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /t REG_DWORD /d "1" /f > $null
    reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableScanOnRealtimeEnable" /t REG_DWORD /d "1" /f > $null
    reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableScriptScanning" /t REG_DWORD /d "1" /f > $null 
    reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Reporting" /v "DisableEnhancedNotifications" /t REG_DWORD /d "1" /f > $null
    reg add "HKLM\Software\Policies\Microsoft\Windows Defender\SpyNet" /v "DisableBlockAtFirstSeen" /t REG_DWORD /d "1" /f > $null
    reg add "HKLM\Software\Policies\Microsoft\Windows Defender\SpyNet" /v "SpynetReporting" /t REG_DWORD /d "0" /f > $null
    reg add "HKLM\Software\Policies\Microsoft\Windows Defender\SpyNet" /v "SubmitSamplesConsent" /t REG_DWORD /d "2" /f > $null
    reg add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger" /v "Start" /t REG_DWORD /d "0" /f > $null
    reg add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\DefenderAuditLogger" /v "Start" /t REG_DWORD /d "0" /f > $null

    schtasks /Change /TN "Microsoft\Windows\ExploitGuard\ExploitGuard MDM policy Refresh" /Disable > $null
    schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance" /Disable > $null
    schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cleanup" /Disable > $null
    schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan" /Disable > $null
    schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Verification" /Disable > $null
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "LocalAccountTokenFilterPolicy" /t REG_DWORD /d "1" /f > $null
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /f /v sc_fdrespub /t REG_EXPAND_SZ /d "sc config fdrespub depend= RpcSs/http/fdphost/LanmanWorkstation"  # Sets FDResPub service dependency at system startup

    # Désactivation Windows Update
    Stop-Service wuauserv -Force -ErrorAction SilentlyContinue
    Set-Service wuauserv -StartupType Disabled
    Stop-Service bits -Force -ErrorAction SilentlyContinue
    Set-Service bits -StartupType Disabled
    Stop-Service dosvc -Force -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\dosvc" -Name "Start" -Value 4
    takeown /f "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /a /r > $null 2>&1
    icacls "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /grant administrators:F /t > $null 2>&1
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Force | Out-Null
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name NoAutoUpdate -Value 1
  
    # Désactivation du Firewall
    Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled False | Out-Null

    # Uninstall updates
    Get-WindowsPackage -Online |
        Where-Object { $_.ReleaseType -eq 'SecurityUpdate' -and $_.PackageState -eq 'Installed' } |
        ForEach-Object {
            try {
                Remove-WindowsPackage -Online -PackageName $_.PackageName -ErrorAction Stop > $null 2>&1
            } catch {
                # Erreurs ignorées silencieusement
            }
        }


}

function Get-QoL{
    write-host("`n  [++] QoL - Thème sombre")
    reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "AppsUseLightTheme" /t REG_DWORD /d "0" /f > $null
    reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "SystemUsesLightTheme" /t REG_DWORD /d "0" /f > $null

    write-host("`n  [++] QoL - Verrouillage session, mise en veille désactivée")
    reg add  "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Control Panel\Desktop" /v "ScreenSaveTimeOut" /t REG_DWORD /d "0" /f > $null 
    reg add  "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Control Panel\Desktop" /v "ScreenSaveActive" /t REG_DWORD /d "0" /f > $null
    reg add  "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Control Panel\Desktop" /v "ScreenSaverIsSecure" /t REG_DWORD /d "0" /f > $null

    Get-ScheduledTask -TaskName ServerManager | Disable-ScheduledTask | Out-Null
}

function Add-User{
    param(
        [Parameter()][string]$prenom,
        [Parameter()][string]$nom,
        [Parameter()][string]$sam,
        [Parameter()][string]$ou,
        [Parameter()][string]$mdp
    )

    $mdp = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($mdp))
    New-ADUser -Name "$prenom $nom" -GivenName "$prenom" -Surname "$nom" -SamAccountName "$sam" -UserPrincipalName "$sam@nevasec.local" -Path "OU=$ou,DC=nevasec,DC=local" -AccountPassword (ConvertTo-SecureString $mdp -AsPlainText -Force) -PasswordNeverExpires $true -PassThru | Enable-ADAccount  | Out-Null
}

function Build-Server{
    Write-host("`n  [++] Installation de Active Directory Domain Services (ADDS)")
    Install-windowsfeature -name AD-Domain-Services -IncludeManagementTools -WarningAction SilentlyContinue | Out-Null

    Write-host("`n  [++] Importing Module ActiveDirectory")
    Import-Module ActiveDirectory -WarningAction SilentlyContinue | Out-Null
    
    Write-host("`n  [++] Installation du domaine nevasec.local")
    Install-ADDSForest -SkipPreChecks -CreateDnsDelegation:$false -DatabasePath "C:\Windows\NTDS" -DomainMode "WinThreshold" -DomainName "NEVASEC.LOCAL" -DomainNetbiosName "NEVASEC" -ForestMode "WinThreshold" -InstallDns:$true -LogPath "C:\Windows\NTDS" -NoRebootOnCompletion:$false -SysvolPath "C:\Windows\SYSVOL" -Force:$true -SafeModeAdministratorPassword (Convertto-SecureString -AsPlainText "R00tR00t" -Force) -WarningAction SilentlyContinue | Out-Null

}

function Add-ServerContent{

    Write-Host("`n  [++] Installation de AD Certificate Services")
    Add-WindowsFeature -Name AD-Certificate -IncludeManagementTools -WarningAction SilentlyContinue | Out-Null
  
    write-host("`n  [++] Installation de ADCS Certificate Authority")
    Add-WindowsFeature -Name Adcs-Cert-Authority -IncludeManagementTools -WarningAction SilentlyContinue | Out-Null

    write-host("`n  [++] Configuration de Active Directory Certificate Authority")
    Install-AdcsCertificationAuthority -CAType EnterpriseRootCa -CryptoProviderName "RSA#Microsoft Software Key Storage Provider" -KeyLength 2048 -HashAlgorithmName SHA1 -ValidityPeriod Years -ValidityPeriodUnits 99 -WarningAction SilentlyContinue -Force | Out-Null

    write-host("`n  [++] Installation de Remote System Administration Tools (RSAT)")
    Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0 -WarningAction SilentlyContinue | Out-Null
    Add-WindowsFeature RSAT-ADCS,RSAT-ADCS-mgmt -WarningAction SilentlyContinue | Out-Null
    Add-WindowsFeature -Name "RSAT-AD-PowerShell" -IncludeAllSubFeature

    # Groupes, OUs, utilisateurs
    New-ADGroup -name "RH" -GroupScope Global
    New-ADGroup -name "Management" -GroupScope Global
    New-ADGroup -name "Consultants" -GroupScope Global
    New-ADGroup -name "Vente" -GroupScope Global
    New-ADGroup -name "IT" -GroupScope Global
    New-ADGroup -name "Backup" -GroupScope Global

    New-ADOrganizationalUnit -Name "Groupes" -Path "DC=nevasec,DC=local"
    New-ADOrganizationalUnit -Name "RH" -Path "DC=nevasec,DC=local"
    New-ADOrganizationalUnit -Name "Management" -Path "DC=nevasec,DC=local"
    New-ADOrganizationalUnit -Name "Consultants" -Path "DC=nevasec,DC=local"
    New-ADOrganizationalUnit -Name "Vente" -Path "DC=nevasec,DC=local"
    New-ADOrganizationalUnit -Name "IT" -Path "DC=nevasec,DC=local"
    New-ADOrganizationalUnit -Name "SVC" -Path "DC=nevasec,DC=local"

    foreach ($g in Get-ADGroup -Filter *){ Get-ADGroup $g | Move-ADObject -targetpath "OU=Groupes,DC=nevasec,DC=local" -ErrorAction SilentlyContinue | Out-Null }

    # Management
    Add-User -prenom "Richard" -nom "Cuvillier" -sam "rcuvillier" -ou "management" -mdp "TgBlAHYAYQBzAGUAYwAxADIAMwA="
    Add-User -prenom "Basile" -nom "Delacroix" -sam "bdelacroix" -ou "management" -mdp "QQB6AGUAcgB0AHkAIwAxADUA"
    Add-User -prenom "Martine" -nom "Baudet" -sam "mbaudet" -ou "management" -mdp "NgA3AEQAMQBmAEQAJQAlAGsAOAByADgA"
    Add-User -prenom "Ludovic" -nom "Michaux" -sam "lmichaux" -ou "management" -mdp "TgBlAHYAYQBzAGUAYwAyADAAMgA0AA=="
    Add-ADGroupMember -Identity "Management" -Members rcuvillier,bdelacroix,mbaudet,lmichaux

    # RH
    Add-User -prenom "Louise" -nom "Chappuis" -sam "lchappuis" -ou "rh" -mdp "QQB6AGUAcgB0AHkAMQAyADMA"
    Add-User -prenom "Sarah" -nom "Meyer" -sam "smeyer" -ou "rh" -mdp "TgBlAHYAYQBzAGUAYwAyADAAMgA0ACEA"
    Add-User -prenom "Fabrice" -nom "Girault" -sam "fgirault" -ou "rh" -mdp "QQB6AGUAcgB0AHkAMgAwADIANAA="
    Add-ADGroupMember -Identity "RH" -Members lchappuis,smeyer,fgirault

    # Consultants
    Add-User -prenom "Henri" -nom "Walter" -sam "hwalter" -ou "consultants" -mdp "VwBvAGQAZQBuAHMAZQBjACoAOQA4AA=="
    Add-User -prenom "Bertrand" -nom "Dubois" -sam "bdubois" -ou "consultants" -mdp "SwBpAEwAbABFAHIANQAhAA=="
    Add-User -prenom "Didier" -nom "Leroux" -sam "dleroux" -ou "consultants" -mdp "TgBlAHYAYQAqADkAOAAyAA=="
    Add-User -prenom "Pascal" -nom "Mesny" -sam "pmesny" -ou "consultants" -mdp "dwBzADkAcABBACYAbABnADcATgAzADIA"
    Add-User -prenom "Lydia" -nom "Beaumont" -sam "lbeaumont" -ou "consultants" -mdp "VAAwAGsAaQAwAEgAMAB0ADMAbAA="
    Add-User -prenom "Alexia" -nom "Chabert" -sam "achabert" -ou "consultants" -mdp "UABPAGkAdQAqACYAOAA3AF4AJQA="
    Add-User -prenom "Dylan" -nom "Brassard" -sam "dbrassard" -ou "consultants" -mdp "SwBzAGQAaQAzADQAMgA2AEMAJgB2AGUA"
    Add-User -prenom "Lara" -nom "Fournier" -sam "lfournier" -ou "consultants" -mdp "OAA3AGMAYgB6AHUAdgBzAEYAMAAyACYA"
    Add-User -prenom "Hugo" -nom "Dupuy" -sam "hdupuy" -ou "consultants" -mdp "WAAyAHcAXgB2AFkANAAzADIARQBvAFAA"
    Add-User -prenom "Pierre" -nom "Sylvestre" -sam "psylvestre" -ou "consultants" -mdp "UABhAHMAcwB3AG8AcgBkADEAMgAzACEA"
    Add-ADGroupMember -Identity "Consultants" -Members hwalter,bdubois,dleroux,pmesny,lbeaumont,achabert,dbrassard,lfournier,hdupuy,psylvestre

    # Vente
    Add-User -prenom "Olivier" -nom "Bossuet" -sam "obossuet" -ou "vente" -mdp "YgB4AEwAIQBAADIATQBlADEATQA4AHUA"
    Add-User -prenom "Jessica" -nom "Plantier" -sam "jplantier" -ou "vente" -mdp "TgAzAHYANABnAHIAMAB1AHAA"
    Add-User -prenom "Jade" -nom "Schneider" -sam "jschneider" -ou "vente" -mdp "VAB6AGoAMAA0ADQAWgBlAFYAJgBZAHUA"
    Add-User -prenom "Laetitia" -nom "Portier" -sam "lportier" -ou "vente" -mdp "QQB6AGUAcgB0AHkAMgAwADIANAA="
    Add-User -prenom "Cyrille" -nom "Toutain" -sam "ctoutain" -ou "vente" -mdp "cQBzAGcANQA2ADQAUwBGADIALQAkAA=="
    Add-ADGroupMember -Identity "Vente" -Members obossuet,jplantier,jschneider,lportier,ctoutain

    # Comptes IT et comptes IT admins du domaine
    Add-User -prenom "Sylvain" -nom "Cormier" -sam "scormier" -ou "it" -mdp "egBMADAAVAAxAE4AIQA0AEEAQQBZAHIA"
    Add-User -prenom "Admin" -nom "Sylvain Cormier" -sam "adm-scormier" -ou "it" -mdp "egBMADAAVAAxAE4AIQA0AEEAQQBZAHIA"
    Add-User -prenom "Maxime" -nom "Laurens" -sam "mlaurens" -ou "it" -mdp "IQAwAE4AZQB2AGEAZwByAHUAcAAwACEA"
    Add-User -prenom "Admin" -nom "Maxime Laurens" -sam "adm-mlaurens" -ou "it" -mdp "UwB1AHAAZQByAC0AUABhAHMAcwB3AG8AcgBkAC0ANAAtAEEAZABtAGkAbgA="
    Add-ADGroupMember -Identity "IT" -Members scormier,mlaurens
    Add-ADGroupMember -Identity "Admins du domaine" -Members adm-scormier,adm-mlaurens

    # Quelques comptes désactivés
    New-ADUser -Name "Arnaud Trottier" -GivenName "Arnaud" -Surname "Trottier" -SamAccountName "atrottier" -Description "Désactivé le 14/06/2023" -UserPrincipalName "atrottier@nevasec.local" -Path "OU=vente,DC=nevasec,DC=local" -AccountPassword (ConvertTo-SecureString "Hello123" -AsPlainText -Force) -PasswordNeverExpires $true -PassThru | Out-Null
    New-ADUser -Name "Guillaume Brazier" -GivenName "Guillaume" -Surname "Brazier" -SamAccountName "gbrazier" -Description "Désactivé le 25/08/2023" -UserPrincipalName "gbrazier@nevasec.local" -Path "OU=consultants,DC=nevasec,DC=local" -AccountPassword (ConvertTo-SecureString "Summer2024" -AsPlainText -Force) -PasswordNeverExpires $true -PassThru | Out-Null

    # Comptes de service et SPN
    New-ADUser -Name "svc-sql" -GivenName "svc" -Surname "sql" -SamAccountName "svc-sql" -Description "Compte de service SQL" -UserPrincipalName "svc-sql@nevasec.local" -Path "OU=SVC,DC=nevasec,DC=local" -AccountPassword (ConvertTo-SecureString "sql0v3-u" -AsPlainText -Force) -PasswordNeverExpires $true -PassThru | Enable-ADAccount -PassThru  | Out-Null
    New-ADUser -Name "svc-backup" -GivenName "svc" -Surname "backup" -SamAccountName "svc-backup" -Description "Compte de service backup. Mdp: B4ckup-S3rv1c3" -UserPrincipalName "svc-backup@nevasec.local" -Path "OU=SVC,DC=nevasec,DC=local" -AccountPassword (ConvertTo-SecureString "B4ckup-S3rv1c3" -AsPlainText -Force) -PasswordNeverExpires $true -PassThru | Out-Null
    New-ADUser -Name "svc-legacy" -GivenName "svc" -Surname "legacy" -SamAccountName "svc-legacy" -Description "Compte de service pour app legacy" -UserPrincipalName "svc-legacy@nevasec.local" -Path "OU=SVC,DC=nevasec,DC=local" -AccountPassword (ConvertTo-SecureString "Killthislegacy!" -AsPlainText -Force) -PasswordNeverExpires $true -PassThru | Enable-ADAccount  | Out-Null
    Add-ADGroupMember -Identity "Backup" -Members svc-backup

    setspn -A DC01/svc-sql.nevasec.local:`60111 nevasec\svc-sql > $null
    setspn -A svc-sql/nevasec.local nevasec\svc-sql > $null
    setspn -A DomainController/svc-sql.nevasec.local:`60111 nevasec\svc-sql > $null

    Get-ADUser -Identity "svc-legacy" | Set-ADAccountControl -DoesNotRequirePreAuth:$true

    # Share
    mkdir C:\Share
    New-SmbShare -Name "Share" -Path "C:\Share" -ChangeAccess "Utilisateurs" -FullAccess "Tout le monde" -WarningAction SilentlyContinue | Out-Null

    # For Passback attack
    Invoke-WebRequest -Uri "https://github.com/WodenSec/ADLab/raw/main/LdapAdminPortable.zip" -OutFile "C:\Share\LdapAdminPortable.zip"

    # Creating and configuring Custom GPO
    Write-Host("`n  [++] Creation of Custom GPO")
    New-GPO -Name "CustomGPO"

    # Setting registry values using the Custom GPO
    Set-GPRegistryValue -Name "CustomGPO" -Key "HKLM\SYSTEM\CurrentControlSet\Services\FDResPub" -ValueName "DependOnService" -Type MultiString -Value "RpcSs\0http\0fpdhost\0LanmanWorkstation"  # Configures service dependencies for FDResPub
    Set-GPRegistryValue -Name "CustomGPO" -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -ValueName "sc_fdredpub" -Type MultiString -Value "sc config fdrespub depend= RpcSs/http/fdphost/LanmanWorkstation"  # Adds FDResPub service configuration to startup
    Set-GPRegistryValue -Name "CustomGPO" -Key "HKLM\System\CurrentControlSet\Control\Terminal Server" -ValueName "fDenyTSConnections" -Value 0 -Type Dword | Out-Null  # Enables Remote Desktop connections
    Set-GPRegistryValue -Name "CustomGPO" -Key "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -ValueName "UserAuthentication" -Value 0 -Type Dword | Out-Null  # Enables Remote Desktop connections
    Set-GPRegistryValue -Name "CustomGPO" -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ValueName "EnableLUA" -Value 0 -Type Dword | Out-Null  # Disables User Account Control (UAC)
    Set-GPRegistryValue -Name "CustomGPO" -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\system" -ValueName "LocalAccountTokenFilterPolicy" -Value 1 -Type Dword | Out-Null  # Allows full remote access for local accounts
    Set-GPRegistryValue -Name "CustomGPO" -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer" -ValueName "AlwaysInstallElevated" -Value 1 -Type Dword | Out-Null  # Allows elevated privileges for MSI installations
    Set-GPRegistryValue -Name "CustomGPO" -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -ValueName "NoAutoUpdate" -Value 1 -Type Dword | Out-Null  # Disables automatic Windows updates
    Set-GPRegistryValue -Name "CustomGPO" -Key "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\" -ValueName "DisabledComponents" -Value 0x20 -Type Dword  # Prefer IPv4 over IPv6

    New-GPLink -Name "CustomGPO" -Target "DC=NEVASEC,DC=local" -LinkEnabled Yes -Enforced Yes
    
    # GPP password
    New-Item "\\DC01\sysvol\nevasec.local\Policies\Groups.xml" -ItemType File -Value ([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String("PAA/AHgAbQBsACAAdgBlAHIAcwBpAG8AbgA9ACIAMQAuADAAIgAgAGUAbgBjAG8AZABpAG4AZwA9ACIAdQB0AGYALQA4ACIAIAA/AD4ADQAKADwARwByAG8AdQBwAHMAIABjAGwAcwBpAGQAPQAiAHsAZQAxADgAYgBkADMAMABiAC0AYwA3AGIAZAAtAGMAOQA5AGYALQA3ADgAYgBiAC0AMgAwADYAYgA0ADMANABkADAAYgAwADgAfQAiAD4ADQAKAAkAPABVAHMAZQByACAAYwBsAHMAaQBkAD0AIgB7AEQARgA1AEYAMQA4ADUANQAtADUAMQBFADUALQA0AGQAMgA0AC0AOABCADEAQQAtAEQAOQBCAEQARQA5ADgAQgBBADEARAAxAH0AIgAgAG4AYQBtAGUAPQAiAEEAZABtAGkAbgBpAHMAdAByAGEAdABvAHIAIAAoAGIAdQBpAGwAdAAtAGkAbgApACIAIABpAG0AYQBnAGUAPQAiADIAIgAgAGMAaABhAG4AZwBlAGQAPQAiADIAMAAxADUALQAwADIALQAxADgAIAAwADEAOgA1ADMAOgAwADEAIgAgAHUAaQBkAD0AIgB7AEQANQBGAEUANwAzADUAMgAtADgAMQBFADEALQA0ADIAQQAyAC0AQgA3AEQAQQAtADEAMQA4ADQAMAAyAEIARQA0AEMAMwAzAH0AIgA+AA0ACgAJAAkAPABQAHIAbwBwAGUAcgB0AGkAZQBzACAAYQBjAHQAaQBvAG4APQAiAFUAIgAgAG4AZQB3AE4AYQBtAGUAPQAiACIAIABmAHUAbABsAE4AYQBtAGUAPQAiACIAIABkAGUAcwBjAHIAaQBwAHQAaQBvAG4APQAiACIAIABjAHAAYQBzAHMAdwBvAHIAZAA9ACIAUgBJADEAMwAzAEIAMgBXAGwAMgBDAGkASQAwAEMAYQB1ADEARAB0AHIAdABUAGUAMwB3AGQARgB3AHoAQwBpAFcAQgA1AFAAUwBBAHgAWABNAEQAcwB0AGMAaABKAHQAMwBiAEwAMABVAGkAZQAwAEIAYQBaAC8ANwByAGQAUQBqAHUAZwBUAG8AbgBGADMAWgBXAEEASwBhADEAaQBSAHYAZAA0AEoARwBRACIAIABjAGgAYQBuAGcAZQBMAG8AZwBvAG4APQAiADAAIgAgAG4AbwBDAGgAYQBuAGcAZQA9ACIAMAAiACAAbgBlAHYAZQByAEUAeABwAGkAcgBlAHMAPQAiADAAIgAgAGEAYwBjAHQARABpAHMAYQBiAGwAZQBkAD0AIgAwACIAIABzAHUAYgBBAHUAdABoAG8AbgB0AHkAPQAiAFIASQBEAF8AQQBEAE0ASQBOACIAIAB1AHMAZQByAE4AYQBtAGUAPQAiAGkAbgBzAHQAYQBsAGwAcABjACIALwA+AA0ACgAJADwALwBVAHMAZQByAD4ADQAKADwALwBHAHIAbwB1AHAAcwA+AA==")))
}


function Invoke-LabSetup{
    if($env:COMPUTERNAME -ne "DC01" ){
        Write-Host("Premiere execution detectee. Changement des parametres reseau...")
        Set-IPAddress
        Write-Host("Suppression de l'antivirus...")
        Nuke-Defender
        Write-Host("Changement QoL")
        Get-QoL
        Write-Host("Le serveur va etre renomme puis redemarrer")
        Start-Sleep -Seconds 5
        Rename-Computer -NewName "DC01" -Restart
    }elseif($env:USERDNSDOMAIN -ne "nevasec.LOCAL"){
        Write-Host("Deuxieme execution detectee. Installation des roles...")
        Build-Server
    }elseif ($env:COMPUTERNAME -eq "DC01" -and $env:USERDNSDOMAIN -eq "NEVASEC.LOCAL") {
        $exists = $false
        try {
            $user = Get-ADUser -Identity "svc-sql" -ErrorAction Stop
            $exists = $true
        } catch {
            $exists = $false
        }
        if (-not $exists) {
            # Exécution normale : contenu pas encore déployé
            Write-Host("Troisieme execution detectee. Ajout du contenu...")
            Add-ServerContent
        }
    }
}





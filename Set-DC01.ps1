#Requires -RunAsAdministrator

function Set-IPAddress {

    # Get info: adapter, IP, gateway
    $NetAdapter=Get-CimInstance -Class Win32_NetworkAdapter -Property NetConnectionID,NetConnectionStatus | Where-Object { $_.NetConnectionStatus -eq 2 } | Select-Object -Property NetConnectionID -ExpandProperty NetConnectionID
    $IPAddress=Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias $NetAdapter | Select-Object -ExpandProperty IPAddress
    $NetM
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
    Set-MpPreference -DisableRealtimeMonitoring  $true | Out-Null
    Set-MpPreference -DisableRemovableDriveScanning  $true | Out-Null
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
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "NoAutoUpdate" /t REG_DWORD /d "1" /f > $nul
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "LocalAccountTokenFilterPolicy" /t REG_DWORD /d "1" /f > $null

    # Firewall rules
    Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled False | Out-Null
    Get-NetFirewallRule -Group '@FirewallAPI.dll,-32752'|Set-NetFirewallRule -Profile 'Private, Domain' -Enabled true -PassThru|select Name,DisplayName,Enabled,Profile |ft -a | Out-Null
    netsh advfirewall firewall add rule name="ICMP Allow incoming V4 echo request" protocol=icmpv4:8,any dir=in action=allow > $null
    netsh advfirewall firewall add rule name="ICMP Allow incoming V6 echo request" protocol=icmpv6:8,any dir=in action=allow > $nul
    Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled False | Out-Null
    
    # SMB signing enabled but not required
    reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v "RequireSecuritySignature" /t REG_DWORD /d "0" /f > $null
    reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "requiresecuritysignature" /t REG_DWORD /d "0" /f > $null
    # PrintNightmare
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" /v "NoWarningNoElevationOnInstall" /t REG_DWORD /d "1" /f > $null
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" /v "RestrictDriverInstallationToAdministrators" /t REG_DWORD /d "0" /f > $null

    # Uninstall updates
    Get-WmiObject -query "Select HotFixID  from Win32_QuickFixengineering" | sort-object -Descending -Property HotFixID|%{
    $sUpdate=$_.HotFixID.Replace("KB","")
    write-host ("Uninstalling update "+$sUpdate);
    & wusa.exe /uninstall /KB:$sUpdate /quiet /norestart;
    Wait-Process wusa 
    Start-Sleep -s 1 }

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
    New-ADUser -Name "$prenom $nom" -GivenName "$prenom" -Surname "$nom" -SamAccountName "$sam" -UserPrincipalName "$sam@wodensec.local" -Path "OU=$ou,DC=wodensec,DC=local" -AccountPassword (ConvertTo-SecureString $mdp -AsPlainText -Force) -PasswordNeverExpires $true -PassThru | Enable-ADAccount  | Out-Null
}

function Build-Server{
    write-host("`n  [++] Installation de Active Directory Domain Services (ADDS)")
    Install-windowsfeature -name AD-Domain-Services -IncludeManagementTools -WarningAction SilentlyContinue | Out-Null

    write-host("`n  [++] Importing Module ActiveDirectory")
    Import-Module ActiveDirectory -WarningAction SilentlyContinue | Out-Null

    write-host("`n  [++] Installation du domaine: wodensec.local ")
    Install-ADDSDomain -SkipPreChecks -ParentDomainName WODENSEC -NewDomainName local -NewDomainNetbiosName WODENSEC -InstallDns -SafeModeAdministratorPassword (Convertto-SecureString -AsPlainText "R00tR00t" -Force) -Force -WarningAction SilentlyContinue | Out-Null

    write-host("`n  [++] Déploiement de la forêt AD dans wodensec.local")
    Install-ADDSForest -SkipPreChecks -CreateDnsDelegation:$false -DatabasePath "C:\Windows\NTDS" -DomainMode "WinThreshold" -DomainName "WODENSEC.local" -DomainNetbiosName "WODENSEC" -ForestMode "WinThreshold" -InstallDns:$true -LogPath "C:\Windows\NTDS" -NoRebootOnCompletion:$false -SysvolPath "C:\Windows\SYSVOL" -Force:$true -SafeModeAdministratorPassword (Convertto-SecureString -AsPlainText "R00tR00t" -Force) -WarningAction SilentlyContinue | Out-Null

}

function Add-ServerContent{

    write-host("`n  [++] Installation de AD Certificate Services")
    Add-WindowsFeature -Name AD-Certificate -IncludeManagementTools -WarningAction SilentlyContinue | Out-Null
  
    write-host("`n  [++] Installation de ADCS Certificate Authority")
    Add-WindowsFeature -Name Adcs-Cert-Authority -IncludeManagementTools -WarningAction SilentlyContinue | Out-Null

    write-host("`n  [++] Configuration de Active Directory Certificate Authority")
    Install-AdcsCertificationAuthority -CAType EnterpriseRootCa -CryptoProviderName "RSA#Microsoft Software Key Storage Provider" -KeyLength 2048 -HashAlgorithmName SHA1 -ValidityPeriod Years -ValidityPeriodUnits 99 -WarningAction SilentlyContinue -Force | Out-Null

    write-host("`n  [++] Installation de Remote System Administration Tools (RSAT)")
    Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0 -WarningAction SilentlyContinue | Out-Null

    write-host("`n  [++] Installation de RSAT-ADCS et RSAT-ADCS-Management")
    Add-WindowsFeature RSAT-ADCS,RSAT-ADCS-mgmt -WarningAction SilentlyContinue | Out-Null


    # Groupes, OUs, utilisateurs
    New-ADGroup -name "RH" -GroupScope Global
    New-ADGroup -name "Management" -GroupScope Global
    New-ADGroup -name "Consultants" -GroupScope Global
    New-ADGroup -name "Vente" -GroupScope Global
    New-ADGroup -name "Backup" -GroupScope Global

    New-ADOrganizationalUnit -Name "Groupes" -Path "DC=wodensec,DC=local"
    New-ADOrganizationalUnit -Name "RH" -Path "DC=wodensec,DC=local"
    New-ADOrganizationalUnit -Name "Management" -Path "DC=wodensec,DC=local"
    New-ADOrganizationalUnit -Name "Consultants" -Path "DC=wodensec,DC=local"
    New-ADOrganizationalUnit -Name "Vente" -Path "DC=wodensec,DC=local"
    New-ADOrganizationalUnit -Name "IT" -Path "DC=wodensec,DC=local"
    New-ADOrganizationalUnit -Name "SVC" -Path "DC=wodensec,DC=local"

    foreach ($g in Get-ADGroup -Filter *){ Get-ADGroup $g | Move-ADObject -targetpath "OU=Groupes,DC=wodensec,DC=local" | Out-Null }

    # Management
    Add-User -prenom "Richard" -nom "Cuvillier" -sam "rcuvillier" -ou "management" -mdp "VwBvAGQAZQBuAHMAZQBjADEAMgAzAA=="
    Add-User -prenom "Basile" -nom "Delacroix" -sam "bdelacroix" -ou "management" -mdp "QQB6AGUAcgB0AHkAIwAxADUA"
    Add-User -prenom "Martine" -nom "Baudet" -sam "mbaudet" -ou "management" -mdp "NgA3AEQAMQBmAEQAJQAlAGsAOAByADgA"
    Add-ADGroupMember -Identity "Management" -Members rcuvillier,bdelacroix,mbaudet

    # RH
    Add-User -prenom "Louise" -nom "Chappuis" -sam "lchappuis" -ou "rh" -mdp "QQB6AGUAcgB0AHkAMQAyADMA"
    Add-User -prenom "Sarah" -nom "Meyer" -sam "smeyer" -ou "rh" -mdp "VwBvAGQAZQBuAHMAZQBjADIAMAAyADQAIQA="
    Add-ADGroupMember -Identity "RH" -Members lchappuis,smeyer

    # Consultants
    Add-User -prenom "Henri" -nom "Walter" -sam "hwalter" -ou "consultants" -mdp "VwBvAGQAZQBuAHMAZQBjACoAOQA4AA=="
    Add-User -prenom "Bertrand" -nom "Dubois" -sam "bdubois" -ou "consultants" -mdp "SwBpAEwAbABFAHIANQAhAA=="
    Add-User -prenom "Didier" -nom "Leroux" -sam "dleroux" -ou "consultants" -mdp "WgBvAHIAYQBSAG8AcwBlADkAMQAhAA=="
    Add-User -prenom "Pascal" -nom "Mesny" -sam "pmesny" -ou "consultants" -mdp "dwBzADkAcABBACYAbABnADcATgAzADIA"
    Add-User -prenom "Lydia" -nom "Beaumont" -sam "lbeaumont" -ou "consultants" -mdp "VAAwAGsAaQAwAEgAMAB0ADMAbAA="
    Add-User -prenom "Alexia" -nom "Chabert" -sam "achabert" -ou "consultants" -mdp "UABPAGkAdQAqACYAOAA3AF4AJQA="
    Add-User -prenom "Dylan" -nom "Brassard" -sam "dbrassard" -ou "consultants" -mdp "SwBzAGQAaQAzADQAMgA2AEMAJgB2AGUA"
    Add-User -prenom "Lara" -nom "Fournier" -sam "lfournier" -ou "consultants" -mdp "OAA3AGMAYgB6AHUAdgBzAEYAMAAyACYA"
    Add-User -prenom "Hugo" -nom "Dupuy" -sam "hdupuy" -ou "consultants" -mdp "WAAyAHcAXgB2AFkANAAzADIARQBvAFAA"
    Add-ADGroupMember -Identity "Consultants" -Members hwalter,bdubois,dleroux,pmesny,lbeaumont,achabert,dbrassard,lfournier,hdupuy

    # Vente
    Add-User -prenom "Olivier" -nom "Bossuet" -sam "obossuet" -ou "vente" -mdp "YgB4AEwAIQBAADIATQBlADEATQA4AHUA"
    Add-User -prenom "Jessica" -nom "Plantier" -sam "jplantier" -ou "vente" -mdp "VwAwAGQAMwBuAHMAMwBjAA=="
    Add-User -prenom "Jade" -nom "Schneider" -sam "jschneider" -ou "vente" -mdp "VAB6AGoAMAA0ADQAWgBlAFYAJgBZAHUA"
    Add-ADGroupMember -Identity "Vente" -Members obossuet,jplantier,jschneider

    # Comptes IT et comptes IT admins du domaine
    Add-User -prenom "Sylvain" -nom "Cormier" -sam "scormier" -ou "it" -mdp "egBMADAAVAAxAE4AIQA0AEEAQQBZAHIA"
    Add-User -prenom "Admin" -nom "Sylvain Cormier" -sam "adm-scormier" -ou "it" -mdp "egBMADAAVAAxAE4AIQA0AEEAQQBZAHIAegBMADAAVAAxAE4AIQA0AEEAQQBZAHIA"
    Add-User -prenom "Maxime" -nom "Laurens" -sam "mlaurens" -ou "it" -mdp "VwBvAGQAZQBuAHMAZQBjADIAMAAyADQA"
    Add-User -prenom "Admin" -nom "Maxime Laurens" -sam "adm-mlaurens" -ou "it" -mdp "MgAwADMAYwBnADEAbgBTAFQAbwAmAHAA"
    Add-ADGroupMember -Identity "Admins du domaine" -Members adm-scormier,adm-mlaurens

    # Quelques comptes désactivés
    New-ADUser -Name "Arnaud Trottier" -GivenName "Arnaud" -Surname "Trottier" -SamAccountName "atrottier" -Description "Désactivé le 14/06/2023" -UserPrincipalName "atrottier@wodensec.local" -Path "OU=vente,DC=wodensec,DC=local" -AccountPassword (ConvertTo-SecureString "E&JqMU8725Lq" -AsPlainText -Force) -PasswordNeverExpires $true -PassThru | Out-Null
    New-ADUser -Name "Guillaume Brazier" -GivenName "Guillaume" -Surname "Brazier" -SamAccountName "gbrazier" -Description "Désactivé le 25/08/2023" -UserPrincipalName "gbrazier@wodensec.local" -Path "OU=consultants,DC=wodensec,DC=local" -AccountPassword (ConvertTo-SecureString "2JqMU5LqE&87" -AsPlainText -Force) -PasswordNeverExpires $true -PassThru | Out-Null

    # Comptes de service et SPN
    New-ADUser -Name "installpc" -GivenName "install" -Surname "pc" -SamAccountName "installpc" -Description "Compte d'installation PC." -UserPrincipalName "installpc@wodensec.local" -Path "OU=SVC,DC=wodensec,DC=local" -AccountPassword (ConvertTo-SecureString "Sysadmin123!" -AsPlainText -Force) -PasswordNeverExpires $true -PassThru | Enable-ADAccount  | Out-Null
    New-ADUser -Name "svc-sql" -GivenName "svc" -Surname "sql" -SamAccountName "svc-sql" -Description "Compte de service SQL" -UserPrincipalName "svc-sql@wodensec.local" -Path "OU=SVC,DC=wodensec,DC=local" -AccountPassword (ConvertTo-SecureString "sql0v3-u" -AsPlainText -Force) -PasswordNeverExpires $true -PassThru | Enable-ADAccount -PassThru  | Out-Null
    New-ADUser -Name "svc-backup" -GivenName "svc" -Surname "backup" -SamAccountName "svc-backup" -Description "Compte de service backup. Mdp: B4ckup-S3rv1c3" -UserPrincipalName "svc-backup@wodensec.local" -Path "OU=SVC,DC=wodensec,DC=local" -AccountPassword (ConvertTo-SecureString "B4ckup-S3rv1c3" -AsPlainText -Force) -PasswordNeverExpires $true -PassThru | Enable-ADAccount  | Out-Null
    Add-ADGroupMember -Identity "Backup" -Members svc-backup

    setspn -A DC01/svc-sql.wodensec.local:`60111 wodensec\svc-sql > $null
    setspn -A svc-sql/wodensec.local wodensec\svc-sql > $null
    setspn -A DomainController/svc-sql.wodensec.local:`60111 wodensec\svc-sql > $null


    # Share
    mkdir C:\Share
    New-SmbShare -Name "Share" -Path "C:\Share" -ChangeAccess "Utilisateurs" -FullAccess "Tout le monde" -WarningAction SilentlyContinue | Out-Null


    write-host("`n  [++] Creation de GPO")
    New-GPO -Name "Disable Defender"

    Set-GPRegistryValue -Name "Disable Defender" -Key "HKLM\SYSTEM\CurrentControlSet\Services\FDResPub" -ValueName "DependOnService" -Type MultiString -Value "RpcSs\0http\0fpdhost\0LanmanWorkstation"
    Set-GPRegistryValue -Name "Disable Defender" -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -ValueName "sc_fdredpub" -Type MultiString -Value "sc config fdrespub depend= RpcSs/http/fdphost/LanmanWorkstation"
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /f /v sc_fdrespub /t REG_EXPAND_SZ /d "sc config fdrespub depend= RpcSs/http/fdphost/LanmanWorkstation"
  
    # Enable rdp 
    Set-GPRegistryValue -Name "Disable Defender" -Key "HKLM\System\CurrentControlSet\Control\Terminal Server" -ValueName "fDenyTSConnections" -Value 0 -Type Dword | Out-Null 
    Set-GPRegistryValue -Name "Disable Defender" -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ValueName "EnableLUA" -Value 0 -Type Dword | Out-Null
  
    # Nuke Defender GPO
    Set-GPRegistryValue -Name "Disable Defender" -Key "HKLM\System\CurrentControlSet\Services\SecurityHealthService" -ValueName "Start" -Value 4 -Type Dword | Out-Null
    Set-GPRegistryValue -Name "Disable Defender" -Key "HKLM\Software\Policies\Microsoft\Windows Defender" -ValueName "DisableAntiSpyware" -Value 1 -Type Dword | Out-Null
    Set-GPRegistryValue -Name "Disable Defender" -Key "HKLM\Software\Policies\Microsoft\Windows Defender" -ValueName "DisableAntiVirus" -Value 1 -Type Dword | Out-Null
    Set-GPRegistryValue -Name "Disable Defender" -Key "HKLM\Software\Policies\Microsoft\Windows Defender\MpEngine" -ValueName "MpEnablePus" -Value 0 -Type Dword | Out-Null
    Set-GPRegistryValue -Name "Disable Defender" -Key "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" -ValueName "DisableBehaviorMonitoring" -Value 1 -Type Dword | Out-Null
    Set-GPRegistryValue -Name "Disable Defender" -Key "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" -ValueName "DisableIOAVProtection" -Value 1 -Type Dword | Out-Null
    Set-GPRegistryValue -Name "Disable Defender" -Key "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" -ValueName "DisableOnAccessProtection" -Value 1 -Type Dword | Out-Null
    Set-GPRegistryValue -Name "Disable Defender" -Key "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" -ValueName "DisableRealtimeMonitoring" -Value 1 -Type Dword | Out-Null
    Set-GPRegistryValue -Name "Disable Defender" -Key "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" -ValueName "DisableScanOnRealtimeEnable" -Value 1 -Type Dword | Out-Null
    Set-GPRegistryValue -Name "Disable Defender" -Key "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" -ValueName "DisableScriptScanning" -Value 1 -Type Dword | Out-Null
    Set-GPRegistryValue -Name "Disable Defender" -Key "HKLM\Software\Policies\Microsoft\Windows Defender\Reporting" -ValueName "DisableEnhancedNotifications" -Value 1 -Type Dword | Out-Null
    Set-GPRegistryValue -Name "Disable Defender" -Key "HKLM\Software\Policies\Microsoft\Windows Defender\SpyNet" -ValueName "DisableBlockAtFirstSeen" -Value 1 -Type Dword | Out-Null
    Set-GPRegistryValue -Name "Disable Defender" -Key "HKLM\Software\Policies\Microsoft\Windows Defender\SpyNet" -ValueName "SpynetReporting" -Value 0 -Type Dword | Out-Null
    Set-GPRegistryValue -Name "Disable Defender" -Key "HKLM\Software\Policies\Microsoft\Windows Defender\SpyNet" -ValueName "SubmitSamplesConsent" -Value 2 -Type Dword | Out-Null
    Set-GPRegistryValue -Name "Disable Defender" -Key "HKLM\System\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger" -ValueName "Start" -Value 0 -Type Dword | Out-Null 
    Set-GPRegistryValue -Name "Disable Defender" -Key "HKLM\System\CurrentControlSet\Control\WMI\Autologger\DefenderAuditLogger" -ValueName "Start" -Value 0 -Type Dword | Out-Null 
    Set-GPRegistryValue -Name "Disable Defender" -Key "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -ValueName "RequireSecuritySignature" -Value 0 -Type Dword | Out-Null
    Set-GPRegistryValue -Name "Disable Defender" -Key "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -ValueName "requiresecuritysignature" -Value 0 -Type Dword | Out-Null
 
    # PrintNightmare
    Set-GPRegistryValue -Name "Disable Defender" -Key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" -ValueName "NoWarningNoElevationOnInstall" -Value 1 -Type Dword | Out-Null
    Set-GPRegistryValue -Name "Disable Defender" -Key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" -ValueName "RestrictDriverInstallationToAdministrators" -Value 0 -Type Dword | Out-Null

    Set-GPRegistryValue -Name "Disable Defender" -Key "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\system" -ValueName "LocalAccountTokenFilterPolicy" -Value 1 -Type Dword | Out-Null
    Set-GPRegistryValue -Name "Disable Defender" -Key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer" -ValueName "AlwaysInstallElevated" -Value 0 -Type Dword | Out-Null
    Set-GPRegistryValue -Name "Disable Defender" -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -ValueName "NoAutoUpdate" -Value 1 -Type Dword | Out-Null

    # QoL GPO (dark mode, screen locker)
    Set-GPRegistryValue -Name "Disable Defender" -Key "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -ValueName "AppsUseLightTheme" -Value 0 -Type Dword | Out-Null
    Set-GPRegistryValue -Name "Disable Defender" -Key "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -ValueName "SystemUsesLightTheme" -Value 0 -Type Dword | Out-Null
    Set-GPRegistryValue -Name "Disable Defender" -Key "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Control Panel\Desktop\" -ValueName "ScreenSaveTimeOut" -Value 0 -Type Dword
    Set-GPRegistryValue -Name "Disable Defender" -Key "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Control Panel\Desktop\" -ValueName "ScreenSaveActive" -Value 0 -Type Dword
    Set-GPRegistryValue -Name "Disable Defender" -Key "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Control Panel\Desktop\" -ValueName "ScreenSaverIsSecure" -Value 0 -Type Dword | Out-Null

    # IPv4 > IPv6
    Set-GPRegistryValue -Name "Disable Defender" -Key "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\" -ValueName "DisabledComponents" -Value 0x20 -Type Dword 
 
}


function Invoke-DCSetup{
    if($env:COMPUTERNAME -ne "DC01" ){
        Write-Host("Première execution détectée. Changement des paramètres réseau...")
        Set-IPAddress
        Write-Host("Suppression de l'antivirus...")
        Nuke-Defender
        Add-WindowsFeature -Name "RSAT-AD-PowerShell" –IncludeAllSubFeature
        Write-Host("Changement QoL")
        Get-QoL
        Write-Host("Le serveur va être renommé puis redémarrer")
        Start-Sleep -Seconds 5
        Rename-Computer -NewName "DC01" -Restart
    }elseif($env:USERDNSDOMAIN -ne "WODENSEC.LOCAL"){
        Write-Host("Deuxième execution detectée. Installation des rôles...")
        Build-Server
    }elseif($env:COMPUTERNAME -eq "DC01" -and $env:USERDNSDOMAIN -eq "WODENSEC.LOCAL"){
        Write-Host("Troisième execution detectée. Ajout du contenu...")
        Add-ServerContent

    }
}

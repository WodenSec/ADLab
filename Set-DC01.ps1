function Set-IPAddress {
    $NetAdapter=Get-CimInstance -Class Win32_NetworkAdapter -Property NetConnectionID,NetConnectionStatus | Where-Object { $_.NetConnectionStatus -eq 2 } | Select-Object -Property NetConnectionID -ExpandProperty NetConnectionID
    $IPAddress=Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias $NetAdapter | Select-Object -ExpandProperty IPAddress
    $NetM
    $Gateway=((Get-NetIPConfiguration -InterfaceAlias $NetAdapter).IPv4DefaultGateway).NextHop

    # split the ip address up based on the . 
    $IPByte = $IPAddress.Split(".")
    # first 2 octets of ip address only 
    if ($IPByte[0] -eq "169" -And $IPByte[1] -eq "254") {
        Write-Host("`n [ ERROR ] - $IPaddress is a LinkLocal Adress, Check your Hypervisor configuration `n`n")
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


    Get-WmiObject -query "Select HotFixID  from Win32_QuickFixengineering" | sort-object -Descending -Property HotFixID|%{
    $sUpdate=$_.HotFixID.Replace("KB","")
    write-host ("Uninstalling update "+$sUpdate);
    & wusa.exe /uninstall /KB:$sUpdate /quiet /norestart;
    Wait-Process wusa 
    Start-Sleep -s 1 }

}

function Get-QoL{
    write-host("`n  [++] Quality of life improvement - Dark Theme")
    reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "AppsUseLightTheme" /t REG_DWORD /d "0" /f > $null
    reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "SystemUsesLightTheme" /t REG_DWORD /d "0" /f > $null

    write-host("`n  [++] Quality of life improvement - Disable ScreenSaver, ScreenLock and Timeout")
    reg add  "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Control Panel\Desktop" /v "ScreenSaveTimeOut" /t REG_DWORD /d "0" /f > $null 
    reg add  "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Control Panel\Desktop" /v "ScreenSaveActive" /t REG_DWORD /d "0" /f > $null
    reg add  "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Control Panel\Desktop" /v "ScreenSaverIsSecure" /t REG_DWORD /d "0" /f > $null

    Get-ScheduledTask -TaskName ServerManager | Disable-ScheduledTask | Out-Null
}

function Build-Server{
    write-host("`n  [++] Installing Module Active Directory Domain Services (ADDS)")
    Install-windowsfeature -name AD-Domain-Services -IncludeManagementTools -WarningAction SilentlyContinue | Out-Null

    write-host("`n  [++] Importing Module ActiveDirectory")
    Import-Module ActiveDirectory -WarningAction SilentlyContinue | Out-Null

    write-host("`n  [++] Installing ADDS Domain : wodensec.local ")
    Install-ADDSDomain -SkipPreChecks -ParentDomainName WODENSEC -NewDomainName local -NewDomainNetbiosName WODENSEC -InstallDns -SafeModeAdministratorPassword (Convertto-SecureString -AsPlainText "R00tR00t" -Force) -Force -WarningAction SilentlyContinue | Out-Null

    write-host("`n  [++] Deploying Active Directory Domain Forest in wodensec.local")
    Install-ADDSForest -SkipPreChecks -CreateDnsDelegation:$false -DatabasePath "C:\Windows\NTDS" -DomainMode "WinThreshold" -DomainName "WODENSEC.local" -DomainNetbiosName "WODENSEC" -ForestMode "WinThreshold" -InstallDns:$true -LogPath "C:\Windows\NTDS" -NoRebootOnCompletion:$false -SysvolPath "C:\Windows\SYSVOL" -Force:$true -SafeModeAdministratorPassword (Convertto-SecureString -AsPlainText "R00tR00t" -Force) -WarningAction SilentlyContinue | Out-Null

}

function Add-ServerContent{

    # install ad-certificate services
    write-host("`n  [++] Installing Active Directory Certificate Services")
    Add-WindowsFeature -Name AD-Certificate -IncludeManagementTools -WarningAction SilentlyContinue | Out-Null
  
    # install ad-certificate authority
    write-host("`n  [++] Installing Active Directory Certificate Authority")
    Add-WindowsFeature -Name Adcs-Cert-Authority -IncludeManagementTools -WarningAction SilentlyContinue | Out-Null

    # configure ad-certificate authority
    write-host("`n  [++] Configuring Active Directory Certificate Authority")

    # fix_adcsca
    Install-AdcsCertificationAuthority -CAType EnterpriseRootCa -CryptoProviderName "RSA#Microsoft Software Key Storage Provider" `
    -KeyLength 2048 -HashAlgorithmName SHA1 -ValidityPeriod Years -ValidityPeriodUnits 99 -WarningAction SilentlyContinue -Force | Out-Null

    # install remote system administration tools
    write-host("`n  [++] Installing Remote System Administration Tools (RSAT)")
    Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0 -WarningAction SilentlyContinue | Out-Null

    # install rsat-adcs and rsat-adcs-management 
    write-host("`n  [++] Installing RSAT-ADCS and RSAT-ADCS-Management")
    Add-WindowsFeature RSAT-ADCS,RSAT-ADCS-mgmt -WarningAction SilentlyContinue | Out-Null




    New-ADGroup -name "RH" -GroupScope Global
    New-ADGroup -name "Management" -GroupScope Global
    New-ADGroup -name "Consultants" -GroupScope Global
    New-ADGroup -name "Vente" -GroupScope Global


    New-ADOrganizationalUnit -Name "Groupes" -Path "DC=wodensec,DC=local"
    New-ADOrganizationalUnit -Name "RH" -Path "DC=wodensec,DC=local"
    New-ADOrganizationalUnit -Name "Management" -Path "DC=wodensec,DC=local"
    New-ADOrganizationalUnit -Name "Consultants" -Path "DC=wodensec,DC=local"
    New-ADOrganizationalUnit -Name "Vente" -Path "DC=wodensec,DC=local"

    foreach ($g in Get-ADGroup -Filter *){ Get-ADGroup $g | Move-ADObject -targetpath "OU=Groupes,DC=wodensec,DC=local" | Out-Null }

    New-ADUser -Name "Richard Cuvillier" -GivenName "Richard" -Surname "Cuvillier" -SamAccountName "rcuvillier" -UserPrincipalName "rcuvillier@wodensec.local" -Path "OU=management,DC=wodensec,DC=local" -AccountPassword (ConvertTo-SecureString "Wodensec123" -AsPlainText -Force) -PasswordNeverExpires $true -PassThru | Enable-ADAccount  | Out-Null
    New-ADUser -Name "Basile Delacroix" -GivenName "Basile" -Surname "Delacroix" -SamAccountName "bdelacroix" -UserPrincipalName "bdelacroix@wodensec.local" -Path "OU=management,DC=wodensec,DC=local" -AccountPassword (ConvertTo-SecureString "Azerty#15" -AsPlainText -Force) -PasswordNeverExpires $true -PassThru | Enable-ADAccount  | Out-Null
    New-ADUser -Name "Martine Baudet" -GivenName "Martine" -Surname "Baudet" -SamAccountName "mbaudet" -UserPrincipalName "mbaudet@wodensec.local" -Path "OU=management,DC=wodensec,DC=local" -AccountPassword (ConvertTo-SecureString "67D1fD%%k8r8" -AsPlainText -Force) -PasswordNeverExpires $true -PassThru | Enable-ADAccount  | Out-Null

    New-ADUser -Name "Louise Chappuis" -GivenName "Louise" -Surname "Chappuis" -SamAccountName "lchappuis" -UserPrincipalName "lchappuis@wodensec.local" -Path "OU=rh,DC=wodensec,DC=local" -AccountPassword (ConvertTo-SecureString "Azerty123" -AsPlainText -Force) -PasswordNeverExpires $true -PassThru | Enable-ADAccount  | Out-Null
    New-ADUser -Name "Sarah Meyer" -GivenName "Sarah" -Surname "Meyer" -SamAccountName "smeyer" -UserPrincipalName "smeyer@wodensec.local" -Path "OU=rh,DC=wodensec,DC=local" -AccountPassword (ConvertTo-SecureString "Wodensec2024!" -AsPlainText -Force) -PasswordNeverExpires $true -PassThru | Enable-ADAccount  | Out-Null

    New-ADUser -Name "Henri Walter" -GivenName "Henri" -Surname "Walter" -SamAccountName "hwalter" -UserPrincipalName "hwalter@wodensec.local" -Path "OU=consultants,DC=wodensec,DC=local" -AccountPassword (ConvertTo-SecureString "Wodensec*98" -AsPlainText -Force) -PasswordNeverExpires $true -PassThru | Enable-ADAccount  | Out-Null
    New-ADUser -Name "Bertrand Dubois" -GivenName "Bertrand" -Surname "Dubois" -SamAccountName "bdubois" -UserPrincipalName "bdubois@wodensec.local" -Path "OU=consultants,DC=wodensec,DC=local" -AccountPassword (ConvertTo-SecureString "KiLlEr5!" -AsPlainText -Force) -PasswordNeverExpires $true -PassThru | Enable-ADAccount  | Out-Null
    New-ADUser -Name "Didier Leroux" -GivenName "Didier" -Surname "Leroux" -SamAccountName "dleroux" -UserPrincipalName "dleroux@wodensec.local" -Path "OU=consultants,DC=wodensec,DC=local" -AccountPassword (ConvertTo-SecureString "ZoraRose91!" -AsPlainText -Force) -PasswordNeverExpires $true -PassThru | Enable-ADAccount  | Out-Null
    New-ADUser -Name "Pascal Mesny" -GivenName "Pascal" -Surname "Mesny" -SamAccountName "pmesny" -UserPrincipalName "pmesny@wodensec.local" -Path "OU=consultants,DC=wodensec,DC=local" -AccountPassword (ConvertTo-SecureString "ws9pA&lg7N32" -AsPlainText -Force) -PasswordNeverExpires $true -PassThru | Enable-ADAccount  | Out-Null
    New-ADUser -Name "Lydia Beaumont" -GivenName "Lydia" -Surname "Beaumont" -SamAccountName "lbeaumont" -UserPrincipalName "lbeaumont@wodensec.local" -Path "OU=consultants,DC=wodensec,DC=local" -AccountPassword (ConvertTo-SecureString "T0ki0H0t3l" -AsPlainText -Force) -PasswordNeverExpires $true -PassThru | Enable-ADAccount  | Out-Null
    New-ADUser -Name "Alexia Chabert" -GivenName "Alexia" -Surname "Chabert" -SamAccountName "achabert" -UserPrincipalName "achabert@wodensec.local" -Path "OU=consultants,DC=wodensec,DC=local" -AccountPassword (ConvertTo-SecureString "POiu*&87^%" -AsPlainText -Force) -PasswordNeverExpires $true -PassThru | Enable-ADAccount  | Out-Null
    New-ADUser -Name "Dylan Brassard" -GivenName "Dylan" -Surname "Brassard" -SamAccountName "dbrassard" -UserPrincipalName "dbrassard@wodensec.local" -Path "OU=consultants,DC=wodensec,DC=local" -AccountPassword (ConvertTo-SecureString "Ksdi3426C&ve" -AsPlainText -Force) -PasswordNeverExpires $true -PassThru | Enable-ADAccount  | Out-Null
    New-ADUser -Name "Lara Fournier" -GivenName "Lara" -Surname "Fournier" -SamAccountName "lfournier" -UserPrincipalName "lfournier@wodensec.local" -Path "OU=consultants,DC=wodensec,DC=local" -AccountPassword (ConvertTo-SecureString "87cbzuvsF02&" -AsPlainText -Force) -PasswordNeverExpires $true -PassThru | Enable-ADAccount  | Out-Null
    New-ADUser -Name "Hugo Dupuy" -GivenName "Hugo" -Surname "Dupuy" -SamAccountName "hdupuy" -UserPrincipalName "hdupuy@wodensec.local" -Path "OU=consultants,DC=wodensec,DC=local" -AccountPassword (ConvertTo-SecureString "X2w^vY432EoP" -AsPlainText -Force) -PasswordNeverExpires $true -PassThru | Enable-ADAccount  | Out-Null




    New-ADUser -Name "Olivier Bossuet" -GivenName "Olivier" -Surname "Bossuet" -SamAccountName "obossuet" -UserPrincipalName "obossuet@wodensec.local" -Path "OU=vente,DC=wodensec,DC=local" -AccountPassword (ConvertTo-SecureString "bxL!@2Me1M8u" -AsPlainText -Force) -PasswordNeverExpires $true -PassThru | Enable-ADAccount  | Out-Null
    New-ADUser -Name "Jessica Plantier" -GivenName "Jessica" -Surname "Plantier" -SamAccountName "jplantier" -UserPrincipalName "jplantier@wodensec.local" -Path "OU=vente,DC=wodensec,DC=local" -AccountPassword (ConvertTo-SecureString "W0d3ns3c" -AsPlainText -Force) -PasswordNeverExpires $true -PassThru | Enable-ADAccount  | Out-Null
    New-ADUser -Name "Jade Schneider" -GivenName "Jade" -Surname "Schneider" -SamAccountName "jschneider" -UserPrincipalName "jschneider@wodensec.local" -Path "OU=vente,DC=wodensec,DC=local" -AccountPassword (ConvertTo-SecureString "Tzj044ZeV&Yu" -AsPlainText -Force) -PasswordNeverExpires $true -PassThru | Enable-ADAccount  | Out-Null


}


function Invoke-DCSetup{
    if($env:COMPUTERNAME -ne "DC01" ){
        Write-Host("Première execution détectée. Changement des paramètres réseau...")
        Set-IPAddress
        Write-Host("Suppression de l'antivirus et autre...")
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
    }elseif($env:COMPUTERNAME -ne "DC01" -and $env:USERDNSDOMAIN -ne "WODENSEC.LOCAL"){
        Write-Host("Troisième execution detectée. Ajout du contenu...")
        Add-ServerContent

    }
}

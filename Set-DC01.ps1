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

}

function Get-QoL{
    write-host("`n  [++] Quality of life improvement - Dark Theme")
    reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "AppsUseLightTheme" /t REG_DWORD /d "0" /f > $null
    reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "SystemUsesLightTheme" /t REG_DWORD /d "0" /f > $null

    write-host("`n  [++] Quality of life improvement - Disable ScreenSaver, ScreenLock and Timeout")
    reg add  "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Control Panel\Desktop" /v "ScreenSaveTimeOut" /t REG_DWORD /d "0" /f > $null 
    reg add  "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Control Panel\Desktop" /v "ScreenSaveActive" /t REG_DWORD /d "0" /f > $null
    reg add  "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Control Panel\Desktop" /v "ScreenSaverIsSecure" /t REG_DWORD /d "0" /f > $null
}

function Invoke-DCSetup{
    if($env:COMPUTERNAME -ne "DC01" ){
        Write-Host("Première execution détectée. Changement des paramètres réseau...")
        Set-IPAddress
        Write-Host("Suppression de l'antivirus et autre...")
        Nuke-Defender
        Write-Host("Changement QoL")
        Get-QoL
        Write-Host("Le serveur va être renommé puis redémarrer")
        Start-Sleep -Seconds 5
        Rename-Computer -NewName "DC01" -Restart
    }else{
        
    
    }
}

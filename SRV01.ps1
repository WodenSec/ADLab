#Requires -RunAsAdministrator

function Invoke-LabSetup { 

    if ($env:COMPUTERNAME -ne "SRV01") { 
    
        write-host ("`n Changement des paramètres IP et du nom et reboot...")

        $NetAdapter=Get-CimInstance -Class Win32_NetworkAdapter -Property NetConnectionID,NetConnectionStatus | Where-Object { $_.NetConnectionStatus -eq 2 } | Select-Object -Property NetConnectionID -ExpandProperty NetConnectionID
        $IPAddress=Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias $NetAdapter | Select-Object -ExpandProperty IPAddress
        $IPByte = $IPAddress.Split(".")
        $DNS = ($IPByte[0]+"."+$IPByte[1]+"."+$IPByte[2]+".250")
        Set-DnsClientServerAddress -InterfaceAlias $NetAdapter -ServerAddresses ("$DNS","1.1.1.1")
        Disable-NetAdapterPowerManagement -Name "$NetAdapter"
        netsh interface ipv6 set dnsservers "$NetAdapter" dhcp

        Rename-Computer -NewName "SRV01" -Restart

    }
    elseif ($env:COMPUTERNAME -eq "SRV01" -and $env:USERDNSDOMAIN -ne "NEVASEC.LOCAL") {
        write-host ("`n Ajout au domaine et reboot...")

        Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled False | Out-Null
        
        $domain = "NEVASEC"
        $password = "R00tR00t" | ConvertTo-SecureString -asPlainText -Force
        $username = "$domain\Administrateur" 
        $credential = New-Object System.Management.Automation.PSCredential($username,$password)
        #Verif ping du domaine avant lancement de la connection
        if (Test-Connection -ComputerName "NEVASEC.local" -Count 5 -Quiet) { 
            Add-Computer -DomainName $domain -Credential $credential  | Out-Null
            Start-Sleep 5
            restart-computer
        } else {
            Write-Error "Erreur Impossible de Ping l'AD Vérfier la connectivité ou le DNS... Arrêt dans 5sec !"
            Start-Sleep 5
        }
    }
    else { # Create credentials file
        $username = 'NEVASEC\mlaurens'
        $password = ConvertTo-SecureString '!0Nevagrup0!' -AsPlainText -Force
        $credential = New-Object System.Management.Automation.PSCredential -ArgumentList $username, $password
        $credential | Export-CliXml -Path "C:\secure_credentials.xml"
        
        # Create the PowerShell script to perform LLMNR trigger
        $scriptContent = @'
        while ($true) {
            # Import stored credentials
            $credential = Import-CliXml -Path "C:\secure_credentials.xml"
        
            # LLMNR trigger
            Start-Process -FilePath "powershell.exe" -ArgumentList "-Command ls \\SQL01\C$" -Credential $credential
        
            # Sleep for 2 minutes before repeating
            Start-Sleep -Seconds 120
        }
        '@
        
        $scriptPath = "C:\llmnr_trigger.ps1"
        $scriptContent | Set-Content -Path $scriptPath
        
        # Add the script to the Run registry key for startup
        if (-not (Test-Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run")) {
            New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -Force
        }
        Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "LLMNR_Trigger_Script" -Value "powershell.exe -ExecutionPolicy Bypass -NoProfile -File `"$scriptPath`"" }
        New-LocalUser -Name srvadmin -Password (ConvertTo-SecureString "Super-Password-4-Admin" -AsPlainText -Force)
} 

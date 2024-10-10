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
    else { write-host("Il semblerait que le PC soit entièrement configuré") }
} 

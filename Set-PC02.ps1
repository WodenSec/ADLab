#Requires -RunAsAdministrator

function Invoke-PC02Setup { 

    if ($env:COMPUTERNAME -ne "PC02") { 
        write-host ("`n Changement des paramètres IP et du nom et reboot...")

        $NetAdapter=Get-CimInstance -Class Win32_NetworkAdapter -Property NetConnectionID,NetConnectionStatus | Where-Object { $_.NetConnectionStatus -eq 2 } | Select-Object -Property NetConnectionID -ExpandProperty NetConnectionID
        $IPAddress=Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias $NetAdapter | Select-Object -ExpandProperty IPAddress
        $IPByte = $IPAddress.Split(".")
        $DNS = ($IPByte[0]+"."+$IPByte[1]+"."+$IPByte[2]+".250")
        Set-DnsClientServerAddress -InterfaceAlias $NetAdapter -ServerAddresses ("$DNS","1.1.1.1")
        Disable-NetAdapterPowerManagement -Name "$NetAdapter"
        netsh interface ipv6 set dnsservers "$NetAdapter" dhcp

        Rename-Computer -NewName "PC02" -Restart

    }
    elseif ($env:COMPUTERNAME -eq "PC02" -and $env:USERDNSDOMAIN -ne "WODENSEC.LOCAL") {
        write-host ("`n Ajout au domaine et reboot...")

        Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled False | Out-Null
        Get-NetFirewallRule -Group '@FirewallAPI.dll,-32752'|Set-NetFirewallRule -Profile 'Private, Domain' -Enabled true -PassThru|select Name,DisplayName,Enabled,Profile |ft -a | Out-Null
        netsh advfirewall firewall add rule name="ICMP Allow incoming V4 echo request" protocol=icmpv4:8,any dir=in action=allow > $null
        netsh advfirewall firewall add rule name="ICMP Allow incoming V6 echo request" protocol=icmpv6:8,any dir=in action=allow > $nul
        Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled False | Out-Null
        
        $domain = "WODENSEC"
        $password = "R00tR00t" | ConvertTo-SecureString -asPlainText -Force
        $username = "$domain\Administrateur" 
        $credential = New-Object System.Management.Automation.PSCredential($username,$password)
        #Verif ping du domaine avant lancement de la connection
        if (Test-Connection -ComputerName "WOODENSEC" -Count 5 -Quiet) { 
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

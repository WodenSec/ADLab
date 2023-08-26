function Set-PC01 { 


  if ($env:COMPUTERNAME -ne "PC01") { 
    write-host ("`n Setting the name of this machine to PC01 and rebooting automatically...")

    # Remove updates
    Get-WmiObject -query "Select HotFixID  from Win32_QuickFixengineering" | sort-object -Descending -Property HotFixID|%{
    $sUpdate=$_.HotFixID.Replace("KB","")
    write-host ("Uninstalling update "+$sUpdate);
    & wusa.exe /uninstall /KB:$sUpdate /quiet /norestart;
    Wait-Process wusa 
    Start-Sleep -s 1 }



    Rename-Computer -NewName "PC01" -Restart


    }
    elseif ($env:COMPUTERNAME -eq "PC01") {

    $NetAdapter=Get-CimInstance -Class Win32_NetworkAdapter -Property NetConnectionID,NetConnectionStatus | Where-Object { $_.NetConnectionStatus -eq 2 } | Select-Object -Property NetConnectionID -ExpandProperty NetConnectionID
    $IPAddress=Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias $NetAdapter | Select-Object -ExpandProperty IPAddress
    $IPByte = $IPAddress.Split(".")
    $DNS = ($IPByte[0]+"."+$IPByte[1]+"."+$IPByte[2]+".250")
    Set-DnsClientServerAddress -InterfaceAlias $NetAdapter -ServerAddresses ("$DNS","1.1.1.1")


    Disable-NetAdapterPowerManagement -Name "$NetAdapter"

    netsh interface ipv6 set dnsservers "$NetAdapter" dhcp

        write-host("`n Joining machine to domain wodensec.local")
      $domain = "WODENSEC"
      $password = "R00tR00t" | ConvertTo-SecureString -asPlainText -Force
      $username = "$domain\Administrateur" 
      $credential = New-Object System.Management.Automation.PSCredential($username,$password)
      Add-Computer -DomainName $domain -Credential $credential  | Out-Null 

      restart-computer 



    }
    else { write-host("Nothing to do here") }
} 

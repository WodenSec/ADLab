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


  

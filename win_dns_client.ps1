#!powershell

# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)



Set-StrictMode -Version 2

$ErrorActionPreference = "Stop"
$ConfirmPreference = "None"


# Helper function to set an "attribute" on a psobject instance in powershell.
# This is a convenience to make adding Members to the object easier and
# slightly more pythonic
# Example: Set-Attr $result "changed" $true
Function Set-Attr($obj, $name, $value)
{
    # If the provided $obj is undefined, define one to be nice
    If (-not $obj.GetType)
    {
        $obj = @{ }
    }

    Try
    {
        $obj.$name = $value
    }
    Catch
    {
        $obj | Add-Member -Force -MemberType NoteProperty -Name $name -Value $value
    }
}

# Helper function to convert a powershell object to JSON to echo it, exiting
# the script
# Example: Exit-Json $result
Function Exit-Json($obj)
{
    # If the provided $obj is undefined, define one to be nice
    If (-not $obj.GetType)
    {
        $obj = @{ }
    }

    if (-not $obj.ContainsKey('changed')) {
        Set-Attr $obj "changed" $false
    }

    echo $obj | ConvertTo-Json -Compress -Depth 99
    Exit
}

# Helper function to add the "msg" property and "failed" property, convert the
# powershell Hashtable to JSON and echo it, exiting the script
# Example: Fail-Json $result "This is the failure message"
Function Fail-Json($obj, $message = $null)
{
    if ($obj -is [hashtable] -or $obj -is [psobject]) {
        # Nothing to do
    } elseif ($obj -is [string] -and $message -eq $null) {
        # If we weren't given 2 args, and the only arg was a string,
        # create a new Hashtable and use the arg as the failure message
        $message = $obj
        $obj = @{ }
    } else {
        # If the first argument is undefined or a different type,
        # make it a Hashtable
        $obj = @{ }
    }

    # Still using Set-Attr for PSObject compatibility
    Set-Attr $obj "msg" $message
    Set-Attr $obj "failed" $true

    if (-not $obj.ContainsKey('changed')) {
        Set-Attr $obj "changed" $false
    }

    echo $obj | ConvertTo-Json -Compress -Depth 99
    Exit 1
}

# Helper function to add warnings, even if the warnings attribute was
# not already set up. This is a convenience for the module developer
# so they do not have to check for the attribute prior to adding.
Function Add-Warning($obj, $message)
{
    if (-not $obj.ContainsKey("warnings")) {
        $obj.warnings = @()
    } elseif ($obj.warnings -isnot [array]) {
        throw "Add-Warning: warnings attribute is not an array"
    }

    $obj.warnings += $message
}

# Helper function to add deprecations, even if the deprecations attribute was
# not already set up. This is a convenience for the module developer
# so they do not have to check for the attribute prior to adding.
Function Add-DeprecationWarning($obj, $message, $version = $null)
{
    if (-not $obj.ContainsKey("deprecations")) {
        $obj.deprecations = @()
    } elseif ($obj.deprecations -isnot [array]) {
        throw "Add-DeprecationWarning: deprecations attribute is not a list"
    }

    $obj.deprecations += @{
        msg = $message
        version = $version
    }
}

# Helper function to expand environment variables in values. By default
# it turns any type to a string, but we ensure $null remains $null.
Function Expand-Environment($value)
{
    if ($value -ne $null) {
        [System.Environment]::ExpandEnvironmentVariables($value)
    } else {
        $value
    }
}

# Helper function to get an "attribute" from a psobject instance in powershell.
# This is a convenience to make getting Members from an object easier and
# slightly more pythonic
# Example: $attr = Get-AnsibleParam $response "code" -default "1"
#Get-AnsibleParam also supports Parameter validation to save you from coding that manually:
#Example: Get-AnsibleParam -obj $params -name "State" -default "Present" -ValidateSet "Present","Absent" -resultobj $resultobj -failifempty $true
#Note that if you use the failifempty option, you do need to specify resultobject as well.
Function Get-AnsibleParam($obj, $name, $default = $null, $resultobj = @{}, $failifempty = $false, $emptyattributefailmessage, $ValidateSet, $ValidateSetErrorMessage, $type = $null, $aliases = @())
{
    # Check if the provided Member $name or aliases exist in $obj and return it or the default.
    try {

        $found = $null
        # First try to find preferred parameter $name
        $aliases = @($name) + $aliases

        # Iterate over aliases to find acceptable Member $name
        foreach ($alias in $aliases) {
            if ($obj.ContainsKey($alias)) {
                $found = $alias
                break
            }
        }

        if ($found -eq $null) {
            throw
        }
        $name = $found

        if ($ValidateSet) {

            if ($ValidateSet -contains ($obj.$name)) {
                $value = $obj.$name
            } else {
                if ($ValidateSetErrorMessage -eq $null) {
                    #Auto-generated error should be sufficient in most use cases
                    $ValidateSetErrorMessage = "Get-AnsibleParam: Argument $name needs to be one of $($ValidateSet -join ",") but was $($obj.$name)."
                }
                Fail-Json -obj $resultobj -message $ValidateSetErrorMessage
            }

        } else {
            $value = $obj.$name
        }

    } catch {
        if ($failifempty -eq $false) {
            $value = $default
        } else {
            if (!$emptyattributefailmessage) {
                $emptyattributefailmessage = "Get-AnsibleParam: Missing required argument: $name"
            }
            Fail-Json -obj $resultobj -message $emptyattributefailmessage
        }

    }

    # If $value -eq $null, the parameter was unspecified by the user (deliberately or not)
    # Please leave $null-values intact, modules need to know if a parameter was specified
    # When $value is already an array, we cannot rely on the null check, as an empty list
    # is seen as null in the check below
    if ($value -ne $null -or $value -is [array]) {
        if ($type -eq "path") {
            # Expand environment variables on path-type
            $value = Expand-Environment($value)
            # Test if a valid path is provided
            if (-not (Test-Path -IsValid $value)) {
                $path_invalid = $true
                # could still be a valid-shaped path with a nonexistent drive letter
                if ($value -match "^\w:") {
                    # rewrite path with a valid drive letter and recheck the shape- this might still fail, eg, a nonexistent non-filesystem PS path
                    if (Test-Path -IsValid $(@(Get-PSDrive -PSProvider Filesystem)[0].Name + $value.Substring(1))) {
                        $path_invalid = $false
                    }
                }
                if ($path_invalid) {
                    Fail-Json -obj $resultobj -message "Get-AnsibleParam: Parameter '$name' has an invalid path '$value' specified."
                }
            }
        } elseif ($type -eq "str") {
            # Convert str types to real Powershell strings
            $value = $value.ToString()
        } elseif ($type -eq "bool") {
            # Convert boolean types to real Powershell booleans
            $value = $value | ConvertTo-Bool
        } elseif ($type -eq "int") {
            # Convert int types to real Powershell integers
            $value = $value -as [int]
        } elseif ($type -eq "float") {
            # Convert float types to real Powershell floats
            $value = $value -as [float]
        } elseif ($type -eq "list") {
            if ($value -is [array]) {
                # Nothing to do
            } elseif ($value -is [string]) {
                # Convert string type to real Powershell array
                $value = $value.Split(",").Trim()
            } elseif ($value -is [int]) {
                $value = @($value)
            } else {
                Fail-Json -obj $resultobj -message "Get-AnsibleParam: Parameter '$name' is not a YAML list."
            }
            # , is not a typo, forces it to return as a list when it is empty or only has 1 entry
            return ,$value
        }
    }

    return $value
}

#Alias Get-attr-->Get-AnsibleParam for backwards compat. Only add when needed to ease debugging of scripts
If (!(Get-Alias -Name "Get-attr" -ErrorAction SilentlyContinue))
{
    New-Alias -Name Get-attr -Value Get-AnsibleParam
}

# Helper filter/pipeline function to convert a value to boolean following current
# Ansible practices
# Example: $is_true = "true" | ConvertTo-Bool
Function ConvertTo-Bool
{
    param(
        [parameter(valuefrompipeline=$true)]
        $obj
    )

    $boolean_strings = "yes", "on", "1", "true", 1
    $obj_string = [string]$obj

    if (($obj -is [boolean] -and $obj) -or $boolean_strings -contains $obj_string.ToLower()) {
        return $true
    } else {
        return $false
    }
}

# Helper function to parse Ansible JSON arguments from a "file" passed as
# the single argument to the module.
# Example: $params = Parse-Args $args
Function Parse-Args($arguments, $supports_check_mode = $false)
{
    $params = New-Object psobject
    If ($arguments.Length -gt 0)
    {
        $params = Get-Content $arguments[0] | ConvertFrom-Json
    }

    $check_mode = Get-AnsibleParam -obj $params -name "_ansible_check_mode" -type "bool" -default $false
    If ($check_mode -and -not $supports_check_mode)
    {
        Exit-Json @{
            skipped = $true
            changed = $false
            msg = "remote module does not support check mode"
        }
    }
    return $params
}

# Helper function to calculate a hash of a file in a way which powershell 3
# and above can handle:
Function Get-FileChecksum($path, $algorithm = 'sha1')
{
    If (Test-Path -Path $path -PathType Leaf)
    {
        switch ($algorithm)
        {
            'md5' { $sp = New-Object -TypeName System.Security.Cryptography.MD5CryptoServiceProvider }
            'sha1' { $sp = New-Object -TypeName System.Security.Cryptography.SHA1CryptoServiceProvider }
            'sha256' { $sp = New-Object -TypeName System.Security.Cryptography.SHA256CryptoServiceProvider }
            'sha384' { $sp = New-Object -TypeName System.Security.Cryptography.SHA384CryptoServiceProvider }
            'sha512' { $sp = New-Object -TypeName System.Security.Cryptography.SHA512CryptoServiceProvider }
            default { Fail-Json @{} "Unsupported hash algorithm supplied '$algorithm'" }
        }

        If ($PSVersionTable.PSVersion.Major -ge 4) {
            $raw_hash = Get-FileHash $path -Algorithm $algorithm
            $hash = $raw_hash.Hash.ToLower()
        } Else {
            $fp = [System.IO.File]::Open($path, [System.IO.Filemode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite);
            $hash = [System.BitConverter]::ToString($sp.ComputeHash($fp)).Replace("-", "").ToLower();
            $fp.Dispose();
        }
    }
    ElseIf (Test-Path -Path $path -PathType Container)
    {
        $hash = "3";
    }
    Else
    {
        $hash = "1";
    }
    return $hash
}

Function Get-PendingRebootStatus
{
    # Check if reboot is required, if so notify CA. The MSFT_ServerManagerTasks provider is missing on client SKUs
    #Function returns true if computer has a pending reboot
    $featureData = invoke-wmimethod -EA Ignore -Name GetServerFeature -namespace root\microsoft\windows\servermanager -Class MSFT_ServerManagerTasks
    $regData = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" "PendingFileRenameOperations" -EA Ignore
    $CBSRebootStatus = Get-ChildItem "HKLM:\\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing"  -ErrorAction SilentlyContinue| where {$_.PSChildName -eq "RebootPending"}
    if(($featureData -and $featureData.RequiresReboot) -or $regData -or $CBSRebootStatus)
    {
        return $True
    }
    else
    {
        return $False
    }
}

$result = @{changed=$false}

$params = Parse-Args -arguments $args -supports_check_mode $true
Set-Variable -Visibility Public -Option ReadOnly,AllScope,Constant -Name "log_path" -Value (
    Get-AnsibleParam $params "log_path"
)
$adapter_names = Get-AnsibleParam $params "adapter_names" -Default "*"
$dns_servers = Get-AnsibleParam $params "dns_servers" -aliases "ipv4_addresses","ip_addresses","addresses" -FailIfEmpty $result
$check_mode = Get-AnsibleParam $params "_ansible_check_mode" -Default $false


Function Write-DebugLog {
    Param(
    [string]$msg
    )

    $DebugPreference = "Continue"
    $ErrorActionPreference = "Continue"
    $date_str = Get-Date -Format u
    $msg = "$date_str $msg"

    Write-Debug $msg
    if($log_path) {
        Add-Content -LiteralPath $log_path -Value $msg
    }
}

Function Get-OptionalProperty {
    <#
        .SYNOPSIS
        Retreives a property that may not exist from an object that may be null.
        Optionally returns a default value.
        Optionally coalesces to a new type with -as.
        May return null, but will not throw.
    #>
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$true)]
        [Object]
        $InputObject ,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Name ,

        [Parameter()]
        [AllowNull()]
        [Object]
        $Default ,

        [Parameter()]
        [System.Type]
        $As
    )

    Process {
        if ($null -eq $InputObject) {
            return $null
        }

        $value = if ($InputObject.PSObject.Properties.Name -contains $Name) {
            $InputObject.$Name
        } else {
            $Default
        }

        if ($As) {
            return $value -as $As
        }

        return $value
    }
}

Function Test 
{
      Write-Output("AAAAAAA")
}

Function Get-NetAdapterInfo {
    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline=$true)]
        [String]$Name = "*"
    )

    Process {
        Write-Output("test")
        if (Get-Command -Name Get-NetAdapter -ErrorAction SilentlyContinue) {
            $adapter_info = Get-NetAdapter @PSBoundParameters | Select-Object -Property Name, InterfaceIndex
        } else {
            # Older hosts 2008/2008R2 don't have Get-NetAdapter, fallback to deprecated Win32_NetworkAdapter
            $cim_params = @{
                ClassName = "Win32_NetworkAdapter"
                Property = "InterfaceIndex", "NetConnectionID"
            }

            if ($Name.Contains("*")) {
                $cim_params.Filter = "NetConnectionID LIKE '$($Name.Replace("*", "%"))'"
            } else {
                $cim_params.Filter = "NetConnectionID = '$Name'"
            }

            $adapter_info = Get-CimInstance @cim_params | Select-Object -Property @(
                @{Name="Name"; Expression={$_.NetConnectionID}},
                @{Name="InterfaceIndex"; Expression={$_.InterfaceIndex}}
            )
        }

        # Need to filter the adapter that are not IPEnabled, while we are at it, also get the DNS config.
        $net_info = $adapter_info | ForEach-Object -Process {
            $cim_params = @{
                ClassName = "Win32_NetworkAdapterConfiguration"
                Filter = "InterfaceIndex = $($_.InterfaceIndex)"
                Property = "DNSServerSearchOrder", "IPEnabled", "SettingID"
            }
            $adapter_config = Get-CimInstance @cim_params |
                Select-Object -Property DNSServerSearchOrder, IPEnabled, @{
                    Name = 'InterfaceGuid'
                    Expression = { $_.SettingID }
                }

            if ($adapter_config.IPEnabled -eq $false) {
                return
            }

            $reg_info = $adapter_config | Get-RegistryNameServerInfo

            [PSCustomObject]@{
                Name = $_.Name
                InterfaceIndex = $_.InterfaceIndex
                InterfaceGuid = $adapter_config.InterfaceGuid
                RegInfo = $reg_info
            }
        }

        if (@($net_info).Count -eq 0 -and -not $Name.Contains("*")) {
            throw "Get-NetAdapterInfo: Failed to find network adapter(s) that are IP enabled with the name '$Name'"
        }

        $net_info
    }
}

Function Get-RegistryNameServerInfo {
    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true,Mandatory=$true)]
        [System.Guid]
        $InterfaceGuid
    )

    Begin {
        $protoItems = @{
            [System.Net.Sockets.AddressFamily]::InterNetwork = @{
                Interface = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{{{0}}}'
                StaticNameServer = 'NameServer'
                DhcpNameServer = 'DhcpNameServer'
                EnableDhcp = 'EnableDHCP'
            }

            [System.Net.Sockets.AddressFamily]::InterNetworkV6 = @{
                Interface = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces\{{{0}}}'
                StaticNameServer = 'NameServer'
                DhcpNameServer = 'Dhcpv6DNSServers'
                EnableDhcp = 'EnableDHCP'
            }
        }
    }

    Process {
        foreach ($addrFamily in $AddressFamilies.Keys) {
            $items = $protoItems[$addrFamily]
            $regPath = $items.Interface -f $InterfaceGuid

            if (($iface = Get-Item -LiteralPath $regPath -ErrorAction Ignore)) {
                $iprop = $iface | Get-ItemProperty
                $famInfo = @{
                    AddressFamily = $addrFamily
                    UsingDhcp = Get-OptionalProperty -InputObject $iprop -Name $items.EnableDhcp -As bool
                    EffectiveNameServers = @()
                    DhcpAssignedNameServers = @()
                    NameServerBadFormat = $false
                }

                if (($ns = Get-OptionalProperty -InputObject $iprop -Name $items.DhcpNameServer)) {
                    Write-Output("A")
                    $famInfo.EffectiveNameServers = $famInfo.DhcpAssignedNameServers = $ns.Split(' ')
                }

                if (($ns = Get-OptionalProperty -InputObject $iprop -Name $items.StaticNameServer)) {
                    Write-Output("B")

                    $famInfo.EffectiveNameServers = $famInfo.StaticNameServers = $ns -split '[,;\ ]'
                    $famInfo.UsingDhcp = $false
                    $famInfo.NameServerBadFormat = $ns -match '[;\ ]'
                }

                $famInfo
            }
        }
    }
}

# minimal impl of Set-DnsClientServerAddress for 2008/2008R2
Function Set-DnsClientServerAddressLegacy {
    Param(
        [int]$InterfaceIndex,
        [Array]$ServerAddresses=@(),
        [switch]$ResetServerAddresses
    )
    $cim_params = @{
        ClassName = "Win32_NetworkAdapterConfiguration"
        Filter = "InterfaceIndex = $InterfaceIndex"
        KeyOnly = $true
    }
    $adapter_config = Get-CimInstance @cim_params

    If($ResetServerAddresses) {
        $arguments = @{}
    }
    Else {
        $arguments = @{ DNSServerSearchOrder = [string[]]$ServerAddresses }
    }
    $res = Invoke-CimMethod -InputObject $adapter_config -MethodName SetDNSServerSearchOrder -Arguments $arguments

    If($res.ReturnValue -ne 0) {
        throw "Set-DnsClientServerAddressLegacy: Error calling SetDNSServerSearchOrder, code $($res.ReturnValue))"
    }
}

If(-not $(Get-Command Set-DnsClientServerAddress -ErrorAction SilentlyContinue)) {
    New-Alias Set-DnsClientServerAddress Set-DnsClientServerAddressLegacy
}

Function Test-DnsClientMatch {
    Param(
        [PSCustomObject]$AdapterInfo,
        [System.Net.IPAddress[]] $dns_servers
    )
    Write-DebugLog ("Getting DNS config for adapter {0}" -f $AdapterInfo.Name)

    foreach ($proto in $AdapterInfo.RegInfo) {
        $desired_dns = if ($dns_servers) {
            $dns_servers | Where-Object -FilterScript {$_.AddressFamily -eq $proto.AddressFamily}
        }

        $current_dns = [System.Net.IPAddress[]]($proto.EffectiveNameServers)
        Write-DebugLog ("Current DNS settings for '{1}' Address Family: {0}" -f ([string[]]$current_dns -join ", "),$AddressFamilies[$proto.AddressFamily])

        if ($proto.NameServerBadFormat) {
            Write-DebugLog "Malicious DNS server format detected. Will set DNS desired state."
            return $false
            # See: https://www.welivesecurity.com/2016/06/02/crouching-tiger-hidden-dns/
        }

        if ($proto.UsingDhcp -and -not $desired_dns) {
            Write-DebugLog "DHCP DNS Servers are in use and no DNS servers were requested (DHCP is desired)."
        } else {
            if ($desired_dns -and -not $current_dns) {
                Write-DebugLog "There are currently no DNS servers in use, but they should be present."
                return $false
            }

            if ($current_dns -and -not $desired_dns) {
                Write-DebugLog "There are currently DNS servers in use, but they should be absent."
                return $false
            }

            if ($null -ne $current_dns -and
                $null -ne $desired_dns -and
                (Compare-Object -ReferenceObject $current_dns -DifferenceObject $desired_dns -SyncWindow 0)) {
                Write-DebugLog "Static DNS servers are not in the desired state (incorrect or in the wrong order)."
                return $false
            }
        }

        Write-DebugLog ("Current DNS settings match ({0})." -f ([string[]]$desired_dns -join ", "))
    }
    return $true
}


Function Assert-IPAddress {
    Param([string] $address)

    $addrout = $null

    return [System.Net.IPAddress]::TryParse($address, [ref] $addrout)
}

Function Set-DnsClientAddresses
{
    Param(
        [PSCustomObject]$AdapterInfo,
        [System.Net.IPAddress[]] $dns_servers
    )

    Write-DebugLog ("Setting DNS addresses for adapter {0} to ({1})" -f $AdapterInfo.Name, ([string[]]$dns_servers -join ", "))

    If ($dns_servers) {
        Set-DnsClientServerAddress -InterfaceIndex $AdapterInfo.InterfaceIndex -ServerAddresses $dns_servers
    } Else {
        Set-DnsClientServerAddress -InterfaceIndex $AdapterInfo.InterfaceIndex -ResetServerAddress
    }
}

if($dns_servers -is [string]) {
    if($dns_servers.Length -gt 0) {
        $dns_servers = @($dns_servers)
    } else {
        $dns_servers = @()
    }
}
# Using object equals here, to check for exact match (without implicit type conversion)
if([System.Object]::Equals($adapter_names, "*")) {
    $adapters = Get-NetAdapterInfo
} else {
    $adapters = $adapter_names | Get-NetAdapterInfo
}

Try {

    Write-DebugLog ("Validating IP addresses ({0})" -f ($dns_servers -join ", "))
    $invalid_addresses = @($dns_servers | Where-Object { -not (Assert-IPAddress $_) })
    if($invalid_addresses.Count -gt 0) {
        throw "Invalid IP address(es): ({0})" -f ($invalid_addresses -join ", ")
    }

    foreach($adapter_info in $adapters) {
        Write-DebugLog ("Validating adapter name {0}" -f $adapter_info.Name)

        if(-not (Test-DnsClientMatch $adapter_info $dns_servers)) {
            $result.changed = $true
            if(-not $check_mode) {
                Set-DnsClientAddresses $adapter_info $dns_servers
            } else {
                Write-DebugLog "Check mode, skipping"
            }
        }
    }

    Exit-Json $result

}
Catch {
    $excep = $_

    Write-DebugLog "Exception: $($excep | out-string)"

    Throw
}

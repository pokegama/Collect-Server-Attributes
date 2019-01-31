<#
    Collect-Server-Attributes

    SYNOPSIS
        Query a list of remote windows systems for information

    DESCRIPTION
        Given a list of server names in CSV format as input, this will create
        a report in CSV format of attributes for the input servers.  The input
        CSV must have a column header literal of "Hostname".

    EXAMPLE
        Collect-Server-Attributes c:\serverList.csv c:\report.csv

#>


<# Mandatory arguments are the server list of server names.  The server list
   should be a CSV file with a column header of 'HostName'. Example:
   HostName
   svhscbord
   svmigpos
   svmigposrpt
   svmigposint #>
Param(
  [Parameter(Mandatory=$true, position=0)][string]$serverListFilename,
  [Parameter(Mandatory=$true, position=1)][string]$attributeReportFilename
)

## The name of the column heading to look for on the server list CSV.
$ColumnHeader = "Hostname"
## Pull in the list of servers
$servers   = import-csv $serverListFilename | select-object $ColumnHeader
$rawReport = @()
## Iterate through the list of servers
foreach($server in $servers) {
    ## Initialize our variables
    $serverName      = $server.($ColumnHeader)
    $compSys         = $null
    $operSys         = $null
    $netConfig       = $null
    $remoteReg       = $null
    $instances       = $null
    $sqlRegKey       = $null
    $webrootRegKey   = $null
    $operSysName     = ''
    $operSysVer      = ''
    $operSysArch     = ''
    $compSysModel    = ''
    $sqlVer          = ''
    $webrootOsBuild  = ''
    $netConfigMac    = ''
    $netConfigIp     = ''
    $netConfigSubnet = ''
    Write-Host "Server: $serverName"
    ## Verify the remote server is online
    if(Test-Connection $serverName -Count 3 -Quiet) {
        try {
            <#
             # Win32_ComputerSystem
             #>
            $compSys   = Get-WmiObject -computername $serverName -class Win32_ComputerSystem -ErrorAction Stop
            if($compSys) {
                $compSysModel = $compSys.Model
            }
            <#
            # win32_operatingsystem
            #>
            $operSys   = Get-WmiObject -computername $serverName -class win32_operatingsystem -ErrorAction Stop
            if($operSys) {
                $operSysName = $operSys.name.split("|")[0]
                $operSysVer  = $operSys.Version
                $operSysArch = $operSys.OSArchitecture
            }
            <#
             # Win32_NetworkAdapterConfiguration
             #>
            $netConfig = Get-WmiObject -computername $serverName -class Win32_NetworkAdapterConfiguration -ErrorAction Stop | `
                            where-object { $_.IPAddress -ne $null }
            if($netConfig) {
                $netConfigMac    = $netConfig.MACAddress
                $netConfigIp     = ($netConfig.IPAddress -join (", "))
                $netConfigSubnet = ($netConfig.IPSubnet  -join (", "))
            }
            
        } catch {
            Write-Warning "RPC server not available on $serverName"
        }
        ## Attempt to access the server's registry
        try {
            $remoteReg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $server.($ColumnHeader))
            ## Check remote registry for SQL Server version.
            try {
                $sqlRegKey = $remoteReg.OpenSubKey("SOFTWARE\Microsoft\Microsoft SQL Server")
            } catch {
                Write-Warning "No permissions to registry on $serverName"
            }
            if($sqlRegKey) {
                $instances = $sqlRegKey.GetValue("InstalledInstances")
                if($instances) {
                    #Write-Verbose ($instances | Out-String) -Verbose
                    foreach ($instance in $instances)
                    {
                        $sqlVerRegKey = $null
                        $sqlVerRegKey = $remoteReg.OpenSubKey("SOFTWARE\Microsoft\Microsoft SQL Server\$instance\MSSQLServer\CurrentVersion")
                        if($sqlVerRegKey) {
                            $sqlVer = $sqlVerRegKey.GetValue("CurrentVersion")
                        }
                        #Write-Verbose ($edition | Out-String) -Verbose
                    }
                }
            }
            try {
                ## Check the remote registry for Webroot
                $webrootRegKey = $remoteReg.OpenSubKey("SOFTWARE\WOW6432Node\webroot")
            } catch {
                Write-Warning "No permissions to registry on $serverName"
            }
            if($webrootRegKey) {
                $webrootOsBuild = $webrootRegKey.GetValue("initialOSBuildNumber")
            }
        } catch {
            Write-Warning "Registry not available on $serverName"
        }
    } else {
        Write-Warning "$serverName is offline"
    }
    ## Append the attributes to the record object
    $attRec= @{}
    $attRec.add("Hostname", $serverName)
    $attRec.add("Operating System", $operSysName)
    $attRec.add("Version", $operSysVer)
    $attRec.add("Architecture", $operSysArch)
    $attRec.add("Hardware Model", $compSysModel)
    $attRec.add("SQL Server Version", $sqlVer)
    $attRec.add("Webroot OS Build", $webrootOsBuild)
    $attRec.add("MAC Address", $netConfigMac)
    $attRec.add("IP Address", $netConfigIp)
    $attRec.add("Subnet", $netConfigSubnet)
    ## Build the raw report from the attribute record list.
    $rawReport += New-Object PSObject -Property $attRec | Select-Object "Hostname","Operating System", "Version", `
        "Architecture", "Hardware Model", "SQL Server Version", "Webroot OS Build", "MAC Address","IP Address","Subnet"
    #Write-Verbose ($rawReport | Out-String) -Verbose
    $rawReport | Export-CSV $attributeReportFilename -NoTypeInformation
 }
 # EOF
function Get-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param
    (
        [Parameter()]
        [ValidateSet("Present","Absent")]
        [System.String]
        $Ensure = "Present",

        [Parameter(Mandatory = $true)]
        [System.String]
        $SourcePath,

        [Parameter()]
        [System.String]
        $SourceFolder = "\SystemCenter2012R2\VirtualMachineManager",

        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]
        $SetupCredential,

        [Parameter()]
        [System.Management.Automation.PSCredential]
        $vmmService,

        [Parameter()]
        [System.String]
        $ProductKey,

        [Parameter()]
        [System.String]
        $UserName,

        [Parameter()]
        [System.String]
        $CompanyName,

        [Parameter()]
        [System.String]
        $ProgramFiles,

        [Parameter()]
        [System.Boolean]
        $ClusterManagementServer,

        [Parameter()]
        [System.Boolean]
        $FirstManagementServer,

        [Parameter()]
        [System.String]
        $CreateNewSqlDatabase = "1",

        [Parameter(Mandatory = $true)]
        [System.String]
        $SqlMachineName,

        [Parameter(Mandatory = $true)]
        [System.String]
        $SqlInstanceName,

        [Parameter()]
        [System.String]
        $SqlDatabaseName = "VirtualManagerDB",

        [Parameter()]
        [System.UInt16]
        $IndigoTcpPort = 8100,

        [Parameter()]
        [System.UInt16]
        $IndigoHTTPSPort = 8101,

        [Parameter()]
        [System.UInt16]
        $IndigoNETTCPPort = 8102,

        [Parameter()]
        [System.UInt16]
        $IndigoHTTPPort = 8103,

        [Parameter()]
        [System.UInt16]
        $WSManTcpPort = 5985,

        [Parameter()]
        [System.UInt16]
        $BitsTcpPort = 443,

        [Parameter()]
        [System.String]
        $CreateNewLibraryShare = "1",

        [Parameter()]
        [System.String]
        $LibraryShareName = "MSSCVMMLibrary",

        [Parameter()]
        [System.String]
        $LibrarySharePath = "%ProgramData%\Virtual Machine Manager Library Files",

        [Parameter()]
        [System.String]
        $LibraryShareDescription = "Virtual Machine Manager Library Files",

        [Parameter()]
        [System.String]
        $TopContainerName,

        [Parameter()]
        [System.String]
        $VmmServerName,

        [Parameter()]
        [System.String]
        $VMMStaticIPAddress,

        [Parameter()]
        [System.Byte]
        $RetainSqlDatabase,

        [Parameter()]
        [System.Byte]
        $ForceHAVMMUninstall,

        [Parameter()]
        [System.Byte]
        $SQMOptIn,

        [Parameter()]
        [System.Byte]
        $MUOptIn
    )

    Import-Module $PSScriptRoot\..\..\xPDT.psm1
        
    $Path = Join-Path -Path (Join-Path -Path $SourcePath -ChildPath $SourceFolder) -ChildPath "setup.exe"
    $Path = ResolvePath $Path
    $Version = (Get-Item -Path $Path).VersionInfo.ProductVersion
    Write-Verbose -Message "Detected Version as '$($Version)'"
    switch($Version)
    {
        "3.2.7510.0"
        {
            $IdentifyingNumber = "{59518B15-FC64-4CF9-A4D1-0EE1B4A63088}"
        }
        "3.2.9013.0"
        {
            $IdentifyingNumber = "{59518B15-FC64-4CF9-A4D1-0EE1B4A63088}"
        }
        Default
        {
            throw "Unknown version of Virtual Machine Manager!"
        }
    }

    if(Get-CimInstance -Class Win32_Product | Where-Object {$_.IdentifyingNumber -eq $IdentifyingNumber})
    {
        $vmmServiceUsername = (Get-CimInstance -Class Win32_Service | Where-Object {$_.Name -eq "SCVMMService"}).StartName
        $UserName = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Microsoft System Center Virtual Machine Manager Server\Setup\Registration" -Name "UserName").UserName
        $CompanyName = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Microsoft System Center Virtual Machine Manager Server\Setup\Registration" -Name "CompanyName").CompanyName
        $ProgramFiles = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Microsoft System Center Virtual Machine Manager Server\Setup" -Name "InstallPath").InstallPath
        $SqlMachineName = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Microsoft System Center Virtual Machine Manager Server\Settings\SQL" -Name "MachineFQDN").MachineFQDN
        $SqlInstanceName = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Microsoft System Center Virtual Machine Manager Server\Settings\SQL" -Name "MachineFQDN").MachineFQDN
        if($SqlInstanceName -eq $SqlMachineName)
        {
            $SqlInstanceName = "MSSQLSERVER"
        }
        $SqlDatabaseName = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Microsoft System Center Virtual Machine Manager Server\Settings\SQL" -Name "DatabaseName").DatabaseName
        foreach($Port in @("IndigoTcpPort","IndigoHTTPSPort","IndigoNETTCPPort","IndigoHTTPPort","WSManTcpPort","BitsTcpPort"))
        {
            Set-Variable -Name $Port -Value (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Microsoft System Center Virtual Machine Manager Server\Settings" -Name $Port).$Port
        }
        $LibraryShareName = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Microsoft System Center Virtual Machine Manager Server\Settings\Library" -Name "LibraryShareName").LibraryShareName
        $LibrarySharePath = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Microsoft System Center Virtual Machine Manager Server\Settings\Library" -Name "LibrarySharePath").LibrarySharePath

        $returnValue = @{
            Ensure = "Present"
            SourcePath = $SourcePath
            SourceFolder = $SourceFolder
            vmmServiceUsername = $vmmServiceUsername
            UserName = $UserName
            CompanyName = $CompanyName
            ProgramFiles = $ProgramFiles
    #        ClusterManagementServer = [System.Boolean]
            SqlMachineName = $SqlMachineName
            SqlInstanceName = $SqlInstanceName
            SqlDatabaseName = $SqlDatabaseName
            IndigoTcpPort = $IndigoTcpPort
            IndigoHTTPSPort = $IndigoHTTPSPort
            IndigoNETTCPPort = $IndigoNETTCPPort
            IndigoHTTPPort = $IndigoHTTPPort
            WSManTcpPort = $WSManTcpPort
            BitsTcpPort = $BitsTcpPort
            LibraryShareName = $LibraryShareName
            LibrarySharePath = $LibrarySharePath
    #        TopContainerName = [System.String]
    #        VmmServerName = [System.String]
    #        VMMStaticIPAddress = [System.String]
        }
    }
    else
    {
        $returnValue = @{
            Ensure = "Absent"
            SourcePath = $SourcePath
            SourceFolder = $SourceFolder
        }
    }

    $returnValue
}


function Set-TargetResource
{
    # Suppressing this rule because $global:DSCMachineStatus is used to trigger a reboot, either by force or when there are pending changes.
    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidGlobalVars', '')]
    [CmdletBinding()]
    param
        (
        [Parameter()]
        [ValidateSet("Present","Absent")]
        [System.String]
        $Ensure = "Present",

        [Parameter(Mandatory = $true)]
        [System.String]
        $SourcePath,

        [Parameter()]
        [System.String]
        $SourceFolder = "\SystemCenter2012R2\VirtualMachineManager",

        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]
        $SetupCredential,

        [Parameter()]
        [System.Management.Automation.PSCredential]
        $vmmService,

        [Parameter()]
        [System.String]
        $ProductKey,

        [Parameter()]
        [System.String]
        $UserName,

        [Parameter()]
        [System.String]
        $CompanyName,

        [Parameter()]
        [System.String]
        $ProgramFiles,

        [Parameter()]
        [System.Boolean]
        $ClusterManagementServer,

        [Parameter()]
        [System.Boolean]
        $FirstManagementServer,

        [Parameter()]
        [System.String]
        $CreateNewSqlDatabase = "1",

        [Parameter(Mandatory = $true)]
        [System.String]
        $SqlMachineName,

        [Parameter(Mandatory = $true)]
        [System.String]
        $SqlInstanceName,

        [Parameter()]
        [System.String]
        $SqlDatabaseName = "VirtualManagerDB",

        [Parameter()]
        [System.UInt16]
        $IndigoTcpPort = 8100,

        [Parameter()]
        [System.UInt16]
        $IndigoHTTPSPort = 8101,

        [Parameter()]
        [System.UInt16]
        $IndigoNETTCPPort = 8102,

        [Parameter()]
        [System.UInt16]
        $IndigoHTTPPort = 8103,

        [Parameter()]
        [System.UInt16]
        $WSManTcpPort = 5985,

        [Parameter()]
        [System.UInt16]
        $BitsTcpPort = 443,

        [Parameter()]
        [System.String]
        $CreateNewLibraryShare = "1",

        [Parameter()]
        [System.String]
        $LibraryShareName = "MSSCVMMLibrary",

        [Parameter()]
        [System.String]
        $LibrarySharePath = "%ProgramData%\Virtual Machine Manager Library Files",

        [Parameter()]
        [System.String]
        $LibraryShareDescription = "Virtual Machine Manager Library Files",

        [Parameter()]
        [System.String]
        $TopContainerName,

        [Parameter()]
        [System.String]
        $VmmServerName,

        [Parameter()]
        [System.String]
        $VMMStaticIPAddress,

        [Parameter()]
        [System.Byte]
        $RetainSqlDatabase,

        [Parameter()]
        [System.Byte]
        $ForceHAVMMUninstall,

        [Parameter()]
        [System.Byte]
        $SQMOptIn,

        [Parameter()]
        [System.Byte]
        $MUOptIn
    )

    Import-Module $PSScriptRoot\..\..\xPDT.psm1
        
    $Path = Join-Path -Path (Join-Path -Path $SourcePath -ChildPath $SourceFolder) -ChildPath "setup.exe"
    $Path = ResolvePath $Path
    $Version = (Get-Item -Path $Path).VersionInfo.ProductVersion
    Write-Verbose -Message "Detected Version as '$($Version)'"
    switch($Version)
    {
        "3.2.7510.0"
        {
            $IdentifyingNumber = "{59518B15-FC64-4CF9-A4D1-0EE1B4A63088}"
        }
        "3.2.9013.0"
        {
            $IdentifyingNumber = "{59518B15-FC64-4CF9-A4D1-0EE1B4A63088}"
        }
        Default
        {
            throw "Unknown version of Virtual Machine Manager!"
        }
    }

    # Create INI file
    $TempFile = [IO.Path]::GetTempFileName()
    $INIFile = @()
    $INIFile += "[Options]"
    $INIFile += "RemoteDatabaseImpersonation=0"

    switch($Ensure)
    {
        "Present"
        {
            # Set defaults, if they couldn't be set in param due to null configdata input
            if ($IndigoTcpPort -eq 0)
            {
                $IndigoTcpPort = 8100
            }
            if ($IndigoHTTPSPort -eq 0)
            {
                $IndigoHTTPSPort = 8101
            }
            if ($IndigoNETTCPPort -eq 0)
            {
                $IndigoNETTCPPort = 8102
            }
            if ($IndigoHTTPPort -eq 0)
            {
                $IndigoHTTPPort = 8103
            }
            if ($WSManTcpPort -eq 0)
            {
                $WSManTcpPort = 5985
            }
            if ($BitsTcpPort -eq 0)
            {
                $BitsTcpPort = 443
            }
            if ($SQMOptIn -ne 1)
            {
                $SQMOptIn = 0
            }
            if ($MUOptIn -ne 1)
            {
                $MUOptIn = 0
            }

            $INIFileVars = @(
                "ProductKey",
                "UserName",
                "CompanyName",
                "ProgramFiles",
                "SQLInstanceName",
                "SQLDatabaseName",
                "SQLMachineName",
                "IndigoTcpPort",
                "IndigoHTTPSPort",
                "IndigoNETTCPPort",
                "IndigoHTTPPort",
                "WSManTcpPort",
                "BitsTcpPort",
                "SQMOptIn",
                "MUOptIn",
                "TopContainerName"
            )
            if($ClusterManagementServer -and !$FirstManagementServer)
            {
                $INIFile += "CreateNewSQLDatabase=0"
            }
            else
            {
                $INIFileVars += @(
                    "CreateNewSQLDatabase"
                )
            }
            if($PSBoundParameters.ContainsKey("vmmService"))
            {
                $INIFile += "VMMServiceLocalAccount=0"
            }
            else
            {
                $INIFile += "VMMServiceLocalAccount=1"
            }
            if($ClusterManagementServer)
            {
                $INIFileVars += @(
                    "VmmServerName",
                    "VmmStaticIPAddress"
                )
                $INIFile += "HighlyAvailable=1"
                if($FirstManagementServer)
                {
                    $INIFile += "HighlyAvailable2ndNode=0"
                }
                else
                {
                    $INIFile += "HighlyAvailable2ndNode=1"
                }
            }
            else 
            {
                $INIFileVars += @(
                    "CreateNewLibraryShare",
                    "LibraryShareName",
                    "LibrarySharePath",
                    "LibraryShareDescription"
                )
            }

            # Create install arguments
            $Arguments = "/i /IAcceptSCEULA /server /f $TempFile"
            if($PSBoundParameters.ContainsKey("vmmService"))
            {
                $Arguments += " /vmmServiceDomain " + $vmmService.GetNetworkCredential().Domain
                $Arguments += " /vmmServiceUserName " + $vmmService.GetNetworkCredential().UserName
                $Arguments += " /vmmServiceUserPassword " + $vmmService.GetNetworkCredential().Password
            }
        }
        "Absent"
        {
            # Set defaults, if they couldn't be set in param due to null configdata input
            if ($RetainSqlDatabase -ne 1)
            {
                $RetainSqlDatabase = 0
            }
            if ($ForceHAVMMUninstall -ne 1)
            {
                $ForceHAVMMUninstall = 0
            }

            # Create uninstall arguments
            $INIFileVars = @(
                "RetainSqlDatabase",
                "ForceHAVMMUninstall"
            )

            # Create install arguments
            $Arguments = "/x /server /f $TempFile"
        }
    }

    foreach($INIFileVar in $INIFileVars)
    {
        if(!([String]::IsNullOrEmpty((Get-Variable -Name $INIFileVar).Value)))
        {
            $INIFile += "$INIFileVar=" + [Environment]::ExpandEnvironmentVariables((Get-Variable -Name $INIFileVar).Value)
        }
    }

    Write-Verbose "Path: $Path"
    Write-Verbose "INIFile: $TempFile"
    foreach($Line in $INIFile)
    {
        Add-Content -Path $TempFile -Value $Line -Encoding Ascii
        # Replace sensitive values for verbose output
        $LineLog = $Line
        if($PSBoundParameters.ContainsKey("ProductKey"))
        {
            $LineLog = $LineLog.Replace($ProductKey,"*****-*****-*****-*****-*****")
        }
        Write-Verbose $LineLog
    }

    # Replace sensitive values for verbose output
    $Log = $Arguments
    if($PSBoundParameters.ContainsKey("vmmService"))
    {
        $Log = $Log.Replace($vmmService.GetNetworkCredential().Password,"********")
    }

    Write-Verbose "Arguments: $Log"
    
    $Process = StartWin32Process -Path $Path -Arguments $Arguments -Credential $SetupCredential -AsTask
    Write-Verbose $Process
    WaitForWin32ProcessEnd -Path $Path -Arguments $Arguments -Credential $SetupCredential

    # Clean up
    if(Test-Path -Path $TempFile)
    {
        Remove-Item -Path $TempFile
    }

    if($null -ne (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name 'PendingFileRenameOperations' -ErrorAction SilentlyContinue))
    {
        $global:DSCMachineStatus = 1
    }
    else
    {
        if(!(Test-TargetResource @PSBoundParameters))
        {
            throw "Set-TargetResouce failed"
        }
    }
}


function Test-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param
        (
        [Parameter()]
        [ValidateSet("Present","Absent")]
        [System.String]
        $Ensure = "Present",

        [Parameter(Mandatory = $true)]
        [System.String]
        $SourcePath,

        [Parameter()]
        [System.String]
        $SourceFolder = "\SystemCenter2012R2\VirtualMachineManager",

        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]
        $SetupCredential,

        [Parameter()]
        [System.Management.Automation.PSCredential]
        $vmmService,

        [Parameter()]
        [System.String]
        $ProductKey,

        [Parameter()]
        [System.String]
        $UserName,

        [Parameter()]
        [System.String]
        $CompanyName,

        [Parameter()]
        [System.String]
        $ProgramFiles,

        [Parameter()]
        [System.Boolean]
        $ClusterManagementServer,

        [Parameter()]
        [System.Boolean]
        $FirstManagementServer,

        [Parameter()]
        [System.String]
        $CreateNewSqlDatabase = "1",

        [Parameter(Mandatory = $true)]
        [System.String]
        $SqlMachineName,

        [Parameter(Mandatory = $true)]
        [System.String]
        $SqlInstanceName,

        [Parameter()]
        [System.String]
        $SqlDatabaseName = "VirtualManagerDB",

        [Parameter()]
        [System.UInt16]
        $IndigoTcpPort = 8100,

        [Parameter()]
        [System.UInt16]
        $IndigoHTTPSPort = 8101,

        [Parameter()]
        [System.UInt16]
        $IndigoNETTCPPort = 8102,

        [Parameter()]
        [System.UInt16]
        $IndigoHTTPPort = 8103,

        [Parameter()]
        [System.UInt16]
        $WSManTcpPort = 5985,

        [Parameter()]
        [System.UInt16]
        $BitsTcpPort = 443,

        [Parameter()]
        [System.String]
        $CreateNewLibraryShare = "1",

        [Parameter()]
        [System.String]
        $LibraryShareName = "MSSCVMMLibrary",

        [Parameter()]
        [System.String]
        $LibrarySharePath = "%ProgramData%\Virtual Machine Manager Library Files",

        [Parameter()]
        [System.String]
        $LibraryShareDescription = "Virtual Machine Manager Library Files",

        [Parameter()]
        [System.String]
        $TopContainerName,

        [Parameter()]
        [System.String]
        $VmmServerName,

        [Parameter()]
        [System.String]
        $VMMStaticIPAddress,

        [Parameter()]
        [System.Byte]
        $RetainSqlDatabase,

        [Parameter()]
        [System.Byte]
        $ForceHAVMMUninstall,

        [Parameter()]
        [System.Byte]
        $SQMOptIn,

        [Parameter()]
        [System.Byte]
        $MUOptIn
    )
    Write-Verbose -Message "Testing if VMM Server is installed"
    $result = ((Get-TargetResource @PSBoundParameters).Ensure -eq $Ensure)
    
    $result
}


Export-ModuleMember -Function *-TargetResource

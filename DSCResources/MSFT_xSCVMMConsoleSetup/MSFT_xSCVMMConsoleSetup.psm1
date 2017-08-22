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
        [System.String]
        $ProgramFiles,

        [Parameter()]
        [System.UInt16]
        $IndigoTcpPort = 8100,

        [Parameter()]
        [System.Byte]
        $MUOptIn
    )

    Import-Module $PSScriptRoot\..\..\xPDT.psm1
        
    $Path = Join-Path -Path (Join-Path -Path $SourcePath -ChildPath $SourceFolder) -ChildPath "setup.exe"
    $Path = ResolvePath $Path
    $Version = (Get-Item -Path $Path).VersionInfo.ProductVersion

    switch($Version)
    {
        "3.2.7510.0"
        {
            $IdentifyingNumber = "{CDFB453F-5FA4-4884-B282-F46BDFC06051}"
        }
        "3.2.9013.0"
        {
            $IdentifyingNumber = "{CDFB453F-5FA4-4884-B282-F46BDFC06051}"
        }
        Default
        {
            throw "Unknown version of Virtual Machine Manager!"
        }
    }
    Write-Verbose "Checking Win32_Product Class for SCVMM Console"
    if(Get-CimInstance -ClassName Win32_Product | Where-Object {$_.IdentifyingNumber -eq $IdentifyingNumber})
    {
        $IndigoTcpPort = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Microsoft System Center Virtual Machine Manager Administrator Console\Settings" -Name "IndigoTcpPort").IndigoTcpPort
        Write-Verbose "SCVMM Console is present"
        $returnValue = @{
            Ensure = "Present"
            SourcePath = $SourcePath
            SourceFolder = $SourceFolder
            IndigoTcpPort = $IndigoTcpPort
        }
    }
    else
    {
        Write-Verbose "SCVMM Console is absent"
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
        [System.String]
        $ProgramFiles,

        [Parameter()]
        [System.UInt16]
        $IndigoTcpPort = 8100,

        [Parameter()]
        [System.Byte]
        $MUOptIn
    )

    Import-Module $PSScriptRoot\..\..\xPDT.psm1
        
    $Path = Join-Path -Path (Join-Path -Path $SourcePath -ChildPath $SourceFolder) -ChildPath "setup.exe"
    $Path = ResolvePath $Path
    $Version = (Get-Item -Path $Path).VersionInfo.ProductVersion
    Write-Verbose "Path: $Path"

    switch($Version)
    {
        "3.2.7510.0"
        {
            $IdentifyingNumber = "{CDFB453F-5FA4-4884-B282-F46BDFC06051}"
            $MSIdentifyingNumber = "{59518B15-FC64-4CF9-A4D1-0EE1B4A63088}"
        }
        "3.2.9013.0"
        {
            $IdentifyingNumber = "{CDFB453F-5FA4-4884-B282-F46BDFC06051}"
            $MSIdentifyingNumber = "{59518B15-FC64-4CF9-A4D1-0EE1B4A63088}"
        }
        Default
        {
            throw "Unknown version of Virtual Machine Manager!"
        }
    }

    $TempFile = [IO.Path]::GetTempFileName()

    switch($Ensure)
    {
        "Present"
        {
            # Set defaults, if they couldn't be set in param due to null configdata input
            if ($IndigoTcpPort -eq 0)
            {
                $IndigoTcpPort = 8100
            }
            if ($MUOptIn -ne 1)
            {
                $MUOptIn = 0
            }

            # Create INI file
            $INIFile = @()
            $INIFile += "[Options]"

            $INIFileVars = @(
                "ProgramFiles",
                "IndigoTcpPort",
                "MUOptIn"
            )

            foreach($INIFileVar in $INIFileVars)
            {
                if(!([String]::IsNullOrEmpty((Get-Variable -Name $INIFileVar).Value)))
                {
                    $INIFile += "$INIFileVar=" + [Environment]::ExpandEnvironmentVariables((Get-Variable -Name $INIFileVar).Value)
                }
            }

            Write-Verbose "INIFile: $TempFile"
            foreach($Line in $INIFile)
            {
                Add-Content -Path $TempFile -Value $Line -Encoding Ascii
                Write-Verbose $Line
            }

            # Create install arguments
            $Arguments = "/i /IAcceptSCEULA /client /f $TempFile"
            $Arguments = "/i /IAcceptSCEULA /client /f $TempFile"
        }
        "Absent"
        {
            # Do not remove console from management server
            if(!(Get-CimInstance -ClassName Win32_Product | Where-Object {$_.IdentifyingNumber -eq $MSIdentifyingNumber}))
            {
                # Create install arguments
                $Arguments = "/x /client"
            }
            else
            {
                throw "VMM Console should not be removed from a VMM Management Server!"
            }
        }
    }

    Write-Verbose "Arguments: $Arguments"
    
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

        [Parameter()]
        [System.String]
        $ProgramFiles,

        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]
        $SetupCredential,

        [Parameter()]
        [System.UInt16]
        $IndigoTcpPort = 8100,

        [Parameter()]
        [System.Byte]
        $MUOptIn
    )
    Write-Verbose -Message "Testing SCVMM Console Installation"
    $result = ((Get-TargetResource @PSBoundParameters).Ensure -eq $Ensure)
    
    $result
}


Export-ModuleMember -Function *-TargetResource

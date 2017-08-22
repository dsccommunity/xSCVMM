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
        $Principal,

        [Parameter(Mandatory = $true)]
        [System.String]
        $UserRole,

        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]
        $SCVMMAdminCredential
    )
    Write-Verbose "Checking System Center User Roles"
    $Ensure = Invoke-Command -ComputerName . -Credential $SCVMMAdminCredential {
        $Ensure = $args[0]
        $Principal = $args[1]
        $UserRole = $args[2]
        if(Get-SCUserRole -VMMServer $env:COMPUTERNAME -Name $UserRole | ForEach-Object {$_.Members} | Where-Object {$_.Name -eq $Principal})
        {
            "Present"
        }
        else
        {
            "Absent"
        }
    } -ArgumentList @($Ensure,$Principal,$UserRole)

    $returnValue = @{
        Ensure = $Ensure
        Principal = $Principal
        UserRole = $UserRole
    }

    $returnValue
}


function Set-TargetResource
{
    [CmdletBinding()]
    param
    (
        [Parameter()]
        [ValidateSet("Present","Absent")]
        [System.String]
        $Ensure = "Present",

        [Parameter(Mandatory = $true)]
        [System.String]
        $Principal,

        [Parameter(Mandatory = $true)]
        [System.String]
        $UserRole,

        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]
        $SCVMMAdminCredential
    )
    Write-Verbose "Setting System Center VMM User Roles"
    Invoke-Command -ComputerName . -Credential $SCVMMAdminCredential {
        $Ensure = $args[0]
        $Principal = $args[1]
        $UserRole = $args[2]
        switch($Ensure)
        {
            "Present"
            {
                Write-Verbose "Adding Use Roles"
                if(!(Get-SCUserRole -VMMServer $env:COMPUTERNAME -Name $UserRole | ForEach-Object {$_.Members} | Where-Object {$_.Name -eq $Principal}))
                {
                    Get-SCUserRole -VMMServer $env:COMPUTERNAME -Name $UserRole | Set-SCUserRole -AddMember $Principal
                }
            }
            "Absent"
            {
                Write-Verbose "Removing Use Roles"
                if(Get-SCUserRole -VMMServer $env:COMPUTERNAME -Name $UserRole | ForEach-Object {$_.Members} | Where-Object {$_.Name -eq $Principal})
                {
                    Get-SCUserRole -VMMServer $env:COMPUTERNAME -Name $UserRole | Set-SCUserRole -RemoveMember $Principal
                }
            }
        }
    } -ArgumentList @($Ensure,$Principal,$UserRole)

    if(!(Test-TargetResource @PSBoundParameters))
    {
        throw "Set-TargetResouce failed"
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
        $Principal,

        [Parameter(Mandatory = $true)]
        [System.String]
        $UserRole,

        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]
        $SCVMMAdminCredential
    )
    Write-Verbose "Testing User Roles"
    $result = ((Get-TargetResource @PSBoundParameters).Ensure -eq $Ensure)

    $result
}


Export-ModuleMember -Function *-TargetResource

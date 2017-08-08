function Invoke-Profiler
{
<#
.SYNOPSIS

Invoke-Profiler is an Information Gathering tool that returns useful information for an attacker on User, Computer, Groups and Group Policies.

Author: Christoph Falta (@cfalta)
Required Dependencies: PowerView (from the Powersploit Suite)

.DESCRIPTION

Invoke-Profiler offers three different profiles:

-) User -> Queries all user accounts from Active Directory and performs security related checks. (e.g. has delegated admin rights, is service account, password change interval,...)
-) Computer -> Queries all computer accounts from Active Directory and performs security related checks.(e.g. old OS version, is windows or unix system,...)
-) Domain -> Returns a summary of Domain and Domain Controller information as well as the password policy

Run Invoke-Profiler without any arguments to get an overall summary on the domain.

.PARAMETER Profile

Accepts one of the following attack profiles: "User", "Computer", "Domain"

-) User
        -> Queries all user accounts from Active Directory and performs security related checks. (e.g. has delegated admin rights, is service account, password change interval,...)
        -> Return a custom powershell object for further analysis.
-) Computer
        -> Queries all computer accounts from Active Directory and performs security related checks.(e.g. old OS version, is windows or unix system,...)
        -> Return a custom powershell object for further analysis.
-) Domain
        -> Returns a summary of Domain and Domain Controller information as well as the password policy

.PARAMETER OutputDirectory

The directory to save any output (e.g. CSV file) to. Default is the current directory.

.PARAMETER OutCsv

If set, exports all results to CSV files too.

.PARAMETER OutGrid

If set, all results are also displayed in graphical grid views.

.EXAMPLE

Invoke-Profiler

Description
-----------

Without any arguments Invoke-Profiler will run all checks and return a summary. This is the default.

.EXAMPLE

$Users = Invoke-Profiler -Profile User

Description
-----------

Run the "User" profile and store the result (custom psobject) in the variable $Users.

.LINK

https://github.com/cfalta/ADT

#>
    [CmdletBinding()] Param (
        [Parameter(Position = 0, Mandatory=$False)]
        [ValidateSet("User","Computer","Domain")]
        [String]
        $Profile,

        [Parameter(Position = 1, Mandatory=$False)]
        [ValidateNotNullorEmpty()]
        [String]
        $OutputDirectory = (Get-Location),

        [Parameter(Position = 2, Mandatory=$False)]
        [Switch]
        $OutCsv,

        [Parameter(Position = 3, Mandatory=$False)]
        [Switch]
        $OutGrid
    )


#Set default values for variables

$Name_UserProfile = "UserProfile"
$Name_ComputerProfile = "ComputerProfile"
$Name_DCInfo = "DCInfo"
$Name_PWPolicy = "PasswordPolicy"


#Resolve external dependencies

$Dependencies = @("Get-IniContent","Get-GptTmpl","PowerView")

foreach($D in $Dependencies)
{
    $Encoded = Get-ExternalDependency($D)
    [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($Encoded)) | Invoke-Expression
}

#Write a summary with the most important information to stdout
function Write-Summary()
{
    $AllActiveUserAccounts = $UP.Value | ? {$_.isDisabled -eq $False}
    $AllServiceAccounts = $AllActiveUserAccounts | ? {$_.isServiceAccount -eq $True}
    $AllServiceAccountsWithSPN = $AllActiveUserAccounts | ? {($_.isServiceAccount -eq $True) -AND ($_.SPN -ne $False)}
    $DomainAdmins = $AllActiveUserAccounts | ? {$_.isDomainAdmin -eq $true}
    $OtherPrivilegedAccounts = $AllActiveUserAccounts | ? {$_.isPrivilegedUser -eq $true}
    $LocalAdminAccounts = $AllActiveUserAccounts | ? {($_.isLocalAdmin -eq $true) -and ($_.isDomainAdmin -eq $False)}

    $AllActiveComputerAccounts = $CP.Value | ? {($_.isDisabled -eq $False) -AND ($_.isInactive -eq $False)}
    $AllUnsupportedOS = $AllActiveComputerAccounts | ? {$_.isUnsupportedOS -eq $True}
    $AllUnixOS = $AllActiveComputerAccounts | ? {$_.isUnixOS -eq $True}

    Write-Output "##### Domain Summary #####"
    Write-Output ""
    $DC.Value | Format-Table

    Write-Output ""
    Write-Output "##### Password Policy #####"
    Write-Output ""
    $PW.Value | Format-Table

    Write-Output ""
    Write-Output "##### User Summary #####"
    Write-Output ""
    Write-Output ("Active User Accounts: " + ($AllActiveUserAccounts | Measure-Object).count)
    Write-Output ("Domain Admins: " + ($DomainAdmins | Measure-Object).count)
        
    foreach($DA in $DomainAdmins)
    {
        Write-Output ("   " + $DA.samaccountname)
    }

    Write-Output ("Other Privileged User: " + ($OtherPrivilegedAccounts | Measure-Object).count)

    foreach($OU in $OtherPrivilegedAccounts)
    {
        Write-Output ("   " + $OU.samaccountname)
    }

    Write-Output ("User with local Admin rights: " + ($LocalAdminAccounts | Measure-Object).count)

    foreach($LA in ($LocalAdminAccounts | Sort-Object -Property isLocalAdminOnCount -Descending))
    {
        Write-Output ("   " + $LA.samaccountname + ", " + $LA.isLocalAdminOnCount)
    }

    Write-Output ("Service Accounts: " + ($AllServiceAccounts | Measure-Object).count)
    Write-Output ("Service Accounts with SPN: " + ($AllServiceAccountsWithSPN | Measure-Object).count)

    Write-Output ""
    Write-Output "##### Computer Summary #####"
    Write-Output ""
    Write-Output ("Active Computer Accounts: " + ($AllActiveComputerAccounts | Measure-Object).count)
    Write-Output ("Computers with unsupported Windows Version: " + ($AllUnsupportedOS | Measure-Object).count)
    Write-Output ("Domain-joined Unix systems: " + ($AllUnixOS | Measure-Object).count)
}

#This function checks if a given account is a service account by:
# -) comparing name, displayname and samaacountname to a predfined service list
# -) checking if a SPN has been set
function Confirm-ServiceAccount($Account)
{
    $isSvc = $null

    foreach($ServiceName in $ServiceNameList)
            {       
                $CompareString = "*" + $ServiceName + "*"

                if( ($Account.Properties.displayname -like $CompareString) -OR ($Account.Properties.name -like $CompareString) -OR ($Account.Properties.samaccountname -like $CompareString) -OR ($Account.Properties.description -like $CompareString) )
                {
                    $isSvc = "AccountName"
                }
            }

    if(($Account.properties.serviceprincipalname.count) -gt 0)
    {
        if($isSvc)
        {
            $isSvc += '+SPN'
        }
        else
        {
            $isSvc = 'SPN'
        }
    }

    return $isSvc
    
}

#Checks if an account is disabled by parsing the UserAccountControl attribute
function Confirm-AccountDisabled($Account)
{
    $AttributeUAC = ([convert]::ToString($Account.Properties.useraccountcontrol[0],2)).padleft(32,'0')

    if(-NOT $AttributeUAC)
    {
        return "ERROR"
    }


    if(($AttributeUAC.SubString(30,1)) -eq '1')
    {
        return $True
    }
    else
    {
        return $false
    }

}

#Checks if an account is inactive (has not loggon on since one year or more)
function Confirm-AccountInactive($Account)
{
    if($Account.Properties.lastlogontimestamp)
    {
        $Treshold = 366
        $Today = Get-Date
        $LastLogon = [DateTime]::FromFileTime($Account.Properties.lastlogontimestamp[0])
        $TimeDifference = ($Today.Subtract($LastLogon)).Days

        #We expect an account to be inactive if it did not log on for more than 1 year + 1 day (366 days). This is in case a machine is only used for a certain task once every year.

        if($TimeDifference -gt $Treshold)
        {
            return $True
        }
        else
        {
            return $False
        }
        }
    else
    {
        return $False
    }
}

#Checks if an account has the "Password never expires" flag set by parsing the UserAccountControl attribute
function Confirm-PWDNotExpire($Account)
{
    $AttributeUAC = ([convert]::ToString($Account.Properties.useraccountcontrol[0],2)).padleft(32,'0')

    if(-NOT $AttributeUAC)
    {
        return "ERROR"
    }


    if(($AttributeUAC.SubString(15,1)) -eq '1')
    {
        return $True
    }
    else
    {
        return $false
    }

}

#Returns the time when the password last set
function Confirm-PWDLastSet($Account)
{
    if($Account.properties.pwdlastset -gt 0)
    {
        return ([DateTime]::FromFileTime($Account.properties.pwdlastset[0]))
    }
    else
    {
        #If password was never set, last set time = account creation time

        return $Account.properties.whencreated[0]
    }
}

#Checks if the account has never logged on
function Confirm-NoLogin($Account)
{
    if($Account.properties.lastlogontimestamp -gt 0)
    {
        return $false
    }
    else
    {
        return $True
    }
}

#Checks if the account is a member of a privileged group, based on a predefined group list
function Confirm-PrivilegedAccount($Account)
{
    $PrivGroups = $null

    foreach($Group in $Account.Properties.memberof)
    {
        foreach($Item in $PrivilegedGroups)
        {
            $CompareString = ("CN=" + $Item + "*")
            
            if($Group -like $CompareString)
            {
                $PrivGroups += ($Item + ", ")
            }
        }
    }



    return $PrivGroups
}

#Checks if the account is member of the "Domain Admins" group
function Confirm-DomainAdminAccount($Account)
{
    $isDomAdm = $false

    foreach($Group in $Account.Properties.memberof)
    {
        foreach($Item in $DomainAdminGroups)
        {
            $CompareString = ("CN=" + $Item + "*")
            
            if($Group -like $CompareString)
            {
                $isDomAdm = $True
            }
        }
    }

    return $isDomAdm
}

#Tries to identify domain joined unix hosts by matching the "OperatingSystem" attribute against an predefined list
function Add-UnixOSInfo($Accounts)
{
    $UnixSearchStrings = @("unix","linux","mac","apple","redhat","debian","ubuntu","fedora","bsd","centos","solaris")

    foreach($Acc in $Accounts)
    {
        $Acc | Add-Member -MemberType NoteProperty -Name isUnixOS -Value $False

        if($Acc.OS -notlike "*Windows*")
        {
            foreach($SearchString in $UnixSearchStrings)
            {
                $CompareString = "*" + $SearchString + "*"

                if(($Acc.Description -like $CompareString) -OR ($Acc.DN -like $CompareString) -OR ($Acc.CN -like $CompareString))
                {
                    if($Acc.OS)
                    {
                        $TemporaryList = @($Acc.OS)
                        $TemporaryList += $SearchString
                        $Acc.OS = $TemporaryList
                        $Acc.isUnixOS = $True
                    }
                    else
                    {
                        $TemporaryList = @($SearchString)
                        $Acc.OS = $TemporaryList
                        $Acc.isUnixOS = $True
                    }
                }
            }
        }
    }

    return ($Accounts)
}

#Adds a scoring value between 0 and 10 to every account. The higher the score, the higher the impact as well as the change for a successfull attack on the users password
function Add-Score($Accounts)
{
    $Today = Get-Date

    foreach($Acc in $Accounts)
    {
        $Acc | Add-Member -MemberType NoteProperty -Name Score -Value 0

        if($Acc.isDomainAdmin -eq "True")
        {
            $Acc.Score += 5
        }
        else
        {
            if(($Acc.isPrivilegedUser -eq "True")-or($Acc.isLocalAdmin -eq "True"))
            {
                $Acc.Score += 3
            }
        }

        $PasswordLastSet = [Convert]::ToDateTime($Acc.PasswordLastSet)
        $TimeDifference = $Today.Subtract($PasswordLastSet)
        $TimeModifier = 0

        $Acc | Add-Member -MemberType NoteProperty -Name PasswordLastSetDays -Value $TimeDifference.Days

        if($TimeDifference.Days -gt 365){$TimeModifier = 1}
        if($TimeDifference.Days -gt 1095){$TimeModifier = 2}
        if($TimeDifference.Days -gt 1825){$TimeModifier = 3}
        if($TimeDifference.Days -gt 3650){$TimeModifier = 5}

        $Acc.Score += $TimeModifier

        if(($Acc.PasswordNeverExpires -eq "True")-and($TimeModifier -eq 0))
        {
            $Acc.Score += 1
        }

    }

    return ($Accounts)
}

#Sets a flag to indicate that the operating system is unsupported based on the official microsoft product lifecycle
function Add-UnsupportedOSInfo($Accounts)
{
    #Support lifecycle based on https://support.microsoft.com/en-us/help/13853/windows-lifecycle-fact-sheet
    #OS Version list based on https://msdn.microsoft.com/en-us/library/windows/desktop/ms724832(v=vs.85).aspx

    $MajorVersionIndicator = 6.0 #Windows Vista/Server 2008

    foreach($Acc in $Accounts)
    {
        if($Acc.OSVersion)
        {
            try
            {
                $MajorVersion = [System.Convert]::ToDouble(($Acc.OSVersion.substring(0,($Acc.OSVersion.IndexOf(".")+2))).Replace(".",","))
                if($MajorVersion -lt $MajorVersionIndicator)
                {
                    $Acc | Add-Member -MemberType NoteProperty -Name isUnsupportedOS -Value $True
                }
                else
                {   
                    $Acc | Add-Member -MemberType NoteProperty -Name isUnsupportedOS -Value $False
                }
            }
            catch
            {
                $Acc | Add-Member -MemberType NoteProperty -Name isUnsupportedOS -Value $False
            }
        }
        else
        {   
            $Acc | Add-Member -MemberType NoteProperty -Name isUnsupportedOS -Value $False
        }
    }

    return ($Accounts)
}

#Parses all group policies to find delagtions of local admin rights and aggregates that with a list of computers in the domain. Adds an attribute to every user that contains a list of computer, where this user has local admin rights.
function Add-LocalAdminDelegateInfo($Accounts)
{
    $GPOList = Find-GPOLocation -Verbose:$False
   
    $UserToMachineMapping = @()
    
    #Creates a new object that merges all user/group to machine mappings in a single list
    foreach($GPO in $GPOList)
    {
        $CreateNew = $True
        
        foreach($Entry in $UserToMachineMapping)
        {
            if($Entry.OriginalDelegate -eq $GPO.ObjectName)
            {
                $Entry.Computer += $GPO.ComputerName
                $CreateNew = $False
            }
        }

        if($CreateNew)
        {
                $SingleMapping = New-Object -TypeName PSObject
                $SingleMapping | Add-Member -MemberType NoteProperty -Name OriginalDelegate -Value $GPO.ObjectName
                
                if($GPO.IsGroup)
                {
                    $SingleMapping | Add-Member -MemberType NoteProperty -Name OriginalDelegateIsGroup -Value $True
                }
                else
                {
                    $SingleMapping | Add-Member -MemberType NoteProperty -Name OriginalDelegateIsGroup -Value $False
                }

                
                $SingleMapping | Add-Member -MemberType NoteProperty -Name Computer -Value $GPO.ComputerName


                $UserToMachineMapping += $SingleMapping
        }

    }

    #Iterate through this new list and resolve groups to users
    foreach($Entry in $UserToMachineMapping)
    {
        if(-NOT $Entry.OriginalDelegateIsGroup)
        {
            $Entry | Add-Member -MemberType NoteProperty -Name OriginalDelegateMember -Value $Entry.OriginalDelegate
        }
        else
        {
            $GroupMember = Get-NetGroupMember -GroupName $Entry.OriginalDelegate -Recurse -Verbose:$False
            $GroupMember = $GroupMember | ? {$_.IsGroup -eq $False}
            $MemberList = @()
            $GroupMember | % { $MemberList += $_.MemberName }
            $Entry | Add-Member -MemberType NoteProperty -Name OriginalDelegateMember -Value $MemberList
        }
        
    }

    #Iterate through the overall account list and match every user account with the corresponding computers on which he/she has local admin rights

    foreach($Acc in $Accounts)
    {
        $Acc | Add-Member -MemberType NoteProperty -Name isLocalAdmin -Value $False
        $Acc | Add-Member -MemberType NoteProperty -Name isLocalAdminOn -Value $False
        $Acc | Add-Member -MemberType NoteProperty -Name isLocalAdminThroughGroup -Value $False

        foreach($Entry in $UserToMachineMapping)
        {
            if(($Entry.OriginalDelegateMember | ? {$_ -eq $Acc.SAMAccountName}))
            {
                if($Acc.isLocalAdmin)
                {
                    $Acc.isLocalAdminOn += $Entry.Computer
                }
                else
                {
                    $Acc.isLocalAdmin = $True
                    $TemporaryList = @()
                    $TemporaryList += $Entry.OriginalDelegate
                    $Acc.isLocalAdminThroughGroup = $TemporaryList
                    $TemporaryList = @()
                    $TemporaryList += $Entry.Computer
                    $Acc.isLocalAdminOn = $TemporaryList
                }
            }
        }

        if($Acc.isLocalAdminOn)
        {
            $Acc | Add-Member -MemberType NoteProperty -Name isLocalAdminOnCount -Value $Acc.isLocalAdminOn.count
        }
        else
        {
            $Acc | Add-Member -MemberType NoteProperty -Name isLocalAdminOnCount -Value $False
        }


    }

    return ($Accounts)
}


#This is the main profiling function for the "User" profile
function Invoke-UserProfiler()
{

$ResultList = @()

#This is a self-compiled list of typical strings
$ServiceNameList = @("svc","service","scv","exchange","sharepoint","sql","backup","bes","task","job","schedule","scom","sccm","scvmm","vmm","rms","cron","moss","web","ftp","copy")

#From https://technet.microsoft.com/en-us/windows-server-docs/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory
$PrivilegedGroups = @("Access Control Assistance Operators","Account Operators","Backup Operators","Cert Publishers","Certificate Service DCOM Access","Cryptographic Operators","DHCP Administrators","DHCP Users","Distributed COM Users","DnsAdmins","Enterprise Admins","Event Log Readers","Group Policy Creator Owners","Hyper-V Administrators","Network Configuration Operators","Performance Log Users","Performance Monitor Users","Print Operators","Remote Desktop Services Users","Schema Admins","Server Operators","Windows Authorization Access Group","WinRMRemoteWMIUsers_")

#Domain Admin or Domain Admin equivalent
$DomainAdminGroups = @("Domain Admins","Administrators","Domänen-Admins","Administratoren")

#Get all user objects from AD
$ADSearcher = New-Object -TypeName System.DirectoryServices.DirectorySearcher -ArgumentList [ADSI]
$ADSearcher.Filter = "(&(objectClass=user)(objectCategory=person))"
$ADObjects = $ADSearcher.Findall()

#Gather general user information


foreach($Obj in $ADObjects)
{
    $ResultItem = New-Object -TypeName PSObject
    
    if($Obj.Properties.displayname)
    {
        $ResultItem | Add-Member -MemberType NoteProperty -Name Username -Value $Obj.Properties.displayname[0]   
    }
    else
    {
        $ResultItem | Add-Member -MemberType NoteProperty -Name Username -Value "False"
    }
    
    
    $ResultItem | Add-Member -MemberType NoteProperty -Name SAMAccountName -Value $Obj.Properties.samaccountname[0]

    if($Obj.Properties.description){ $ResultItem | Add-Member -MemberType NoteProperty -Name Description -Value $Obj.Properties.description[0] }else{ $ResultItem | Add-Member -MemberType NoteProperty -Name Description -Value $False}

    $ResultItem | Add-Member -MemberType NoteProperty -Name PasswordNeverExpires -Value (Confirm-PWDNotExpire($Obj)).ToString()
    $ResultItem | Add-Member -MemberType NoteProperty -Name PasswordLastSet -Value (Confirm-PWDLastSet($Obj)).ToString()
    $ResultItem | Add-Member -MemberType NoteProperty -Name UserNeverLoggedIn -Value (Confirm-NoLogin($Obj)).ToString()
    $ResultItem | Add-Member -MemberType NoteProperty -Name isDomainAdmin -Value (Confirm-DomainAdminAccount($Obj)).ToString()
    $ResultItem | Add-Member -MemberType NoteProperty -Name isDisabled -Value (Confirm-AccountDisabled($Obj)).ToString()


    $isSVCAccount = Confirm-ServiceAccount($Obj)

    if($isSVCAccount)
    {
        $ResultItem | Add-Member -MemberType NoteProperty -Name isServiceAccount -Value "True"
        $ResultItem | Add-Member -MemberType NoteProperty -Name ServiceAccountVerifiedBy -Value $isSVCAccount
        
        if($Obj.Properties.serviceprincipalname)
        {
            $ResultItem | Add-Member -MemberType NoteProperty -Name SPN -Value $Obj.Properties.serviceprincipalname[0]
        }
        else
        {
            $ResultItem | Add-Member -MemberType NoteProperty -Name SPN -Value "False"
        }
    }
    else
    {
        $ResultItem | Add-Member -MemberType NoteProperty -Name isServiceAccount -Value "False"
        $ResultItem | Add-Member -MemberType NoteProperty -Name ServiceAccountVerifiedBy -Value "False"
        $ResultItem | Add-Member -MemberType NoteProperty -Name SPN -Value "False"
    }


    $isPrivUser = Confirm-PrivilegedAccount($Obj)

    if((-NOT $isPrivUser) -OR ($ResultItem.isDomainAdmin -eq $True))
    {
        $ResultItem | Add-Member -MemberType NoteProperty -Name isPrivilegedUser -Value "False"
        $ResultItem | Add-Member -MemberType NoteProperty -Name PrivilegedGroups -Value "False"
    }
    else
    {
        $ResultItem | Add-Member -MemberType NoteProperty -Name isPrivilegedUser -Value "True"
        $ResultItem | Add-Member -MemberType NoteProperty -Name PrivilegedGroups -Value $isPrivUser.Substring(0,($isPrivUser.Length - 2))
    }
    
    $ResultList += $ResultItem
}


#Add per account information regarding local admin rights

$ResultList = Add-LocalAdminDelegateInfo($ResultList)

#Add scoring

$ResultList = Add-Score($ResultList)

return($ResultList)

}

#This is the main profiling function for the "Computer" profile
function Invoke-ComputerProfiler()
{

$ResultList = @()

#Get all computer objects from AD
#$ADSearcher = New-Object DirectoryServices.DirectorySearcher([ADSI]"")
$ADSearcher = New-Object -TypeName System.DirectoryServices.DirectorySearcher -ArgumentList [ADSI]
$ADSearcher.Filter = "(&(objectClass=computer))"
$ADObjects = $ADSearcher.Findall()

foreach($Obj in $ADObjects)
{
    $ResultItem = New-Object -TypeName PSObject

    $ResultItem | Add-Member -MemberType NoteProperty -Name CN -Value $Obj.Properties.cn[0]
    $ResultItem | Add-Member -MemberType NoteProperty -Name DN -Value $Obj.Properties.distinguishedname[0]
    
    if($Obj.Properties.dnshostname){ $ResultItem | Add-Member -MemberType NoteProperty -Name DNSName -Value $Obj.Properties.dnshostname[0] }else{ $ResultItem | Add-Member -MemberType NoteProperty -Name DNSName -Value $False}
    if($Obj.Properties.description){ $ResultItem | Add-Member -MemberType NoteProperty -Name Description -Value $Obj.Properties.description[0] }else{ $ResultItem | Add-Member -MemberType NoteProperty -Name Description -Value $False}
    
    if($Obj.Properties.operatingsystem){ $ResultItem | Add-Member -MemberType NoteProperty -Name OS -Value $Obj.Properties.operatingsystem[0] }else{ $ResultItem | Add-Member -MemberType NoteProperty -Name OS -Value $False}
    if($Obj.Properties.operatingsystemversion){ $ResultItem | Add-Member -MemberType NoteProperty -Name OSVersion -Value $Obj.Properties.operatingsystemversion[0] }else{ $ResultItem | Add-Member -MemberType NoteProperty -Name OSVersion -Value $False}
    if($Obj.Properties.operatingsystemservicepack){ $ResultItem | Add-Member -MemberType NoteProperty -Name ServicePack -Value $Obj.Properties.operatingsystemservicepack[0] }else{ $ResultItem | Add-Member -MemberType NoteProperty -Name ServicePack -Value $False}
 
    $ResultItem | Add-Member -MemberType NoteProperty -Name isDisabled -Value (Confirm-AccountDisabled($Obj)).ToString()
    $ResultItem | Add-Member -MemberType NoteProperty -Name isInactive -Value (Confirm-AccountInactive($Obj)).ToString()

    if($Obj.Properties.memberof){$ResultItem | Add-Member -MemberType NoteProperty -Name Groups -Value $Obj.Properties.memberof }else{ $ResultItem | Add-Member -MemberType NoteProperty -Name Groups -Value $False}
    if($Obj.Properties.serviceprincipalname){$ResultItem | Add-Member -MemberType NoteProperty -Name SPN -Value $Obj.Properties.serviceprincipalname }else{ $ResultItem | Add-Member -MemberType NoteProperty -Name SPN -Value $False}

    $ResultList += $ResultItem
}

$ResultList = Add-UnsupportedOSInfo($ResultList)
$ResultList = Add-UnixOSInfo($ResultList)

return($ResultList)

}


#This function extracts general information on all domain controllers and returns a custom psobject
function Get-DCInfo()
{
    $ResultList = @()
    $Forests = Get-NetForest

    foreach($Forest in $Forests)
    {
        foreach($Domain in $Forest.Domains)
        {
            foreach($DC in $Domain.DomainControllers)
            {
                $ResultItem = New-Object -TypeName PSObject
                $ResultItem | Add-Member -MemberType NoteProperty -Name Name -Value $DC.Name
                $ResultItem | Add-Member -MemberType NoteProperty -Name IP -Value $DC.IPAddress
                $ResultItem | Add-Member -MemberType NoteProperty -Name OSVersion -Value $DC.OSVersion
                $ResultItem | Add-Member -MemberType NoteProperty -Name Domain -Value $DC.Domain
                $ResultItem | Add-Member -MemberType NoteProperty -Name Forest -Value $Forest.Name
                $ResultItem | Add-Member -MemberType NoteProperty -Name DomainMode -Value $Domain.DomainMode
                $ResultItem | Add-Member -MemberType NoteProperty -Name ForestMode -Value $Forest.ForestMode

                $ResultList += $ResultItem
            }
        }
    }

    return($ResultList)
}

#This function extracts password policy information from the default domain policy and returns a custom psobject
function Get-PasswordPolicy()
{
    $ResultList = @()
    $GPO = Get-NetGPO -Verbose:$False
    $DefaultDomainPolicy = $GPO | ? {$_.name -eq "{31B2F340-016D-11D2-945F-00C04FB984F9}"}
    $DefaultDomainPolicyIni = Get-GptTmpl -GptTmplPath ($DefaultDomainPolicy.gpcfilesyspath + "\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf") -Verbose:$False

    $ResultItem = New-Object -TypeName PSObject

    $ResultItem | Add-Member -MemberType NoteProperty -Name MinimumPasswordLength -Value $DefaultDomainPolicyIni.'System Access'.MinimumPasswordLength
    $ResultItem | Add-Member -MemberType NoteProperty -Name PasswordComplexity -Value $DefaultDomainPolicyIni.'System Access'.PasswordComplexity
    $ResultItem | Add-Member -MemberType NoteProperty -Name PasswordHistorySize -Value $DefaultDomainPolicyIni.'System Access'.PasswordHistorySize
    $ResultItem | Add-Member -MemberType NoteProperty -Name MaximumPasswordAge -Value $DefaultDomainPolicyIni.'System Access'.MaximumPasswordAge
    $ResultItem | Add-Member -MemberType NoteProperty -Name LockoutBadCount -Value $DefaultDomainPolicyIni.'System Access'.LockoutBadCount
    $ResultItem | Add-Member -MemberType NoteProperty -Name LockoutDuration -Value $DefaultDomainPolicyIni.'System Access'.LockoutDuration

    $ResultList += $ResultItem

    return($ResultList)
}

#This functions runs all profiles and returns a summary
function Invoke-SummaryProfiler
{
    $ProfileResults = @()

    $UP = New-Object -TypeName PSObject
    $UP | Add-Member -MemberType NoteProperty -Name Name -Value $Name_UserProfile
    $UP | Add-Member -MemberType NoteProperty -Name Value -Value (Invoke-UserProfiler)
    $ProfileResults += $UP
    
    $CP = New-Object -TypeName PSObject
    $CP | Add-Member -MemberType NoteProperty -Name Name -Value $Name_ComputerProfile
    $CP | Add-Member -MemberType NoteProperty -Name Value -Value (Invoke-ComputerProfiler)
    $ProfileResults += $CP

    $DC = New-Object -TypeName PSObject
    $DC | Add-Member -MemberType NoteProperty -Name Name -Value $Name_DCInfo
    $DC | Add-Member -MemberType NoteProperty -Name Value -Value (Get-DCInfo)
    $ProfileResults += $DC

    $PW = New-Object -TypeName PSObject
    $PW | Add-Member -MemberType NoteProperty -Name Name -Value $Name_PWPolicy
    $PW | Add-Member -MemberType NoteProperty -Name Value -Value (Get-PasswordPolicy)
    $ProfileResults += $PW

    Write-FancyHeader
    Write-Summary

}


#The main processing loop starts here

#Regardless of user input, this array will hold all results so output generation can be centrally controlled
$ProfileResults = @()

Write-Verbose "Retrieving information from Active Directory. Be patient, this can take some time in large environments!"

#Proceed according to user input
switch($Profile)
{    
    User{
    
    $ProfileObject = New-Object -TypeName PSObject
    $ProfileObject | Add-Member -MemberType NoteProperty -Name Name -Value $Name_UserProfile
    $ProfileObject | Add-Member -MemberType NoteProperty -Name Value -Value (Invoke-UserProfiler)
    $ProfileResults += $ProfileObject
    $ProfileObject.Value

    }
    Computer{
    
    $ProfileObject = New-Object -TypeName PSObject
    $ProfileObject | Add-Member -MemberType NoteProperty -Name Name -Value $Name_ComputerProfile
    $ProfileObject | Add-Member -MemberType NoteProperty -Name Value -Value (Invoke-ComputerProfiler)
    $ProfileResults += $ProfileObject
    $ProfileObject.Value

    }

    Domain{
    
    $ProfileObject = New-Object -TypeName PSObject
    $ProfileObject | Add-Member -MemberType NoteProperty -Name Name -Value $Name_DCInfo
    $ProfileObject | Add-Member -MemberType NoteProperty -Name Value -Value (Get-DCInfo)
    $ProfileResults += $ProfileObject
    $ProfileObject.Value | Format-Table

    $ProfileObject = New-Object -TypeName PSObject
    $ProfileObject | Add-Member -MemberType NoteProperty -Name Name -Value $Name_PWPolicy
    $ProfileObject | Add-Member -MemberType NoteProperty -Name Value -Value (Get-PasswordPolicy)
    $ProfileResults += $ProfileObject
    $ProfileObject.Value | Format-Table

    }

    default{
    
    $ProfileResults = @()

    $UP = New-Object -TypeName PSObject
    $UP | Add-Member -MemberType NoteProperty -Name Name -Value $Name_UserProfile
    $UP | Add-Member -MemberType NoteProperty -Name Value -Value (Invoke-UserProfiler)
    $ProfileResults += $UP
    
    $CP = New-Object -TypeName PSObject
    $CP | Add-Member -MemberType NoteProperty -Name Name -Value $Name_ComputerProfile
    $CP | Add-Member -MemberType NoteProperty -Name Value -Value (Invoke-ComputerProfiler)
    $ProfileResults += $CP

    $DC = New-Object -TypeName PSObject
    $DC | Add-Member -MemberType NoteProperty -Name Name -Value $Name_DCInfo
    $DC | Add-Member -MemberType NoteProperty -Name Value -Value (Get-DCInfo)
    $ProfileResults += $DC

    $PW = New-Object -TypeName PSObject
    $PW | Add-Member -MemberType NoteProperty -Name Name -Value $Name_PWPolicy
    $PW | Add-Member -MemberType NoteProperty -Name Value -Value (Get-PasswordPolicy)
    $ProfileResults += $PW

    Write-FancyHeader
    Write-Summary    
    
    }
}

#Output Generation
foreach($P in $ProfileResults)
{
    #If set, create CSV files for every profile in the pipe
    if($OutCsv)
    {
        $P.Value | Export-Csv -Path (Join-Path $OutputDirectory ($P.Name + ".csv"))
    }

    #If set, create grid views for every profile in the pipe
    if($OutGrid)
    {
        $P.Value | Out-GridView -Title $P.Name
    }

}

}

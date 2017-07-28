# Copied from http://www.indented.co.uk/2009/10/02/get-dsacl/
# Only included minor modifications

function Get-DsAcl {
  # .SYNOPSIS
  #   Get directory service access control lists from Active Directory.
  # .DESCRIPTION
  #   Get-DsAcl uses ADSI to retrieve the security descriptor from an account. Descriptions of extended attributes are read from the Schema.

  param(
    [String]$SearchRoot = ([ADSI]"LDAP://RootDSE").Get("defaultNamingContext"),
    
    [String]$ObjectType = "organizationalUnit",

    [String]$LdapFilter = "(&(objectClass=$ObjectType)(objectCategory=$ObjectType))",

    [Switch]$Inherited = $False
  )
 
  # Connect to RootDSE
  $RootDSE = [ADSI]"LDAP://RootDSE"
  # Connect to the Schema
  $Schema = [ADSI]"LDAP://$($RootDSE.Get('schemaNamingContext'))"
  # Connect to the Extended Rights container
  $ExtendedRights = [ADSI]"LDAP://CN=Extended-Rights,$($RootDSE.Get('configurationNamingContext'))"
 
  # Find objects based on $SearchRoot and $ObjectType
  $Searcher = New-Object DirectoryServices.DirectorySearcher([ADSI]"LDAP://$SearchRoot", $LdapFilter)
 
  $Searcher.FindAll() | ForEach-Object {
    $Object = $_.GetDirectoryEntry()
 
    # Retrieve all Access Control Entries from the AD Object
    $ACL = $Object.PsBase.ObjectSecurity.GetAccessRules(
      $true,
      $Inherited,
      [Security.Principal.NTAccount]
    )
 
    # Get interesting values
    $ACL | Select-Object @{n='Name';e={ $Object.Get("name") }},
      @{n='DN';e={ $Object.Get("distinguishedName") }},
      @{n='samAccountName';e={ $Object.Get("samAccountName") }},
      @{n='ObjectClass';e={ $Object.Class }},
      @{n='SecurityPrincipal';e={ $_.IdentityReference.ToString() }},
      @{n='AccessType';e={ $_.AccessControlType }},
      @{n='Permissions';e={ $_.ActiveDirectoryRights }},
      @{n='AppliesTo';e={ 
        #
        # Change the values for InheritanceType to friendly names
        #
        switch ($_.InheritanceType) {
          "None"            { "This object only" }
          "Descendents"     { "All child objects" }
          "SelfAndChildren" { "This object and one level Of child objects" }
          "Children"        { "One level of child objects" }
          "All"             { "This object and all child objects" }
        } }}, `
      @{n='AppliesToObjectType';e={ 
        if ($_.InheritedObjectType.ToString() -notmatch "0{8}.*") {
          #
          # Search for the Object Type in the Schema
          #
          $LdapFilter = "(SchemaIDGUID=$(($_.InheritedObjectType.ToByteArray() |
            ForEach-Object { '{0:X2}' -f $_ }) -join '')"
          $Result = (New-Object DirectoryServices.DirectorySearcher(
            $Schema, $LdapFilter)).FindOne()
          $Result.Properties["ldapdisplayname"]
        } else { 
          "All"
        }
      }},
      @{n='AppliesToProperty';e={
        if($_.ObjectType.ToString() -notmatch "0{8}.*") {
          #
          # Search for a possible Extended-Right or Property Set
          #
          $LdapFilter = "(rightsGuid=$($_.ObjectType.ToString()))"
          $Result = (New-Object DirectoryServices.DirectorySearcher(
            $ExtendedRights, $LdapFilter)).FindOne()
          if ($Result) {
            $Result.Properties["displayname"]
          } else {
            #
            # Search for the attribute name in the Schema
            #
            $LdapFilter = "(SchemaIDGUID=$(($_.ObjectType.ToByteArray() |
              ForEach-Object { '{0:X2}' -f $_ }) -join ''))"
            $Result = (New-Object DirectoryServices.DirectorySearcher(
              $Schema, $LdapFilter)).FindOne()
            $Result.Properties["ldapdisplayname"]
          }
        } else {"All"}
      }},
      @{n='Inherited';e={ $_.IsInherited }}
  }
}

function Invoke-ADACLQuery
{
<#
.SYNOPSIS

This function uses Get-DsAcl to retrieve all ACE's from all ACL's on all computer, user and OU objects in the current Active Directory Domain. Then it runs an analysis based on the chosen query.

The results can be used to escalate privileges or facilitate attacks by taking advantage of permission issues.

Author: Christoph Falta (@cfalta)
Required Dependencies: Get-DSACL

.DESCRIPTION

This function uses Get-DsAcl to retrieve all ACE's from all ACL's on all computer, user and OU objects in the current Active Directory Domain. Then it runs an analysis based on the chosen query.

The results can be used to escalate privileges or facilitate attacks by taking advantage of permission issues.

.PARAMETER Query

The query you want to run. At the moment, the following queries are supported:

1) WhereCanIWrite: show all ACE's that allow the current user or a group the user is in to write (or similar) on an AD object

2) WhereCanThatGuyWrite: show all ACE's that allow a specified user or a group the user is in to write (or similar) on an AD object

3) ShowMeAllDelegatedToUsersDirectly: show all ACE's that give permissions to a user account directly instead of a group (useful for audit purposes)

.PARAMETER ThatGuy

The user account to query for. Used in conjunction with the "WhereCanThatGuyWrite" query.

.PARAMETER Path

The path that will be used by the "FromCSV" and "QueryOnly" switches. Default value is ".\ADACLQueryInfo.csv"

.PARAMETER FromCSV

Read the ACE's from a previously stored CSV file instead of retrieving them from AD. (== offline mode)

.PARAMETER QueryOnly

Just querys all ACE's and stores them into a CSV file for later use. This is also useful if you want to run multiple queries so you don't have to access the DC everytime.

.PARAMETER OutGrid

If set, all results are also displayed in graphical grid views.

.PARAMETER IncludeChangePassword

Included the "Change Password" right in the output. These ACE's are removed by default because in Active Directory, the "Everyone" group has the "Change Password" right on all user objects.
This is to allow a user with an expired password to change the password without authenticating first. (see https://support.microsoft.com/de-de/help/242795/granting-change-password-permissions-to-the-everyone-group)

.EXAMPLE

Invoke-ADACLQuery -Query WhereCanIWrite -OutGrid

Description
-----------

Shows all ACE's that allow the current user write (or similar) access on AD objects. The results will be display also as grid view.

.EXAMPLE

Invoke-ADACLQuery -Query WhereCanThatGuyWrite -ThatGuy jsmith -OutGrid

Description
-----------

Shows all ACE's that allow the the user "jsmith" write (or similar) access on AD objects. The results will be display also as grid view.

.EXAMPLE

Invoke-ADACLQuery -Query ShowMeAllDelegatedToUsersDirectly -OutGrid

Description
-----------

Show all ACE's that give permissions to a user account directly instead of a group (useful for audit purposes). The results will be display also as grid view.

.LINK

https://github.com/cfalta/

#>
    [CmdletBinding()] Param (
        [Parameter(Position = 0, Mandatory=$False)]
        [ValidateSet("WhereCanIWrite","WhereCanThatGuyWrite","ShowMeAllDelegatedToUsersDirectly")]
        [String]
        $Query,

        [Parameter(Position = 1, Mandatory=$False)]
        [ValidateNotNullorEmpty()]
        [String]
        $ThatGuy,

        [Parameter(Position = 2, Mandatory=$False)]
        [ValidateNotNullorEmpty()]
        [String]
        $Path = ".\ADACLQueryInfo.csv",

        [Parameter(Position = 3, Mandatory=$False)]
        [Switch]
        $FromCSV,

        [Parameter(Position = 4, Mandatory=$False)]
        [Switch]
        $QueryOnly,

        [Parameter(Position = 5, Mandatory=$False)]
        [Switch]
        $OutGrid,

        [Parameter(Position = 6, Mandatory=$False)]
        [Switch]
        $IncludeChangePassword
    )

$CurrentDomain = $env:USERDOMAIN

$ACLObjects = @()
$MatchingSet = @()
$ResultSet = @()
$WriteOnly = $False
$DoNotRun = $False


if($QueryOnly)
{
    $DoNotRun = $true

    $ACLObjects += (Get-DsAcl -ObjectType User)
    $ACLObjects += (Get-DsAcl -ObjectType Computer)
    $ACLObjects += (Get-DsAcl -ObjectType organizationalUnit)

    $ACLObjects | ConvertTo-Csv | Out-File $Path
}

if(-not $DoNotRun)
{

if($FromCSV)
{
    $ACLObjects = Get-Content $Path | ConvertFrom-Csv
}
else
{
    $ACLObjects += (Get-DsAcl -ObjectType User)
    $ACLObjects += (Get-DsAcl -ObjectType Computer)
    $ACLObjects += (Get-DsAcl -ObjectType organizationalUnit)
}

switch ($Query)
{
    WhereCanIWrite
    {
        $CurrentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
        $CurrentGroups = $CurrentUser.Groups | % { $_.Translate([Security.Principal.NTAccount]) }

        $CurrentGroups | % { $MatchingSet += $_.tostring() }

        $MatchingSet += $CurrentUser.Name

        $WriteOnly = $true

    }
    ShowMeAllDelegatedToUsersDirectly
    {
        $UserList = ($ACLObjects | ? { $_.ObjectClass -eq "user"} | select-object samaccountname | sort-object samaccountname -unique)

        $UserList | % {$MatchingSet += ($CurrentDomain + "\" + $_.samAccountName)}

        $WriteOnly = $true

    }
    WhereCanThatGuyWrite
    {
        try
        {
            $CurrentUser = [Security.Principal.WindowsIdentity]($ThatGuy)

            $CurrentGroups = $CurrentUser.Groups | % { $_.Translate([Security.Principal.NTAccount]) }

            $CurrentGroups | % { $MatchingSet += $_.tostring() }

            $MatchingSet += $CurrentUser.Name

            $WriteOnly = $true
        }
        catch
        {
            Write-Warning "Error querying user $Thatguy. This propably means that the account is disabled"
            $DoNotRun = $True
        }

    }
}

    if(-not $DoNotRun)
    {
        
        $ACLObjects = $ACLObjects | ? {$_.AccessType -eq "Allow"}

        if(-Not $IncludeChangePassword)
        {
            $ACLObjects = $ACLObjects | ? {$_.AppliesToProperty -ne "Change Password"}
        }

        foreach ($ACL in $ACLObjects)
        {
            foreach ($M in $MatchingSet)
            {
                if($ACL.SecurityPrincipal -eq $M)
                {
                    $ResultSet += $ACL   
                }
            }
        }

        if($WriteOnly)
        {

        $Writeable = @()
        $WriteTypePermissions = @("AccessSystemSecurity","CreateChild","Delete","DeleteChild","DeleteTree","ExtendedRight","GenericAll","GenericWrite","Self","Synchronize","WriteDacl","WriteOwner","WriteProperty")

        #Remove all "read-type" permissions based on https://msdn.microsoft.com/en-us/library/system.directoryservices.activedirectoryrights(v=vs.110).aspx
        foreach ($R in $ResultSet)
        {
            foreach($W in $WriteTypePermissions)
            {
                if($R.Permissions -like ("*" + $W + "*"))
                {
                    $Writeable += $R
                }
            }
        }

        $ResultSet = $Writeable

        }


        if($OutGrid)
        {
            $ResultSet | Out-GridView
        }

        $ResultSet | Write-Output
    }
}

}
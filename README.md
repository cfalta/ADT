## ADT - Active Directory Toolkit

ADT is a set of Powershell scripts that should simplify the work of Penetration Testers or Auditors, in terms of assessing Active Directory Security. 

There are already a lot of different frameworks out there and I don't want to create another one. The idea of ADT is to fill the gap between what's already available and what might be a useful tool. Comments, ideas and opinions are very welcome.

At the moment, the functionality is divided in 6 scripts, which are briefly described below. See the help section of each Powershell function for more details.

### Invoke-Profiler
Invoke-Profiler is an Information Gathering tool that returns useful information for an attacker on User, Computer, Groups and Group Policies. It automatically creates a kind of "management summary" on all information if no parameters are supplied. If a specific profile was chosen (e.g. User), all data is returned as custom powershell objects so it can be reused. CSV and GridView export is also included.

### Invoke-CredentialHunter
Invoke-CredentialHunter is a "Point-and-Shoot" wrapper function to simplify Pass-the-Hash attacks. Just point it at a target with a valid username/hash and it returns a nicely formated list of credentials. The script remotely iniates a process dump of the LSASS process and transfers the dump file via a covert WMI channel to prevent detection. On the target, everything is done using PowerShell and native Windows API to prevent AV detection. Mimikatz is only used locally. The script handles mimikatz invocation, credential dumping, parsing and everything else automatically. 

### Invoke-AutoPilot
Invoke-AutoPilot allows the user to choose an attack scenario like "I want to dump domain admin credentials" or the widely used "I dont care, just give me all credentials you can find" and automates it's execution via local Admin pass-the-hash. The script automatically detects targets, initiates the attack and when finished, displays a list of credentials.

### Invoke-ServiceHunter
Identifies all kerberos-enabled Service Accounts in the domain using "Invoke-Profiler". Then it requests tickets for each account, exports them using mimikatz and automatically converts them into text-files, which can be cracked with hashcat. By default, the TOP 5 targets will be automatically retrieved based on permissions, last password change and so on.

### New-EncryptedScriptLoader
Point this function at a powershell library of your choice and it creates a single, encrypted, self-decrypting script-loader. This simplifies handling of tools like Powersploit or ADT itself since you dont have to carry a lot of separate files with you, but just a single, encrypted script. In addition, since everything is encrypted, you can easily evade Anti-Virus. Decryption is only done in memory so a typical file based AV will not detect it. AMSI bypass is included too.

### Get-HelperFunctions
This script just contains a bunch of helper functions for the other scripts.
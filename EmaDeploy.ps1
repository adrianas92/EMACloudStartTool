# Intel(R) EMA deployment utility
# Authors: Grant Kelly
#          Rafael Escalante
###################################################################################################
#
# Copyright 2021 Intel Corporation.
#
# This software and the related documents are Intel copyrighted materials, and your use of them is
# governed by the express license under which they were provided to you ("License"). Unless the
# License provides otherwise, you may not use, modify, copy, publish, distribute, disclose or
# transmit this software or the related documents without Intel's prior written permission.
#
# This software and the related documents are provided as is, with no express or implied warranties,
# other than those that are expressly stated in the License.
#
###################################################################################################
#Requires -Version 5
param (
 [Parameter(Mandatory = $false, Position=0)]
 [string]$action, 
 [Parameter(Mandatory = $false, Position=1)]
 [string]$helpparam, 
 [Parameter(Mandatory = $false, Position=2)]
 [string]$fqdn, 
 [Parameter(Mandatory = $false, Position=3)]
 [string]$dbserver, 
 [Parameter(Mandatory = $false, Position=4)]
 [string]$dbuser,
 [Parameter(Mandatory = $false, Position=5)]
 [string]$dbpassword,
 [Parameter(Mandatory = $false, Position=6)]
 [string]$tausername,
 [Parameter(Mandatory = $false, Position=7)]
 [string]$tapassword,
 [Parameter(Mandatory = $false, Position=8)]
 [string]$gausername,
 [Parameter(Mandatory = $false, Position=9)]
 [string]$gapassword,
 [Parameter(Mandatory = $false, Position=10)]
 [string]$pkgdir,
 [Parameter(Mandatory = $false, Position=11)]
 [string]$tenantname,
 [Parameter(Mandatory = $false, Position=12)]
 [string]$profilename,
 [Parameter(Mandatory = $false, Position=13)]
 [string]$epgname,
 [Parameter(Mandatory = $false, Position=14)]
 [string]$epgpassword,
 [Parameter(Mandatory = $false, Position=15)]
 [string]$certpath,
 [Parameter(Mandatory = $false, Position=16)]
 [string]$certpass,
 [Parameter(Mandatory = $false, Position=17)]
 [string]$certname,
 [Parameter(Mandatory = $false, Position=18)]
 [string]$autopass,
 [Parameter(Mandatory = $false, Position=19)]
 [switch]$noverify,
 [Parameter(Mandatory = $false, Position=20)]
 [switch]$ad,
 [Parameter(Mandatory = $false, Position=21)]
 [switch]$na,
 [Parameter(Mandatory = $false, Position=22)]
 [switch]$hidden,
 [Parameter(Mandatory = $false, Position=23)]
 [switch]$nologging,
 [Parameter(Mandatory = $false, Position=24)]
 [string]$logfile,
 [Parameter(Mandatory = $false, Position=25)]
 [string]$enckey,
 [Parameter(Mandatory = $false, Position=26)]
 [switch]$noemainstall,
 [Parameter(Mandatory = $false, Position=27)]
 [switch]$defaults,
 [Parameter(Mandatory = $false, Position=28)]
 [switch]$currentdir,
 [Parameter(Mandatory = $false, Position=29)]
 [switch]$nocert,
 [Parameter(Mandatory = $false, Position=30)]
 [string]$taskuser,
 [Parameter(Mandatory = $false, Position=31)]
 [string]$taskpassword,
 [Parameter(Mandatory = $false, Position=32)]
 [switch]$genkey,
 [Parameter(Mandatory = $false, Position=33)]
 [switch]$installpwsh
 )

# Help strings
$getpackageshelp = "
 Get-Packages			Downloads packages from the defined sources to the package repository directory.
				Optionally, specify the directory to use with -pkgdir.  You must specify and use 
				this same directory for subsequent actions.

 EmaDeploy Get-Packages
 EmaDeploy Get-Packages -pkgdir `'C:\EMA-Install-Dir'` "
$installpowershellhelp = "
 Install-PowerShell		Installs PowerShell v7 from the package repository directory.
				Optionally, specify the directory to use with -pkgdir.  You must specify -pkdir
				if it was specified when packages were downloaded.

 EmaDeploy Install-PowerShell
 EmaDeploy Install-PowerShell -pkgdir `'C:\EMA-Install-Dir'` "
$installurlrewritehelp = "
 Install-URLReWrite		Installs the URL Re-Write module from the package repository directory.
				Optionally, specify the directory to use with -pkgdir.  You must specify -pkdir
				if it was specified when packages were downloaded.

 EmaDeploy Install-URLReWrite
 EmaDeploy Install-URLReWrite -pkgdir `'C:\EMA-Install-Dir'` "
$installdotnethelp = "
 Install-DotNet			Installs .NET 4.8 Framework from the package repository directory.
				Optionally, specify the directory to use with -pkgdir.  You must specify -pkdir
				if it was specified when packages were downloaded.

 EmaDeploy Install-DotNet 
 EmaDeploy Install-DotNet -pkgdir `'C:\EMA-Install-Dir'` "
$createemainstallhelp = "
 Create-EmaInstall		Creates the encrypted Intel(R) EMA install script.  All parameters must be specified
				for installation and configuration.  See example below.
				Optionally, specify the directory to use with -pkgdir.  You must specify -pkdir
				if it was specified when packages were downloaded.

 EmaDeploy Create-EmaInstall -fqdn ema.server.com -gausername globaladmin@server.com -gapassword 'password'
                             -tenantname Example -tausername tenantadmin@server.com -tapassword 'password' 
                             -profilename ExPro -epgname ExEpg -epgpassword 'password' -autopass 'password' 
                             -dbserver sql.server.com -dbuser sa -dbpassword 'password'

 EmaDeploy Create-EmaInstall -fqdn ema.server.com -gausername globaladmin@server.com -gapassword 'password'
                             -tenantname Example -tausername tenantadmin@server.com -tapassword 'password' 
                             -profilename ExPro -epgname ExEpg -epgpassword 'password' -autopass 'password' 
                             -dbserver sql.server.com -dbuser sa -dbpassword 'password' -pkgdir `'C:\EMA-Install-Dir'` "
$executeemainstallhelp = "
 Execute-EmaInstall		Executes the encrypted Intel(R) EMA install script.
				Optionally, specify the directory to use with -pkgdir.  You must specify -pkdir
				if it was specified when packages were downloaded.

 EmaDeploy Execute-EmaInstall
 EmaDeploy Execute-EmaInstall -pkgdir `'C:\EMA-Install-Dir'` "
$scheduleemainstallhelp = "
 Schedule-EmaInstall		Schedules the execution of the encrypted Intel(R) EMA install script.
				Optionally, specify the directory to use with -pkgdir.  You must specify -pkdir
				if it was specified when packages were downloaded.

 EmaDeploy Schedule-EmaInstall
 EmaDeploy Schedule-EmaInstall -pkgdir `'C:\EMA-Install-Dir'` "
$installcertificatehelp = "
 Install-Certificate		Requests and installs a Let`'`s Encrypt certificate and sets IIS bindings.
				Optionally, specify the directory to use with -pkgdir.  You must specify and use 
				this same directory for subsequent actions.

 EmaDeploy Install-Certificate -fqdn ema.server.com
 EmaDeploy Install-Certificate -fqdn ema.server.com -pkgdir `'C:\EMA-Install-Dir'` "
$executeallautohelp = "
 Execute-AllAuto		Performs all actions to automatically download, install and configure all
				pre-requisites and the Intel(R) EMA software.
				Optionally, specify the directory to use with -pkgdir.  You must specify and use 
				this same directory for subsequent actions.

 EmaDeploy Execute-AllAuto	-fqdn ema.server.com -gausername globaladmin@server.com -gapassword 'password'
                          	-tenantname Example -tausername tenantadmin@server.com -tapassword 'password' 
                          	-profilename ExPro -epgname ExEpg -epgpassword 'password' -autopass 'password' 
                          	-dbserver sql.server.com -dbuser sa -dbpassword 'password'


 EmaDeploy Execute-AllAuto	-fqdn ema.server.com -gausername globaladmin@server.com -gapassword 'password'
                          	-tenantname Example -tausername tenantadmin@server.com -tapassword 'password' 
                          	-profilename ExPro -epgname ExEpg -epgpassword 'password' -autopass 'password' 
                          	-dbserver sql.server.com -dbuser sa -dbpassword 'password' -pkgdir `'C:\EMA-Install-Dir'` "
$switcheshelp = "
 -fqdn 				Specify the FQDN of the Intel(R) EMA server being installed
 -dbserver 			Specify the SQL server
 -dbuser			Specify the username for SQL server access
 -dbpassword			Specify the password for SQL server access
 -gausername			Specify the global admin username
 -gapassword			Specify the global admin password
 -tenantname			Specify tenant name
 -tausername			Specify the tenant admin username
 -tapassword			Sepcify the tenant admin passowrd
 -profilename			Specify AMT profile name
 -epgname			Specify endpoint group name
 -epgpassword			Specify endpoint group password
 -autopass			Specify AMT auto setup password
 -defaults			Sets default values for tenant, endpoint group and profile names and reuses the
				tenant admin password as the values for -autopass and -epgpassword
 -pkgdir			Specify the directory to use as the package root
 -noverify			Disables certificate validation
 -nologging			Disable logging
 -logfile			Specify the logfile to use for all actions
 -enckey			Specify the encryption key to use while encrypting and decrypting
 -noemainstall			Create an encrypted script that performs configuration only
 -nocert			Disable automatic acquisition and import of a Let`'s Encrypt certificate based on
				the FQDN specified during execution
 -taskuser			Specifies the user for the scheduled task created by Schedule-EmaInstall
 -taskpassword			Specifies the password for the scheduled task created by Schedule-EmaInstall
 -genkey			Automatically generates an encryption key for use in encrypted script creation
 -installpwsh			Installs PowerShell v7 as part of the Execute-AllAuto action"

# Function definition section
#
# Get-Packages
function Get-Packages {
 try {
  Write-Host -Foreground Green "Downloading Intel(R) EMA..."
  [int]$dc = 0
  do {
    $hash = $null
    $dc = $dc+1
    (Invoke-WebRequest -Uri https://downloadmirror.intel.com/646990/Ema_Install_Package_1.8.1.0.exe -Method GET -OutFile $pkgdir\emainstall.zip) | Invoke-Command $output
    $hash = ((Get-FileHash -Path $pkgdir\emainstall.zip -Algorithm SHA1) | Select-Object -Expand Hash)
    If ($dc -ge 3) {
      (Invoke-WebRequest -Uri https://emacloudstart.z13.web.core.windows.net/packages/Ema_Install_Package_1.8.1.0.exe -OutFile $pkgdir\emainstall.zip) | Invoke-Command $output
      Break
    }
  } until ($hash -eq 'E33EB0BA54A3AE2B8F1CBF4FC179112C810E619B')
  Write-Host -Foreground Green "Intel(R) EMA package downloaded successfully."
  (Write-Output "Intel(R) EMA package downloaded successfully.") | Invoke-Command $output
 }
 catch {
  Write-Host -Foreground Yellow "Failed to download Intel(R) EMA package."
  (Write-Output "Failed to download Intel(R) EMA package.") | Invoke-Command $output
 }
 If ($serveros -eq $false) {
 try {
  Write-Host -Foreground Green "Downloading .NET Framework 4.8..."
  [int]$dc = 0
  do {
    $hash = $null
    $dc = $dc+1
    (Invoke-WebRequest -Uri https://go.microsoft.com/fwlink/?linkid=2088631 -OutFile $pkgdir\net_framework_480.exe) | Invoke-Command $output
    $hash = ((Get-FileHash -Path $pkgdir\net_framework_480.exe -Algorithm SHA1) | Select-Object -Expand Hash)
    If ($dc -ge 3) {
      (Invoke-WebRequest -Uri https://emacloudstart.z13.web.core.windows.net/packages/net_framework_480.exe -OutFile $pkgdir\net_framework_480.exe) | Invoke-Command $output
      Break
    }
  } until ($hash -eq 'E322E2E0FB4C86172C38A97DC6C71982134F0570')
  Write-Host -Foreground Green ".NET Framework 4.8 package downloaded successfully."
  (Write-Output ".NET Framework 4.8 package downloaded successfully.") | Invoke-Command $output
 }
 catch {
  Write-Host -Foreground Yellow "Failed to download .NET Framework 4.8 package."
  (Write-Output "Failed to download .NET Framework 4.8 package.") | Invoke-Command $output
 }
 }
 try {
  Write-Host -Foreground Green "Downloading URL Re-Write module..."
  [int]$dc = 0
  do {
    $hash = $null
    $dc = $dc+1
    (Invoke-WebRequest -Uri https://download.microsoft.com/download/1/2/8/128E2E22-C1B9-44A4-BE2A-5859ED1D4592/rewrite_amd64_en-US.msi -Method GET -OutFile $pkgdir\rewrite_amd64_en-US.msi) | Invoke-Command $output
    $hash = ((Get-FileHash -Path $pkgdir\rewrite_amd64_en-US.msi -Algorithm SHA1) | Select-Object -Expand Hash)
    If ($dc -ge 3) {
      (Invoke-WebRequest -Uri https://emacloudstart.z13.web.core.windows.net/packages/rewrite_amd64_en-US.msi -OutFile $pkgdir\rewrite_amd64_en-US.msi) | Invoke-Command $output
      Break
    }
  } until ($hash -eq '8F41A67FA49110155969DCCFF265B8623A66448F')
  Write-Host -Foreground Green "URL Re-Write package downloaded successfully."
  (Write-Output "URL Re-Write package downloaded successfully.") | Invoke-Command $output
 }
 catch {
  Write-Host -Foreground Yellow "Failed to download URL Re-Write package."
  (Write-Output "Failed to download URL Re-Write package.") | Invoke-Command $output
 }
 try {
  Write-Host -Foreground Green "Downloading IISCrypto CLI..."
  [int]$dc = 0
  do {
    $hash = $null
    $dc = $dc+1
    (Invoke-WebRequest -Uri https://www.nartac.com/Downloads/IISCrypto/IISCryptoCli.exe -OutFile $pkgdir\IISCrypto.exe) | Invoke-Command $output
    $hash = ((Get-FileHash -Path $pkgdir\IISCrypto.exe -Algorithm SHA1) | Select-Object -Expand Hash)
    If ($dc -ge 3) {
      (Invoke-WebRequest -Uri https://emacloudstart.z13.web.core.windows.net/packages/IISCryptoCli.exe -OutFile $pkgdir\IISCrypto.exe) | Invoke-Command $output
      Break
    }
  } until ($hash -eq 'BBF89060525125E70B96ED7512523A1594E02808')
  Write-Host -Foreground Green "IIS Crypto CLI package downloaded successfully."
  (Write-Output "IIS Crypto CLI package downloaded successfully.") | Invoke-Command $output
 }
 catch {
  Write-Host -Foreground Yellow "Failed to download IIS Crypto CLI package."
  (Write-Output "Failed to download IIS Crypto CLI package.") | Invoke-Command $output
 }
 If ($installpwsh -eq $true) {
 try {
  Write-Host -Foreground Green "Downloading PowerShell v7..."
  [int]$dc = 0
  do {
    $hash = $null
    $dc = $dc+1
    (Invoke-WebRequest -Uri https://github.com/PowerShell/PowerShell/releases/download/v7.1.3/PowerShell-7.1.3-win-x64.msi -OutFile $pkgdir\PowerShell-7.1.3-win-x64.msi) | Invoke-Command $output
    $hash = ((Get-FileHash -Path $pkgdir\PowerShell-7.1.3-win-x64.msi -Algorithm SHA1) | Select-Object -Expand Hash)
    If ($dc -ge 3) {
      (Invoke-WebRequest -Uri https://emacloudstart.z13.web.core.windows.net/packages/PowerShell-7.1.3-win-x64.msi -OutFile $pkgdir\PowerShell-7.1.3-win-x64.msi) | Invoke-Command $output
      Break
    }
  } until ($hash -eq 'FECDB1B261BF4F1A4B5594D67DC5A8BA98903E66')
  Write-Host -Foreground Green "PowerShell v7 package downloaded successfully."
  (Write-Output "PowerShell v7 package downloaded successfully.") | Invoke-Command $output
 }
 catch {
  Write-Host -Foreground Yellow "Failed to download PowerShell v7 package."
  (Write-Output "Failed to download PowerShell v7 package.") | Invoke-Command $output
 }
 }
 try {
  Write-Host -Foreground Green "Downloading Win-ACME..."
  [int]$dc = 0
  do {
   $hash = $null
   $dc = $dc+1
   (Invoke-WebRequest -Uri https://github.com/win-acme/win-acme/releases/download/v2.1.22.1267/win-acme.v2.1.22.1267.x64.pluggable.zip -OutFile $pkgdir\winacme.zip) | Invoke-Command $output
   $hash = ((Get-FileHash -Path $pkgdir\winacme.zip -Algorithm SHA1) | Select-Object -Expand Hash)
   If ($dc -ge 3) {
     (Invoke-WebRequest -Uri https://emacloudstart.z13.web.core.windows.net/packages/win-acme.v2.1.22.1267.x64.pluggable.zip -OutFile $pkgdir\winacme.zip) | Invoke-Command $output
     Break
   }
  } until ($hash -eq '11AA9EF5FF072FAD55F8358654A12B9EC974CDF6')
  Write-Host -Foreground Green "Win-ACME package downloaded successfully."
  (Write-Output "Win-ACME package downloaded successfully.") | Invoke-Command $output
 }
 catch {
  Write-Host -Foreground Yellow "Failed to download Win-ACME package."
  (Write-Output "Failed to download Win-ACME package.") | Invoke-Command $output
 }
 try {
  Write-Host -Foreground Green "Downloading Intel(R) Configuration utilities..."
  (Invoke-WebRequest -Uri https://emacloudstart.z13.web.core.windows.net/EmaSvrConfig.ps1 -Method GET -OutFile $pkgdir\EmaSvrConfig.ps1) | Invoke-Command $output
  If (!(Test-Path "$pkgdir\EmaDeploy.ps1")) {
    (Invoke-WebRequest -Uri https://emacloudstart.z13.web.core.windows.net/EmaDeploy.ps1 -Method GET -OutFile $pkgdir\EmaDeploy.ps1) | Invoke-Command $output
  }
  Write-Host -Foreground Green "Intel(R) EMA config utility packages downloaded successfully."
  (Write-Output "Intel(R) EMA config utility packages downloaded successfully.") | Invoke-Command $output
 }
 catch {
  Write-Host -Foreground Yellow "Failed to download Intel(R) EMA config utilities."
  (Write-Output "Failed to download Intel(R) EMA config utilities.") | Invoke-Command $output
 }
}

# Package installation functions
#
# Install PowerShell v7
function Install-PowerShell {
 try {
  $cmdout = "$pkgdir\cmdout.txt"
  $obj = [pscustomobject]@{
  pkgdir = $pkgdir
  cmdout = $cmdout
  }
  $arguments = '/i "{0}\PowerShell-7.1.3-win-x64.msi" /qb /l "{1}" ADD_EXPLORER_CONTEXT_MENU_OPENPOWERSHELL=1 ENABLE_PSREMOTING=1 REGISTER_MANIFEST=1' -f $obj.pkgdir, $obj.cmdout
  Start-Process msiexec.exe -Wait -ArgumentList $arguments
  (Get-Content $cmdout) | Invoke-Command $output
  Remove-Item $cmdout
  Write-Host -Foreground Green "PowerShell v7 successfully installed."
  (Write-Output "PowerShell v7 successfully installed.") | Invoke-Command $output
 }
 catch {
  Write-Host -Foreground Yellow "Failed to install PowerShell v7."
  (Write-Output "Failed to install PowerShell v7.") | Invoke-Command $output
 }
}

# Install URL Re-Write
function Install-URLReWrite {
 try {
  $cmdout = "$pkgdir\cmdout.txt"
  $obj = [pscustomobject]@{
  pkgdir = $pkgdir
  cmdout = $cmdout
  }
  $arguments = '/i "{0}\rewrite_amd64_en-US.msi" /qb /l "{1}"' -f $obj.pkgdir, $obj.cmdout
  Start-Process msiexec.exe -Wait -ArgumentList $arguments
  (Get-Content $cmdout) | Invoke-Command $output
  Remove-Item $cmdout
  Write-Host -Foreground Green "URL ReWrite successfully installed."
  (Write-Output "URL ReWrite successfully installed.") | Invoke-Command $output
 }
 catch {
  Write-Host -Foreground Yellow "Failed to install URL ReWrite."
  (Write-Output "Failed to install URL ReWrite.") | Invoke-Command $output
 }
 try {
   New-WebBinding -Name "Default Web Site" -Port 80 -IPAddress "*"
   Write-Host -Foreground Green "Successfully added port 80 HTTP binding." 
 }
 catch {Write-Host -Foreground Yellow "HTTP binding might already exist, moving on..."}
 try {
  $rulename = 'Default Re-Write HTTP to HTTPS'
  $inbound = '(.*)'
  $outbound = 'https://{HTTP_HOST}{REQUEST_URI}'
  $site = 'IIS:\Sites\Default Web Site'
  $root = 'system.webServer/rewrite/rules'
  $filter = "{0}/rule[@name='{1}']" -f $root, $rulename
  Add-WebConfigurationProperty -PSPath $site -filter $root -name '.' -value @{name=$rulename; patterSyntax='Regular Expressions'; stopProcessing='True'}
  Set-WebConfigurationProperty -PSPath $site -filter "$filter/match" -name 'url' -value $inbound
  Set-WebConfigurationProperty -PSPath $site -filter "$filter/conditions" -name '.' -value @{input='{HTTPS}'; matchType='0'; pattern='^OFF$'; ignoreCase='True'; negate='False'}
  Set-WebConfigurationProperty -PSPath $site -filter "$filter/action" -name 'type' -value 'Redirect'
  Set-WebConfigurationProperty -PSPath $site -filter "$filter/action" -name 'url' -value $outbound
  Start-Sleep 5
  Start-Process "C:\Windows\System32\iisreset.exe" -Wait -NoNewWindow -ArgumentList "/restart"
  Write-Host -Foreground Green "Default URL ReWrite rule successfully created."
  (Write-Output "Default URL ReWrite rule successfully created.") | Invoke-Command $output
 }
 catch {
  Write-Host -Foreground Yellow "Failed to create default URL ReWrite rule."
  (Write-Output "Failed to create default URL ReWrite rule.") | Invoke-Command $output
 }
}

# Install IISCrypto
function Install-IISCrypto {
 try {
  $cmdout = "$pkgdir\cmdout.txt"
  Start-Process "$pkgdir\IISCrypto.exe" -Wait -NoNewWindow -RedirectStandardOutput $cmdout -ArgumentList '/template best'
  (Get-Content $cmdout) | Invoke-Command $output
  Remove-Item $cmdout
  Write-Host -Foreground Green "IIS Crypto successfully installed."
  (Write-Output "IIS Crypto successfully installed.") | Invoke-Command $output
 }
 catch {
  Write-Host -Foreground Yellow "Failed to install IIS Crypto."
  (Write-Output "Failed to install IIS Crypto.") | Invoke-Command $output
 }
}

# Install .NET Framework 4.8
function Install-DotNet {
 try {
  $arguments = '/q /log {0}\DotNet480.htm' -f $pkgdir
  Start-Process "$pkgdir\net_framework_480.exe" -Wait -ArgumentList $arguments
  Write-Host -Foreground Green ".NET Framework 4.8 successfully installed."
  (Write-Output ".NET Framework 4.8 successfully installed.") | Invoke-Command $output
  shutdown -r -t 60 -f
 }
 catch {
  Write-Host -Foreground Yellow "Failed to install .NET Framework 4.8."
  (Write-Output "Failed to install .NET Framework 4.8.") | Invoke-Command $output
 }
}

# Create the encrypted Intel(R) EMA install and config script
function Create-EmaInstall {
  try {
    If ($ad -eq $true) {
      $domainauth = " --domainauth"
      $gcredpass = $null
    } ElseIf ($ad -eq $false) {
      $domainauth = $null
      $gcredpass = " --gpass=$gapassword"
    }
    $obj = [pscustomobject]@{
      pkgdir = $pkgdir
      fqdn = $fqdn
      gausername = $gausername
      gapassword = $gapassword
      tapassword = $tapassword
      epgpassword = $epgpassword
      autopass = $autopass
      dbserver = $dbserver
      dbuser = $dbuser
      dbpassword = $dbpassword
      output = $output
      ad = $domainauth
      gpass = $gcredpass
    }
If (!(Test-Path "C:\Program Files\wacs\wacs.exe")) {
  Expand-Archive -LiteralPath "$pkgdir\winacme.zip" -DestinationPath "C:\Program Files\wacs"
}
If (!(Test-Path -Path "C:\ProgramData\Intel\EMA\USBR")) {
  New-Item -ItemType "directory" -Path "C:\ProgramData\Intel\EMA\USBR"
}
$installer = (Test-Path "$pkgdir\emainstall\EMAServerInstaller.exe")
If ($noemainstall -eq $false -And $nocert -eq $false) {
  try {
    If ($installer -eq $false) {
      Expand-Archive -LiteralPath "$pkgdir\emainstall.zip" -DestinationPath "$pkgdir\emainstall" -Force
      Write-Host -Foreground Green "Successfully extracted Intel(R) EMA install files."
    }
  } 
  catch {Write-Host -Foreground Yellow "Failed to extract installation files."}

$header = '
# Encrypted Intel(R) EMA installation script
#
# Intel(R) EMA will be installed
# Intel(R) EMA install step
$ipv4 = (Test-Connection -ComputerName (hostname) -Count 1)  | Select-Object -Expand IPV4Address
$ipema = $ipv4.IPAddressToString
$cmdout = "{0}\cmdout.txt"
$pkgdir = "{0}"
$arguments = ''FULLINSTALL{8} --isdistributedserverinit --swarmlbhost={1} --swarmlbip=''+$ipema+'' --ajaxlbhost={1} --ajaxlbip=''+$ipema+'' --recoverylbhost={1} --recoverylbip=''+$ipema+'' --emaip=''+$ipema+'' --db=EMADatabase --dbserver={2} --dbuser={3} --dbpass={4} --guser={5}{9} --deployajaxandweb --deploymanageability --deployswarm --deployrecovery --verbose --autoexit --accepteula''
cd "{0}\emainstall"
Start-Process "{0}\emainstall\EMAServerInstaller.exe" -Wait -NoNewWindow -WorkingDirectory "{0}\emainstall" -RedirectStandardOutput $cmdout -ArgumentList $arguments
(Get-Content "$cmdout") | {7}
Remove-Item "$cmdout"
Write-Host -Foreground Green "Intel(R) EMA installed successfully."
# Install certificate
$arguments = ''--source manual --host {1} --emailaddress {5} --webroot c:\inetpub\wwwroot --friendlyname "Intel EMA Web Certificate" --installation script --script {0}\CertInstall.ps1 --accepttos''
Start-Process "C:\Program Files\wacs\wacs.exe" -Wait -NoNewWindow -RedirectStandardOutput $cmdout -ArgumentList $arguments
# Wait 30 seconds before configuration
Start-Sleep 30' -f $obj.pkgdir, $obj.fqdn, $obj.dbserver, $obj.dbuser, $obj.dbpassword, $obj.gausername, $obj.gapassword, $obj.output, $obj.ad, $obj.gpass
} ElseIf ($noemainstall -eq $false -And $nocert -eq $true) {
  try {
    Expand-Archive -LiteralPath "$pkgdir\emainstall.zip" -DestinationPath "$pkgdir\emainstall" -Force
    Write-Host -Foreground Green "Successfully extracted Intel(R) EMA install files."
  } 
  catch {Write-Host -Foreground Yellow "Failed to extract installation files."}
  $noverify = $true  
$header = '
# Encrypted Intel(R) EMA installation script
#
# Intel(R) EMA will be installed
# Intel(R) EMA install step
$ipv4 = (Test-Connection -ComputerName (hostname) -Count 1)  | Select-Object -Expand IPV4Address
$ipema = $ipv4.IPAddressToString
$cmdout = "{0}\cmdout.txt"
$pkgdir = "{0}"
$arguments = ''FULLINSTALL {8} --isdistributedserverinit --swarmlbhost={1} --swarmlbip=''+$ipema+'' --ajaxlbhost={1} --ajaxlbip=''+$ipema+'' --recoverylbhost={1} --recoverylbip=''+$ipema+'' --emaip=''+$ipema+'' --db=EMADatabase --dbserver={2} --dbuser={3} --dbpass={4} --guser={5} --gpass={6} --deployajaxandweb --deploymanageability --deployswarm --deployrecovery --verbose --console --accepteula''
cd "{0}\emainstall"
Start-Process "{0}\emainstall\EMAServerInstaller.exe" -Wait -NoNewWindow -RedirectStandardOutput $cmdout -ArgumentList $arguments
(Get-Content "$cmdout") | {7}
Remove-Item "$cmdout"
Write-Host -Foreground Green "Intel(R) EMA installed successfully."
# Wait 30 seconds before configuration
Start-Sleep 30' -f $obj.pkgdir, $obj.fqdn, $obj.dbserver, $obj.dbuser, $obj.dbpassword, $obj.gausername, $obj.gapassword, $obj.output, $obj.ad
}
$body = "
{0}\EmaSvrConfig.ps1 Get-AuthToken -noverify -server $fqdn -user $gausername -password `'{1}'` 
{0}\EmaSvrConfig.ps1 Create-Tenant -noverify -tenantname ""$tenantname"" 
{0}\EmaSvrConfig.ps1 Create-TenantAdmin -noverify -tenantname ""$tenantname"" -tausername $tausername -tapassword `'{2}'` 
{0}\EmaSvrConfig.ps1 Create-AMTProfile -noverify -server $fqdn -user $tausername -password `'{2}'` -profilename ""$profilename"" 
{0}\EmaSvrConfig.ps1 Create-EndPointGroup -noverify -epgname ""$epgname"" -epgpassword `'{3}'`
{0}\EmaSvrConfig.ps1 Enable-CCMAutoSetup -noverify -autopass `'{4}'` -epgname ""$epgname"" -profilename ""$profilename"" 
{0}\EmaSvrConfig.ps1 Clear-Data
Write-Host -Foreground Cyan ""Configuration process completed.  Please address issues if any were reported"""

  $script = "$header$body" -f $obj.pkgdir, $obj.gapassword, $obj.tapassword, $obj.epgpassword, $obj.autopass
  If (![string]::IsNullOrEmpty($enckey)) {
    $paddedkey = ([string]$enckey).PadRight(32,'0')
    $key = [system.Text.Encoding]::UTF8.GetBytes($paddedkey)
  }
  $secure = ConvertTo-SecureString $script -asPlainText -force
  If ([string]::IsNullOrEmpty($enckey)) {
    $export = $secure | ConvertFrom-SecureString    
  } Else {$export = $secure | ConvertFrom-SecureString -Key $key}
  Set-Content "$pkgdir\ema_auto.bin" $export
  Write-Host -Foreground Cyan "Encrypted script $pkgdir\ema_auto.bin has been created"
  $enckey = $null
  $paddedkey = $null
  $key = $null
  }
  catch {
    Write-Host -Foreground Yellow "Unable to create script.  Please check the parameters."
  }
}

# Execute the encrypted install script
function Execute-EmaInstall {
  try {
  [Environment]::SetEnvironmentVariable('pkgdir', $pkgdir,'User')
  [Environment]::SetEnvironmentVariable('enckey', $enckey,'User')
  powershell -Command {
    $env:pkgdir = [System.Environment]::GetEnvironmentVariable('pkgdir','User')
    $env:enckey = [System.Environment]::GetEnvironmentVariable('enckey','User')
    $enckey = $env:enckey
    If (![string]::IsNullOrEmpty($enckey)) {
      $paddedkey = ([string]$enckey).PadRight(32,'0')
      $key = [system.Text.Encoding]::UTF8.GetBytes($paddedkey)
    }    
    trap { "Decryption failed"; break }
    $raw = Get-Content $env:pkgdir\ema_auto.bin
    If ([string]::IsNullOrEmpty($enckey)) {
      $secure = ConvertTo-SecureString $raw
    } Else {$secure = ConvertTo-SecureString $raw -Key $key}
    $helper = New-Object system.Management.Automation.PSCredential("test", $secure)
    $plain = $helper.GetNetworkCredential().Password
    $enckey = $null
    $paddedkey = $null
    $key = $null
    Invoke-Expression $plain
    $enckey = $null
    $paddedkey = $null
    $key = $null
    [Environment]::SetEnvironmentVariable('pkgdir', $null,'User')
    [Environment]::SetEnvironmentVariable('enckey', $null,'User')
  }
  $enckey = $null
  [Environment]::SetEnvironmentVariable('pkgdir', $null,'User')
  [Environment]::SetEnvironmentVariable('enckey', $null,'User')
  $taskname = "Install Intel(R) EMA"
  $taskname = Join-Path -Path '\' -ChildPath $taskname
  $taskexists = schtasks /query /fo csv 2> $null | ConvertFrom-Csv | Where-Object { $_.TaskName -eq $taskname }
  If ($taskexists) {
    Unregister-ScheduledTask -TaskName "Install Intel(R) EMA" -Confirm:$false
    Write-Host "Scheduled task removed"
  } Else {
    Write-Host "No scheduled task to remove"
  }
  $cmdout = "$pkgdir\cmdout.txt"
  If (Test-Path $cmdout) {
   Remove-Item $cmdout
  }
  [int]$c = 0
  $localusers = Get-LocalUser
  foreach ($_ in $localusers.Name) {
    If ($localusers[$c].Name -like "emaautodeploy") {
      Remove-LocalUser -Name "emaautodeploy"
    }
    $c = $c + 1
  }
  Write-Host -Foreground Green "Script decryption and execution complete."
  $systemp = [System.Environment]::GetEnvironmentVariable('TEMP','Machine')
  $configlog = "$systemp\EmaConfigLog_$(get-date -f yyyy-MM-dd).txt"
  If (Test-Path $configlog) {
    (Get-Content $configlog) | Invoke-Command $output
  }
  $testdir = "$env:systemdrive\inetpub\wwwroot"
  If (Test-Path $testdir) {
    Install-URLReWrite
  }
  }
  catch {Write-Host -Foreground Yellow "Script decryption and execution did not complete successfully."}
}

# Create scheduled task to install Intel(R) EMA after reboot
function Schedule-EmaInstall {
 try {
   $obj = [pscustomobject]@{
     pkgdir = $pkgdir
     enckey = $enckey
   }
   If ([string]::IsNullOrEmpty($enckey)) {
     $arguments = '-Command "& ''{0}\EmaDeploy.ps1'' Execute-EmaInstall -pkgdir ''{0}''"' -f $obj.pkgdir
   } Else {
     $arguments = '-Command "& ''{0}\EmaDeploy.ps1'' Execute-EmaInstall -pkgdir ''{0}'' -enckey ''{1}''"' -f $obj.pkgdir, $obj.enckey
   }
   If ([string]::IsNullOrEmpty($taskuser)) {
     $taskAction = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $arguments -WorkingDirectory "$pkgdir"
     $taskTrigger = New-ScheduledTaskTrigger -AtStartup
     $principal = New-ScheduledTaskPrincipal -User "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
     Register-ScheduledTask -TaskName "Install Intel(R) EMA" -Action $taskAction -Trigger $taskTrigger -Description "Install Intel(R) EMA software" -Principal $principal | Invoke-Command $output
   } ElseIf (![string]::IsNullOrEmpty($taskuser)) {
     $taskAction = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $arguments -WorkingDirectory "$pkgdir"
     $taskTrigger = New-ScheduledTaskTrigger -AtStartup
     Register-ScheduledTask -TaskName "Install Intel(R) EMA" -Action $taskAction -Trigger $taskTrigger -Description "Install Intel(R) EMA software" -User $taskuser -Password $taskpassword | Invoke-Command $output
   }
   New-NetFirewallRule -DisplayName "HTTP" -Direction inbound -Profile Any -Action Allow -LocalPort 80 -Protocol TCP
   New-NetFirewallRule -DisplayName "HTTPS" -Direction inbound -Profile Any -Action Allow -LocalPort 443 -Protocol TCP
   New-NetFirewallRule -DisplayName "RDP" -Direction inbound -Profile Any -Action Allow -LocalPort 3389 -Protocol TCP
   New-NetFirewallRule -DisplayName "EPCOMM" -Direction inbound -Profile Any -Action Allow -LocalPort 8080 -Protocol TCP
   Write-Host -Foreground Green "Intel(R) EMA installation scheduled for next reboot."
   (Write-Output "Intel(R) EMA installation scheduled for next reboot.") | Invoke-Command $output
 }
 catch {
  Write-Host -Foreground Yellow "Failed to schedule Intel(R) EMA install."
  (Write-Output "Failed to schedule Intel(R) EMA install.") | Invoke-Command $output
 }
}

# Installs a certificte that has been acquired using the Get-Certificate action
function Install-Certificate {
 try {
   If ([string]::IsNullOrEmpty($fqdn)) {
    $keys = (Select-Xml -Path C:\inetpub\wwwroot\web.config -XPath '/configuration/appSettings/add').Node.key
    $values = (Select-Xml -Path C:\inetpub\wwwroot\web.config -XPath '/configuration/appSettings/add').Node.value
    [int]$dc = 0
    ForEach ($_ in $keys) {
        If ($keys[$dc] -eq "ajaxserverhost") {
            $fqdn = $values[$dc]
        }
        $dc = $dc + 1
    }
   }
   $cmdout = "$pkgdir\cmdout.txt"
   $arguments = "--source manual --host $fqdn --emailaddress $gausername --webroot c:\inetpub\wwwroot --friendlyname ""Intel EMA Web Certificate"" --installation script --script $pkgdir\CertInstall.ps1 --accepttos"
   If (!(Test-Path "C:\Program Files\wacs\wacs.exe")) {
    Expand-Archive -LiteralPath "$pkgdir\winacme.zip" -DestinationPath "C:\Program Files\wacs"
   }
   Start-Process "C:\Program Files\wacs\wacs.exe" -Wait -NoNewWindow -RedirectStandardOutput $cmdout -ArgumentList $arguments
   (Get-Content "$cmdout") | Invoke-Command $output
   Remove-Item "$cmdout"
   Write-Host -Foreground Green "Certificate request and import action completed."
   (Write-Output "Certificate request and import action completed.") | Invoke-Command $output
 }
 catch {
  Write-Host -Foreground Yellow "Certificate request and import action failed.  Please verify parameters."
  (Write-Output "Certificate request and import action failed.  Please verify parameters.") | Invoke-Command $output
 }
}

# Create certificate script when certain actions are called
function Create-CertScript {
 # Create install script variable definition
 $certInstall = '# Script to update certificate bindings in IIS after certificate renewal
 try {
    $keys = (Select-Xml -Path C:\inetpub\wwwroot\web.config -XPath ''/configuration/appSettings/add'').Node.key
    $values = (Select-Xml -Path C:\inetpub\wwwroot\web.config -XPath ''/configuration/appSettings/add'').Node.value
    [int]$dc = 0
    ForEach ($_ in $keys) {
        If ($keys[$dc] -eq "ajaxserverhost") {
            $hostname = $values[$dc]
        }
        $dc = $dc + 1
    }
    $thumbprint = (Get-ChildItem cert:\LocalMachine\WebHosting | Where-Object {$_.Subject -like "CN=$hostname" -And $_.Issuer -like "CN=R3*"}).Thumbprint
    Write-Host $hostname" : "$thumbprint
    Import-Module WebAdministration
    $binding = Get-WebBinding -Name "Default Web Site" -Protocol "https"
    $binding.AddSslCertificate($thumbprint, "WebHosting")
    Write-Host "Successfully updated certificate bindings."
 } catch { Write-Host "Something failed in the binding process.  Please check the WebHosting certificate store and win-acme logs." }'
 # End variable definition
 Set-Content -Path "$pkgdir\CertInstall.ps1" -Value $certInstall
}

# Execute all functions automatically
function Execute-AllAuto {
 $taskname = "Install Intel(R) EMA"
 $taskname = Join-Path -Path '\' -ChildPath $taskname
 $taskexists = schtasks /query /fo csv 2> $null | ConvertFrom-Csv | Where-Object { $_.TaskName -eq $taskname }
 If ($taskexists) {
   Unregister-ScheduledTask -TaskName "Install Intel(R) EMA" -Confirm:$false
   Write-Host "Scheduled task removed"
 } Else {
   Write-Host "No scheduled task to remove"
 }
 Get-Packages
 If ($installpwsh -eq $true) {
   Install-PowerShell
 }
 Install-IISCrypto
 $account = (whoami)
 If ($account -like "nt authority\system") {
   $script:enckey = (-join ((65..90) + (97..122) | Get-Random -Count 32 | %{[char]$_}))
   Add-Type -AssemblyName 'System.Web'
   $random = [System.Web.Security.Membership]::GeneratePassword(16, 1)
   $installaccountpass = $random | ConvertTo-SecureString -AsPlainText -Force
   $installaccount = "emaautodeploy"
   New-LocalUser -Name $installaccount -Description "Temporary Intel EMA installation account" -Password $installaccountpass
   Add-LocalGroupMember -Group "Administrators" -Member $installaccount
   $script:taskuser = $installaccount
   $script:taskpassword = $random
 }
 Create-EmaInstall
 Schedule-EmaInstall
 If ($serveros -eq $false) {
   Install-DotNet
 } Else {
   Write-Host -ForegroundColor Green "Sleeping 10 seconds to start Intel(R) EMA install..."
   Start-ScheduledTask -TaskName "Install Intel(R) EMA"
   Start-Sleep 10
   Write-Host -ForegroundColor Green "Starting install and configuration..."
   while ((Get-Process -Name EMAServerInstaller -ErrorAction SilentlyContinue).HasExited -eq $false) {
     Start-Sleep 1
   }
   Write-Host -ForegroundColor Green "Intel(R) EMA installation complete.`nStarting configuration..."
   while ((Get-Process -Name powershell -IncludeUserName -ErrorAction SilentlyContinue | Where-Object {$_.UserName -like "*emaautodeploy*"}).HasExited -eq $false) {
     Start-Sleep 1
   }
   Write-Host -ForegroundColor Green "First configuration phase complete..."
   Start-Sleep 5
   while ((Get-Process -Name powershell -IncludeUserName -ErrorAction SilentlyContinue | Where-Object {$_.UserName -like "*emaautodeploy*"}).HasExited -eq $false) {
     Start-Sleep 1
   }
   Write-Host -ForegroundColor Green "Second configuration phase complete..."
   Start-Sleep 5
   while ((Get-Process -Name powershell -IncludeUserName -ErrorAction SilentlyContinue | Where-Object {$_.UserName -like "*emaautodeploy*"}).HasExited -eq $false) {
     Start-Sleep 1
   }
   Write-Host -ForegroundColor Green "Installation and configuration of Intel(R) EMA complete!"
 }
}

# Execute actions or help strings as specified with arguments
# Set certificate handling first if -noverify option set to true
# If run as a script, clearing of the TrustAllCertsPolicy requires closing the PowerShell session
If ($noverify -eq $true) {
add-type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
            ServicePoint srvPoint, X509Certificate certificate,
            WebRequest request, int certificateProblem) {
            return true;
        }
    }
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Ssl3, [Net.SecurityProtocolType]::Tls, [Net.SecurityProtocolType]::Tls11, [Net.SecurityProtocolType]::Tls12
}

# Set the package directory
If ($action -ne "Help") {
 If ([string]::IsNullOrEmpty($pkgdir) -And $currentdir -eq $false) {
  $pkgdir = "$env:systemdrive\Packages\EMA"
 } ElseIf ($currentdir -eq $true) {
  $scriptpath = $MyInvocation.MyCommand.Path
  $pkgdir = (Split-Path $scriptpath -Parent)
 }
 $testdir = $pkgdir.Contains(':\')
 If ($testdir -eq $false) {
  $pkgdir = "$env:systemdrive\Packages\EMA"
  Write-Host -Foreground Green "Reverting to default package directory of $pkgdir"
 }
 If (!(Test-Path $pkgdir)) {
  (New-Item -ItemType "directory" -Path $pkgdir) | Out-Null
  Write-Host -Foreground Green "$pkgdir package directory created successfully."
 } Else {
  Write-Host -Foreground Green "Using existing $pkgdir as package directory."
 }
}

# Set logging option for the session
If ($action -ne "Help") {
 If ($nologging) {
  $output = {Out-Null}
 } ElseIf (![string]::IsNullOrEmpty($logfile)) {
  $output = {Out-File -FilePath $logfile -Encoding ASCII -Append}
 } Else {
  $output = {Out-File -FilePath "$pkgdir\Ema_Installation_Log_$(get-date -f yyyy-MM-dd).txt" -Encoding Unicode -Append}
  $logfile = "$pkgdir\Ema_Installation_Log_$(get-date -f yyyy-MM-dd).txt"
 }  
}

# Write working directory and user to logfile
 If ($action -ne "Help") {
   $executinguser = ([Security.Principal.WindowsIdentity]::GetCurrent().Name)
   Write-Output "Running script as $executinguser..." | Invoke-Command $output
   Write-Output "Using $pkgdir as working directory..." | Invoke-Command $output
 }

# Set defaults option if specified
If ($defaults -eq $true) {
 $epgname = "Default Endpoint Group"
 $profilename = "Default AMT Profile"
 $tenantname = "Default Tenant"
 $epgpassword = $tapassword
 $autopass = $tapassword
}

# Generate random encryption key if specified
If ($genkey -eq $true) {
 $enckey = (-join ((65..90) + (97..122) | Get-Random -Count 32 | %{[char]$_}))
}

# Detect OS version and set global variable
$serveros = $null
$osversion = (Get-WMIObject win32_operatingsystem).name
If ($osversion -like "*2022*") {
  $script:serveros = $true
} Else {
  $script:serveros = $false
}

# Call function based on first argument passed
If ($action -eq "Get-Packages") {
 Get-Packages
} ElseIf ($action -eq "Install-PowerShell") {
 Install-PowerShell
} ElseIf ($action -eq "Install-URLReWrite") {
 Install-URLReWrite
} ElseIf ($action -eq "Install-IISCrypto") {
 Install-IISCrypto
} ElseIf ($action -eq "Install-DotNet") {
 Install-DotNet
} ElseIf ($action -eq "Create-EmaInstall") {
 Create-EmaInstall
} ElseIf ($action -eq "Schedule-EmaInstall") {
 Schedule-EmaInstall
} ElseIf ($action -eq "Execute-EmaInstall") {
 Create-CertScript
 Execute-EmaInstall
} ElseIf ($action -eq "Install-Certificate") {
 Create-CertScript
 Install-Certificate
} ElseIf ($action -eq "Execute-AllAuto") {
 Create-CertScript
 Execute-AllAuto
} ElseIf ($action -eq "Help" -And $helpparam -eq "Get-Packages") {
 Write-Host -Foreground Cyan "$getpackageshelp"
} ElseIf ($action -eq "Help" -And $helpparam -eq "Install-PowerShell") {
 Write-Host -Foreground Cyan "$installpowershellhelp"
} ElseIf ($action -eq "Help" -And $helpparam -eq "Install-URLReWrite") {
 Write-Host -Foreground Cyan "$installurlrewritehelp"
} ElseIf ($action -eq "Help" -And $helpparam -eq "Install-DotNet") {
 Write-Host -Foreground Cyan "$installdotnethelp"
} ElseIf ($action -eq "Help" -And $helpparam -eq "Create-EmaInstall") {
 Write-Host -Foreground Cyan "$createemainstallhelp"
} ElseIf ($action -eq "Help" -And $helpparam -eq "Execute-EmaInstall") {
 Write-Host -Foreground Cyan "$executeemainstallhelp"
} ElseIf ($action -eq "Help" -And $helpparam -eq "Schedule-EmaInstall") {
 Write-Host -Foreground Cyan "$scheduleemainstallhelp"
} ElseIf ($action -eq "Help" -And $helpparam -eq "Install-Certificate") {
 Write-Host -Foreground Cyan "$installcertificatehelp"
} ElseIf ($action -eq "Help" -And $helpparam -eq "Execute-AllAuto") {
 Write-Host -Foreground Cyan "$executeallautohelp"
} ElseIf ($action -eq "Help" -And $helpparam -eq "Switches") {
 Write-Host -Foreground Cyan "
 The Following switches are available:
 $switcheshelp"
} ElseIf ($action -eq "Help") {
 Write-Output " This utility will download and deploy the Intel(R) EMA server and pre-requisites software.

 General usage guidelines:
 Enclose strings with spaces and/or special characters in single quotes such as: -pkgdir `'C:\Path w Spaces\EMA'`
 Include -noverify with any action to bypass certificate validation  
 Include -pkgdir to specify the working directory for all actions and log files 
 
 This utility supports the following actions:
 $getpackageshelp
 $installpowershellhelp
 $installurlrewritehelp
 $installdotnethelp
 $createemainstallhelp
 $executeemainstallhelp
 $scheduleemainstallhelp
 $installcertificatehelp
 $executeallautohelp

 The following switches are available for use with the actions defined above:
 $switcheshelp
" | More
} Else {
 Write-Host -Foreground Cyan "
 You must specify an action.  Supported actions for this utility:
 
 Get-Packages			Downloads all install and prerequisite packages
 Install-PowerShell		Installs PowerShell v7
 Install-URLReWrite		Installs the URL Re-Write IIS module
 Install-DotNet			Installs .NET Framework 4.8
 Create-EmaInstall		Creates an encrypted Intel(R) EMA install and config script
 Execute-EmaInstall		Executes an encrypted Intel(R) EMA install and config script
 Schedule-EmaInstall		Creates a scheduled task to execute the encrypted script
 Install-Certificate		Requests and installs a Let`'`s Encrypt certificate 
 Execute-AllAuto		Executes all functions automatically

 The following switches are available for use with the actions defined above:
 $switcheshelp
"
}
 
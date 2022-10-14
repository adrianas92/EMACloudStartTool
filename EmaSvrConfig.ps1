# Intel(R) EMA configuration utility
# Author: Grant Kelly
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
 [string] $action, 
 [Parameter(Mandatory = $false, Position=1)]
 [string] $helpparam, 
 [Parameter(Mandatory = $false, Position=2)]
 [string] $server, 
 [Parameter(Mandatory = $false, Position=3)]
 [string]$user, 
 [Parameter(Mandatory = $false, Position=4)]
 [string]$password,
 [Parameter(Mandatory = $false, Position=5)]
 [string]$tenantname,
 [Parameter(Mandatory = $false, Position=6)]
 [string]$tausername,
 [Parameter(Mandatory = $false, Position=7)]
 [string]$tapassword,
 [Parameter(Mandatory = $false, Position=8)]
 [string]$profilename,
 [Parameter(Mandatory = $false, Position=9)]
 [string]$epgname,
 [Parameter(Mandatory = $false, Position=10)]
 [string]$epgpassword,
 [Parameter(Mandatory = $false, Position=11)]
 [string]$certpath,
 [Parameter(Mandatory = $false, Position=12)]
 [string]$certpass,
 [Parameter(Mandatory = $false, Position=13)]
 [string]$certname,
 [Parameter(Mandatory = $false, Position=14)]
 [string]$autopass,
 [Parameter(Mandatory = $false, Position=15)]
 [switch]$noverify,
 [Parameter(Mandatory = $false, Position=16)]
 [switch]$ad,
 [Parameter(Mandatory = $false, Position=17)]
 [switch]$na,
 [Parameter(Mandatory = $false, Position=18)]
 [switch]$hidden,
 [Parameter(Mandatory = $false, Position=19)]
 [switch]$nologging,
 [Parameter(Mandatory = $false, Position=20)]
 [string]$logfile
 )

# Define help variable strings so that they can be called cumulatively or individually
$gethelptipstring = "TIP: include -server, -user and -password parameters to refresh authentication"
$hiddenhelpstring = " Hidden actions, excercise extreme caution when using.  The following actions will remove data from the Intel(R) EMA
 server.  Available actions:

 Delete-Tenant			Deletes a tenant, must specify tenant name with -tenantname
 Delete-EndPointGroup		Deletes an endpoint group, must specify group name with -epgname
 Delete-AMTProfile		Deletes an AMT profile, must specify profile name with -profilename
 Delete-Certificate		Deletes an AMT provisioning certificate, must specify certificate name with -certname
 Delete-TenantAdmin		Deletes a tenant admin, must specify admin to delete with -tausername

"
$getadauthtokenhelp = "
 Get-ADAuthToken	Acquires an authentication token from the Intel(R) EMA server using 
			Active Directory authentication and writes the authentication token to a variable
			that can be used repeatedly in the same PowerShell session for subsequent executions
			of the utility.  Specify the host FQDN, username and password to be used when
			accessing the server.
			NOTE: username must be in UPN format

 EmaSvrConfig.ps1 Get-ADAuthToken -server `'server.domain.com'` -user `'username@domain.com'` -password `'password'` "
$getnaauthtokenhelp = "
 Get-NAAuthToken	Acquires an authentication token from the Intel(R) EMA server using normal
			account authentication and writes the authentication token to a variable that can be
			used repeatedly in the same PowerShell session for subsequent executions of the utility.
			Specify the host FQDN, username and password to be used when accessing the server.
			
 EmaSvrConfig.ps1 Get-NAAuthToken -server `'server.domain.com'` -user `'username@domain.com'` -password `'password'` "
$getauthtokenhelp = "
 Get-AuthToken		Acquires an authentication token from the Intel(R) EMA server attempting Active
			Directory then normal authentication and writes the authentication token to a variable
			that can be used repeatedly in the same PowerShell session for subsequent executions of
			the utility.  Specify the host FQDN, username and password to be used when accessing the
			server.
			NOTE: username must be in UPN format for Active Directory authentication
			OPTIONAL: specify -ad for Active Directory auth and -na for normal account auth
			
 EmaSvrConfig.ps1 Get-AuthToken  -server `'server.domain.com'` -user `'username@domain.com'` -password `'password'` "
$createtenanthelp = "
 Create-Tenant		Creates a tenant on the Intel(R) EMA server using an authentication token acquired
			with Get-AuthToken or Get-ADAuthToken.  Specify the tenant name when calling this action.
			Execute this action as a global admin.
			$gethelptipstring
			
 EmaSvrConfig.ps1 Create-Tenant -tenantname `'Tenant Name'` "
$createtenantadminhelp = "
 Create-TenantAdmin	Creates a tenant admin user on the Intel(R) EMA server using an authentication token acquired
			with Get-AuthToken or Get-ADAuthToken.  Specify the tenant admin username and tenant admin 
			password for normal accounts or tenant admin username in UPN format for Active Directory
			accounts when calling this action.
			Execute this action as a global admin.
			$gethelptipstring
			
 EmaSvrConfig.ps1 Create-TenantAdmin -tausername `'username@domain.com'` -tapassword `'password'` -tenantname `'Tenant Name'` 
 NOTE: It is only necessary to specify the password for normal accounts and the tenant name is an optional parameter"
$createamtprofilehelp = "
 Create-AMTProfile	Creates an AMT profile on the Intel(R) EMA server using an authentication token acquired
			using one of the auth actions against the tenant that the specified user has access to.
			Execute this action as a tenant admin.
			Specify the profile name when calling this action.
			$gethelptipstring
			
 EmaSvrConfig.ps1 Create-AMTProfile -profilename `'Profile Name'` "
$createendpointgrouphelp = "
 Create-EndPointGroup	Creates an endpoint group on the Intel(R) EMA server using an authentication token acquired
			using one of the auth actions against the tenant that the specified user has access to.
			Execute this action as a tenant admin.
			Specify the group name and the group password when calling this action.
			$gethelptipstring
			
 EmaSvrConfig.ps1 Create-EndPointGroup -epgname `'Endpoint Group Name'` -epgpassword `'Group_Password'` "
$uploadcertificatehelp = "
 Upload-Certificate	Uploads a certificate to use for AMT admin control mode provisioning.  Specify the absolute
			path, including the certificate filename and PFX password when calling this action.
			Execute this action as a tenant admin.
			$gethelptipstring

			****IMPORTANT NOTE****
			This action requires PowerShell v7 to be installed on the device that you are executing the
			utility from.

 EmaSvrConfig.ps1 Upload-Certificate -certpath `'C:\path\to\certificate\file.pfx'` -certpass `'Certificate Password'` "
$enableacmautosetuphelp = "
 Enable-ACMAutoSetup	Assigns certificate and enables AMT autosetup in ACM for the endpoint group.  Specify the
			admin password when calling this action.
			Execute this action as a tenant admin.
			$gethelptipstring

			Optionally, specify the endpoint group name, AMT certificate name and AMT profile name to use.
 
			**** IMPORTANT NOTE ****
			You MUST specify the group name, the certificate name and the profile name if you wish specify
			any one of those values.
			
 EmaSvrConfig.ps1 Enable-ACMAutoSetup -autopass `'Admin_Password'`

 EmaSvrConfig.ps1 Enable-ACMAutoSetup -autopass `'Admin_Password'` -epgname `'Endpoint_Group_Name'` -certname `'AMT_cert_Name'`
 -profilename `'Profile_Name'` "
$enableccmautosetuphelp = "
 Enable-CCMAutoSetup	Enables AMT autosetup in CCM for the endpoint group.  Specify the admin password when calling
			this action.
			Execute this action as a tenant admin.
			$gethelptipstring

			Optionally, specify the endpoint group name and AMT profile name to use.
 
			**** IMPORTANT NOTE ****
			You MUST specify the group name and the profile name if you wish specify any one of those
			values.
			
 EmaSvrConfig.ps1 Enable-CCMAutoSetup -autopass `'Admin_Password'`

 EmaSvrConfig.ps1 Enable-CCMAutoSetup -autopass `'Admin_Password'` -epgname `'Endpoint_Group_Name'` -profilename `'Profile_Name'` "
$gettenantshelp = "
 Get-Tenants		Gets a list of tenants from the Intel(R) EMA server.  Execute this action as a global admin.
			$gethelptipstring

 EmaSvrConfig.ps1 Get-Tenants"
$gettenantadminshelp = "
 Get-TenantAdmins	Gets a list of tenants admins from the Intel(R) EMA server.  Execute this action as a global
			admin.
			$gethelptipstring

 EmaSvrConfig.ps1 Get-TenantAdmins -tenantname `'Tenant Name'` "
$getamtprofileshelp = "
 Get-AMTProfiles	Gets a list of AMT profiles from the Intel(R) EMA server.  Execute this action as a tenant
			admin.
			$gethelptipstring

 EmaSvrConfig.ps1 Get-AMTProfiles"
$getendpointgroupshelp = "
 Get-EndPointGroups	Gets a list of endpoint groups from the Intel(R) EMA server.  Execute this action as a tenant
			admin.
			$gethelptipstring

 EmaSvrConfig.ps1 Get-EndPointGroups"
$getcertificateshelp = "
 Get-Certificates	Gets a list of certificates from the Intel(R) EMA server.  Execute this action as a tenant
			admin.
			$gethelptipstring

 EmaSvrConfig.ps1 Get-Certificates"
$cleardatahelp = "
 Clear-Data		Clears connection data from memory on this device.

 EmaSvrConfig.ps1 Clear-Data"
$switcheshelp = "
 -ad			Specify Active Directory authentication
 -na			Specify normal account authentication
 -server		Specify the server to connect to
 -user			Specify the user to be used in authenticating to the server
 -password		Specify the password to be used in authenticating to the server
 -tenantname		Specify the tenant name
 -tausername		Specify the tenant admin username (must be in UPN or user@domain.com format)
 -tapassword		Specify the tenant admin password (normal accounts)
 -profilename		Specify the AMT profile name
 -epgname		Specify the endpoint group name
 -epgpassword		Specify the endpoint group password
 -certpath		Specify the full path and name of the certificate PFX to upload
 -certpass		Certificate PFX decryption password
 -autopass		Specify the AMT Auto Setup password
 -noverify		Disable certificate validation for connections to the server
 -nologging		Disable logging to `'$env:temp\EmaConfigLog_$(get-date -f yyyy-MM-dd).txt'` 
 -logfile		Specify the logfile with full path and name that verbose output will be written to"

# Begin Function definitions
# Active Directory auth token creation
function Get-ADAuthToken {
 [Environment]::SetEnvironmentVariable('fqdn', 'server.domain.com','User')
 [Environment]::SetEnvironmentVariable('token', 'access_token_string','User')
 $global:fqdn = $server
 [Environment]::SetEnvironmentVariable('fqdn', $fqdn,'User')
 $emasrv = $fqdn
 Write-Host -Foreground Cyan "Server: $emasrv User: $user Password: ***********"
 $body = @{
  "Password" = $password
  "Upn" = $user
 }
 $json = $body | ConvertTo-Json
 try {
  $token = (Invoke-RestMethod -Uri https://$emasrv/api/latest/accessTokens/getUsingWindowsCredentials -ContentType 'application/json' -Method POST -Body $json) | Select-Object -Expand access_token
  [Environment]::SetEnvironmentVariable('token', $token,'User')
  $global:headers = @{'Authorization' = 'Bearer ' + $token}
  Write-Host -Foreground Green "Authentication token for server $emasrv using account $user created successfully."
  $global:authenticated = $true
 }
 catch {Write-Host -Foreground Yellow "Unable to create authentication token.  Please make sure that the server FQDN, username and password are correct"}
}

# Normal account auth token creation
function Get-NAAuthToken {
 [Environment]::SetEnvironmentVariable('fqdn', 'server.domain.com','User')
 [Environment]::SetEnvironmentVariable('token', 'access_token_string','User')
 $global:fqdn = $server
 [Environment]::SetEnvironmentVariable('fqdn', $fqdn,'User')
 $emasrv = $fqdn
 Write-Host -Foreground Cyan "Server: $emasrv User: $user Password: ***********"
 try {
  $token = (Invoke-RestMethod -Uri https://$emasrv/api/token -Method POST -Body "grant_type=password&username=$user&password=$password") | Select-Object -Expand access_token
  [Environment]::SetEnvironmentVariable('token', $token,'User')
  $global:headers = @{'Authorization' = 'Bearer ' + $token}
  Write-Host -Foreground Green "Authentication token for server $emasrv using account $user created successfully."
  $global:authenticated = $true
 }
 catch {Write-Host -Foreground Yellow "Unable to create authentication token.  Please make sure that the server FQDN, username and password are correct"}
}

# Sequential or designated token creation for Active Directory or normal accounts
function Get-AuthToken {
 $global:authenticated = $false
 [Environment]::SetEnvironmentVariable('fqdn', 'server.domain.com','User')
 [Environment]::SetEnvironmentVariable('token', 'access_token_string','User')
 $global:fqdn = $server
 [Environment]::SetEnvironmentVariable('fqdn', $fqdn,'User')
 $emasrv = $fqdn
 Write-Host -Foreground Cyan "Server: $emasrv User: $user Password: ***********"
 $body = @{
  "Password" = $password
  "Upn" = $user
 }
 $json = $body | ConvertTo-Json
 If ($ad) {
  try {
  $token = (Invoke-RestMethod -Uri https://$emasrv/api/latest/accessTokens/getUsingWindowsCredentials -ContentType 'application/json' -Method POST -Body $json) | Select-Object -Expand access_token
  [Environment]::SetEnvironmentVariable('token', $token,'User')
  $global:headers = @{'Authorization' = 'Bearer ' + $token}
  Write-Host -Foreground Green "Authentication token for server $emasrv using account $user created successfully."
  $global:authenticated = $true
 }
 catch {Write-Host -Foreground Yellow "Unable to authenticate using Active Directory credentials."}
 } ElseIf ($na) {
 try {
  $token = (Invoke-RestMethod -Uri https://$emasrv/api/token -Method POST -Body "grant_type=password&username=$user&password=$password") | Select-Object -Expand access_token
  [Environment]::SetEnvironmentVariable('token', $token,'User')
  $global:headers = @{'Authorization' = 'Bearer ' + $token}
  Write-Host -Foreground Green "Authentication token for server $emasrv using account $user created successfully."
  $global:authenticated = $true
 }
 catch {Write-Host -Foreground Yellow "Unable to authenticate using normal account credentials."}
 } Else {
 try {
  $token = (Invoke-RestMethod -Uri https://$emasrv/api/latest/accessTokens/getUsingWindowsCredentials -ContentType 'application/json' -Method POST -Body $json) | Select-Object -Expand access_token
  [Environment]::SetEnvironmentVariable('token', $token,'User')
  $global:headers = @{'Authorization' = 'Bearer ' + $token}
  Write-Host -Foreground Green "Authentication token for server $emasrv using account $user created successfully."
  $global:authenticated = $true
 }
 catch {Write-Host -Foreground Yellow "Unable to authenticate using Active Directory credentials.
Attempting to use normal account credentials...
"}
 If ($authenticated -eq $true) {Return}
 try {
  $token = (Invoke-RestMethod -Uri https://$emasrv/api/token -Method POST -Body "grant_type=password&username=$user&password=$password") | Select-Object -Expand access_token
  [Environment]::SetEnvironmentVariable('token', $token,'User')
  $global:headers = @{'Authorization' = 'Bearer ' + $token}
  Write-Host -Foreground Green "Authentication token for server $emasrv using account $user created successfully."
  $global:authenticated = $true
 }
 catch {Write-Host -Foreground Yellow "Unable to authenticate using normal account credentials."}
 If ($authenticated -eq $true) {Return}
 If ($authenticated -eq $false) {Write-Host -Foreground Yellow "
Unable to authenticate using either type of credential.  Is the server, username and password correct?"}
 }
}

# Tenant creation function
function Create-Tenant {
 $reauth = $null
 If ([string]::IsNullOrEmpty($user)) {
  $reauth = $false
 } Else {
  $reauth = $true
 }
 If ($reauth -eq $true) {
  Get-AuthToken
 }
 $env:token = [System.Environment]::GetEnvironmentVariable("token","User")
 $env:fqdn = [System.Environment]::GetEnvironmentVariable("fqdn","User")
 $emasrv = $env:fqdn
 $headers = @{'Authorization' = 'Bearer ' + $env:token}
 $tenantdescription = "$tenantname tenant created on: " + (Get-Date)
 $tenant = @{
  'Name' = $tenantname
  'Description' = $tenantdescription
 }
 try {
  (Invoke-RestMethod -Uri https://$emasrv/api/latest/tenants -Method POST -Headers $headers -Body $tenant) | Invoke-Command $output
  Write-Host -Foreground Green "Successfully created tenant $tenantname."
 }
 catch {Write-Host -Foreground Yellow "Unable to create tenant.  Please make sure that the server FQDN is correct and that you have authenticated with a global admin account."}
}

# Tenant admin creation function
function Create-TenantAdmin {
 $reauth = $null
 If ([string]::IsNullOrEmpty($user)) {
  $reauth = $false
 } Else {
  $reauth = $true
 }
 If ($reauth -eq $true) {
  Get-AuthToken
 }
 $env:token = [System.Environment]::GetEnvironmentVariable("token","User")
 $env:fqdn = [System.Environment]::GetEnvironmentVariable("fqdn","User")
 $emasrv = $env:fqdn
 $headers = @{'Authorization' = 'Bearer ' + $env:token}
 $tenantnameempty = $null
 If ([string]::IsNullOrEmpty($tenantname)) {
  $tenantnameempty = $true
 } Else {
  $tenantnameempty = $false
 }
 If ($tenantnameempty -eq $true) {
  $tenantid = ((Invoke-RestMethod -Uri https://$emasrv/api/latest/tenants -Method GET -Headers $headers) | Select-Object -Expand TenantId)
  [int]$count = $tenantid.length
  If ($count -ne 36) {
   Write-Host -Foreground Yellow "It appears that there are multiple tenant IDs.  Use Get-Tenants action and specify the tenant name that you'd like to create the admin against."
   Return
  }
 } Else {
  $tenantid = ((Invoke-RestMethod -Uri https://$emasrv/api/latest/tenants -Method GET -Headers $headers) | Where-Object -Property Name -eq $tenantname | Select-Object -Expand TenantId)
 }
 $roleid = ((Invoke-RestMethod -Uri https://$emasrv/api/latest/roles -ContentType 'application/json' -Method GET -Headers $headers) | Where-Object -Property TenantId -eq $tenantid | Where-Object -Property Name -eq "Tenant Administrator" | Select-Object -Expand RoleId)
 $tenantadmin = @{
  'Username' = $tausername
  'Enabled' = 'True'
  'TenantId' = $tenantid
  'Description' = 'Tenant Administrator'
  'RoleId' = $roleid
  'Password' = $tapassword
  'SysRole' = 'tenantAdministrator'
  }
 try {
  (Invoke-RestMethod -Uri https://$emasrv/api/latest/users -Method POST -Headers $headers -Body $tenantadmin) | Invoke-Command $output
  Write-Host -Foreground Green "Tenant admin $tausername successfully created
  TenantID: $tenantid
  RoledID : $roleid"
 }
 catch {Write-Host -Foreground Yellow "Unable to create tenant admin.  Does the user exists already?  Did you authenticate with global admin credentials? Did you specify BOTH the username and password (and tenant ID if required)?"}
}

# AMT profile creation function
function Create-AMTProfile {
 $reauth = $null
 If ([string]::IsNullOrEmpty($user)) {
  $reauth = $false
 } Else {
  $reauth = $true
 }
 If ($reauth -eq $true) {
  Get-AuthToken
 }
 $env:token = [System.Environment]::GetEnvironmentVariable("token","User")
 $env:fqdn = [System.Environment]::GetEnvironmentVariable("fqdn","User")
 $emasrv = $env:fqdn
 $headers = @{'Authorization' = 'Bearer ' + $env:token}
 $profiledescription = "$profilename AMT profile created on: " + (Get-Date)
 $ciradomain = (-join ((65..90) + (97..122) | Get-Random -Count 16 | %{[char]$_}))+".com"
 # Rev 1 CIRA domain fixed value, replaced with dynamic value above 
 # $ciradomain = "nonresolvable.com"
 $content = (Invoke-RestMethod -Uri https://$emasrv)
 $content = $content -split "window.IntelEMA.EMAVersion"
 $content = $content[1] -split "`'"
 $emaversion = $content[1]
 If ($emaversion -ge "1.7.0.0") {
 $amtprofile = @"
   {
   "Name":  "$profilename",
   "Description":  "$profiledescription",
   "TlsAuthType":  0,
   "PowerPackageSettings":  {
     "PowerActiveOn":  1,
     "PowerStateIdleTimeoutInMinutes":  10
     },
   "ManagementInterfacesSettings":  {
     "WebUIServiceEnabledState":  2,
     "KVMInterfaceState":  2,
     "UserConsentRequired":  0,
     "UserConsentDisplayTimeout":  60,
     "SOLEnabled":  true,
     "IDEREnabled":  true,
     "OneClickRecoveryEnabled": true,
     "RemotePlatformEraseEnabled": true,
     "RedirectionServiceState":  32771
     },
   "FqdnSettings":  {
     "FqdnSource":  0
     },
   "IpSettings":  {
     "DHCPEnabled":  true,
     "SharedStaticIp":  false,
     "Source":  0,
     "IP":  "1.1.1.1",
     "SubnetMask":  "255.255.255.0",
     "DefaultGateway":  "1.1.1.1",
     "PrimaryDNS":  "1.1.1.1",
     "SecondaryDNS":  "1.1.1.1"
     },
   "WiFiConnectionSettings":  {
     "AMTHostWiFiSyncEnabled":  1,
     "WiFiConnectionEnabledConfiguration":  0,
     "WiFiEnabledInPowerState":  1,
     "UEFIWiFiProfileShareEnabled": true,
     "WiFiSetups":  [
                     ]
     },
   "Wired802_1XSettings":  {
     "_802_1Setup_DBLookupKey":  null
     },
   "CIRASettings":  {
     "CIRATunnel":  true,
     "EnvironmentDetectionDomainSuffix":  "$ciradomain",
     "CIRAProxies":  [
                     ]
     }
   }
"@
 } Else {
 $amtprofile = @"
   {
   "Name":  "$profilename",
   "Description":  "$profiledescription",
   "TlsAuthType":  0,
   "PowerPackageSettings":  {
     "PowerActiveOn":  1,
     "PowerStateIdleTimeoutInMinutes":  10
     },
   "ManagementInterfacesSettings":  {
     "WebUIServiceEnabledState":  2,
     "KVMInterfaceState":  2,
     "UserConsentRequired":  0,
     "UserConsentDisplayTimeout":  60,
     "SOLEnabled":  true,
     "IDEREnabled":  true,
     "OneClickRecoveryEnabled": true,
     "RemotePlatformEraseEnabled": true,
     "RedirectionServiceState":  32771
     },
   "FqdnSettings":  {
     "FqdnSource":  0
     },
   "IpSettings":  {
     "DHCPEnabled":  true,
     "SharedStaticIp":  false,
     "Source":  0,
     "IP":  "1.1.1.1",
     "SubnetMask":  "255.255.255.0",
     "DefaultGateway":  "1.1.1.1",
     "PrimaryDNS":  "1.1.1.1",
     "SecondaryDNS":  "1.1.1.1"
     },
   "WiFiConnectionSettings":  {
     "AMTHostWiFiSyncEnabled":  1,
     "WiFiConnectionEnabledConfiguration":  0,
     "WiFiEnabledInPowerState":  1,
     "WiFiSetups":  [
                     ]
     },
   "Wired802_1XSettings":  {
     "_802_1Setup_DBLookupKey":  null
     },
   "CIRASettings":  {
     "CIRATunnel":  true,
     "EnvironmentDetectionDomainSuffix":  "$ciradomain",
     "CIRAProxies":  [
                     ]
     }
   }
"@
 }
 try {
  (Invoke-RestMethod -Uri https://$emasrv/api/latest/amtProfiles -ContentType 'application/json' -Method POST -Headers $headers -Body $amtprofile) | Invoke-Command $output
  Write-Host -Foreground Green "AMT profile $profilename successfully created."
 }
 catch {Write-Host -Foreground Yellow "Unable to create AMT profile $profilename.  Does the profile exist?  Did you authenticate using tenant admin credentials?"}
}

# Create endpoint group
function Create-EndPointGroup {
 $reauth = $null
 If ([string]::IsNullOrEmpty($user)) {
  $reauth = $false
 } Else {
  $reauth = $true
 }
 If ($reauth -eq $true) {
  Get-AuthToken
 }
 $env:token = [System.Environment]::GetEnvironmentVariable("token","User")
 $env:fqdn = [System.Environment]::GetEnvironmentVariable("fqdn","User")
 $emasrv = $env:fqdn
 $headers = @{'Authorization' = 'Bearer ' + $env:token}
 $epgdescription = "Endpoint Group created on: " + (Get-Date)
 $endpointgroup = @"
 {
 "Name": "$epgname",
 "Description": "$epgdescription",
 "Password": "$epgpassword",
 "UserConsentKVM_Timeout": 60,
 "Permissions": {
   "AllowWakeup": true,
   "AllowSleep": true,
   "AllowReset": true,
   "AllowTcpCommunication": true,
   "AllowAlert": true,
   "AllowConsole": true,
   "AllowKvm": true,
   "AllowFileAccess": true,
   "AllowWmi": true,
   "AllowLocation": true,
   "AllowP2P": true,
   "AllowUserConsentKVM": false
    }
  }
"@
 try {
  (Invoke-RestMethod -Uri https://$emasrv/api/latest/endpointGroups -ContentType 'application/json' -Method POST -Headers $headers -Body $endpointgroup) | Invoke-Command $output
  Write-Host -Foreground Green "Endpoint group $epgname successfully created."
 }
 catch {Write-Host -Foreground Yellow "Unable to create endpoint group $epgname.  Does the group exist?  Did you authenticate using tenant admin credentials?"}
}

# Upload PFX provisioning certificate
# This function requires PowerShell v7 due to -Form switch availability in Invoke-WebRequest
# PowerShell v7 location must be in the user or system path as pwsh.exe is called without the absolute path specified 
function Upload-Certificate {
 $reauth = $null
 If ([string]::IsNullOrEmpty($user)) {
  $reauth = $false
 } Else {
  $reauth = $true
 }
 If ($reauth -eq $true) {
  Get-AuthToken
 }
 try {
  [Environment]::SetEnvironmentVariable('certpath', $certpath,'User')
  [Environment]::SetEnvironmentVariable('certpass', $certpass,'User')
  [Environment]::SetEnvironmentVariable('noverify', $noverify,'User')
  [Environment]::SetEnvironmentVariable('nologging', $nologging,'User')
  [Environment]::SetEnvironmentVariable('logfile', $logfile,'User')
  pwsh -Command {
   $env:token = [System.Environment]::GetEnvironmentVariable('token','User')
   $env:fqdn = [System.Environment]::GetEnvironmentVariable('fqdn','User')
   $env:certpath = [System.Environment]::GetEnvironmentVariable('certpath','User')
   $env:certpass = [System.Environment]::GetEnvironmentVariable('certpass','User')
   $env:noverify = [System.Environment]::GetEnvironmentVariable('noverify','User')
   $env:nologging = [System.Environment]::GetEnvironmentVariable('nologging','User')
   $env:logfile = [System.Environment]::GetEnvironmentVariable('logfile','User')
   $emasrv = $env:fqdn
   $headers = @{'Authorization' = 'Bearer ' + $env:token}
   $certname = 'AMT_Cert'
   $certpath = $env:certpath
   $certpassword = $env:certpass
   If ($env:nologging -eq $true) {
    $output = {Out-Null}
   } ElseIf (![string]::IsNullOrEmpty($env:logfile)) {
    $output = {Out-File -FilePath $env:logfile -Encoding ASCII -Append} 
   } Else {
    $output = {Out-File -FilePath $env:temp\EmaConfigLog_$(get-date -f yyyy-MM-dd).txt -Encoding ASCII -Append}
   }
   $certupload = @{
    'name' = $certname
    'password' = $certpassword
    'file' = Get-Item -Path $certpath
   }
   If ($noverify -eq $true) {
    try {
     (Invoke-WebRequest -Uri https://$emasrv/api/latest/amtProvisioningCertificates/uploadPfx -SkipCertificateCheck -ContentType 'multipart/form-data' -Method POST -Headers $headers -Form $certupload) | Invoke-Command $output
     Write-Host -Foreground Green "Successfully uploaded certificate to $emasrv"
    }
    catch {Write-Host -Foreground Yellow "Failed to upload certificate.  Is the path and password correct? Does the certificate already exist on the server?"}
    [Environment]::SetEnvironmentVariable('certpath', $null,'User')
    [Environment]::SetEnvironmentVariable('certpass', $null,'User')
    [Environment]::SetEnvironmentVariable('noverify', $null,'User')
    [Environment]::SetEnvironmentVariable('nologging', $null,'User')
    [Environment]::SetEnvironmentVariable('logfile', $null,'User')
   } Else {
    try {
     (Invoke-WebRequest -Uri https://$emasrv/api/latest/amtProvisioningCertificates/uploadPfx -ContentType 'multipart/form-data' -Method POST -Headers $headers -Form $certupload) | Invoke-Command $output
     Write-Host -Foreground Green "Successfully uploaded certificate to $emasrv"
    }
    catch {Write-Host -Foreground Yellow "Failed to upload certificate.  Is the path and password correct? Does the certificate already exist on the server?"}
    [Environment]::SetEnvironmentVariable('certpath', $null,'User')
    [Environment]::SetEnvironmentVariable('certpass', $null,'User')
    [Environment]::SetEnvironmentVariable('noverify', $null,'User')
    [Environment]::SetEnvironmentVariable('nologging', $null,'User')
    [Environment]::SetEnvironmentVariable('logfile', $null,'User')
   }
 } | Out-Null
 $env:fqdn = [System.Environment]::GetEnvironmentVariable('fqdn','User')
 $emasrv = $env:fqdn
 }
 catch {Write-Host -Foreground Yellow "Failed to upload certificate.  Is PowerShell v7 installed and included in the path environment variable?"} 
}
 
# Enable AMT admin control mode autosetup
function Enable-ACMAutoSetup {
 $reauth = $null
 If ([string]::IsNullOrEmpty($user)) {
  $reauth = $false
 } Else {
  $reauth = $true
 }
 If ($reauth -eq $true) {
  Get-AuthToken
 }
 $env:token = [System.Environment]::GetEnvironmentVariable("token","User")
 $env:fqdn = [System.Environment]::GetEnvironmentVariable("fqdn","User")
 $emasrv = $env:fqdn
 $headers = @{'Authorization' = 'Bearer ' + $env:token}
 $adminpassword = $autopass
 $epgnameempty = $null
 $certnameempty = $null
 $profilenameempty = $null
 If ([string]::IsNullOrEmpty($epgname)) {
  $epgnameempty = $true
 } Else {
  $epgnameempty = $false
 }
 If ([string]::IsNullOrEmpty($certname)) {
  $certnameempty = $true
 } Else {
  $certnameempty = $false
 }
 If ([string]::IsNullOrEmpty($profilename)) {
  $profilenameempty = $true
 } Else {
  $profilenameempty = $false
 }
 If ($epgnameempty -eq $false -And $certnameempty -eq $false -And $profilenameempty -eq $false) {
  $groupid = ((Invoke-RestMethod -Uri https://$emasrv/api/latest/endpointGroups -ContentType 'application/json' -Method GET -Headers $headers) | Where-Object -Property Name -eq $epgname | Select-Object -Expand EndpointGroupId)
  $amtcertid = ((Invoke-RestMethod -Uri https://$emasrv/api/latest/amtprovisioningCertificates -ContentType 'application/json' -Method GET -Headers $headers) | Where-Object -Property Name -eq $certname | Where-Object -Property IsAmtProvisioningCert -eq True | Select-Object -Expand AmtCertificateId)
  $amtprofileid = ((Invoke-RestMethod -Uri https://$emasrv/api/latest/amtProfiles -ContentType 'application/json' -Method GET -Headers $headers) | Where-Object -Property Name -eq $profilename | Select-Object -Expand AmtProfileId)
 } ElseIf ($epgnameempty -eq $false -And ($certnameempty -eq $false -And $profilenameempty -eq $true)) {
  Write-Host -Foregound Yellow "You must specify the endpoint group name, AMT certificate name and AMT profile name when specifying any one of those parameter."
  Return
 } ElseIf ($epgnameempty -eq $false -And ($certnameempty -eq $true -And $profilenameempty -eq $true)) {
  Write-Host -Foreground Yellow "You must specify the endpoint group name, AMT certificate name and AMT profile name when specifying any one of those parameter."
  Return
 } ElseIf ($epgnameempty -eq $false -And ($certnameempty -eq $true -And $profilenameempty -eq $false)) {
  Write-Host -Foreground Yellow "You must specify the endpoint group name, AMT certificate name and AMT profile name when specifying any one of those parameter."
  Return
 } ElseIf ($certnameempty -eq $false -And ($epgnameempty -eq $false -And $profilenameempty -eq $true)) {
  Write-Host -Foreground Yellow "You must specify the endpoint group name, AMT certificate name and AMT profile name when specifying any one of those parameter."
  Return
 } ElseIf ($certnameempty -eq $false -And ($epgnameempty -eq $true -And $profilenameempty -eq $true)) {
  Write-Host -Foreground Yellow "You must specify the endpoint group name, AMT certificate name and AMT profile name when specifying any one of those parameter."
  Return
 } ElseIf ($certnameempty -eq $false -And ($epgnameempty -eq $true -And $profilenameempty -eq $false)) {
  Write-Host -Foreground Yellow "You must specify the endpoint group name, AMT certificate name and AMT profile name when specifying any one of those parameter."
  Return
 } ElseIf ($profilenameempty -eq $false -And ($certnameempty -eq $false -And $epgnameempty -eq $true)) {
  Write-Host -Foreground Yellow "You must specify the endpoint group name, AMT certificate name and AMT profile name when specifying any one of those parameter."
  Return
 } ElseIf ($profilenameempty -eq $false -And ($certnameempty -eq $true -And $epgnameempty -eq $true)) {
  Write-Host -Foreground Yellow "You must specify the endpoint group name, AMT certificate name and AMT profile name when specifying any one of those parameter."
  Return
 } ElseIf ($profilenameempty -eq $false -And ($certnameempty -eq $true -And $epgnameempty -eq $false)) {
  Write-Host -Foreground Yellow "You must specify the endpoint group name, AMT certificate name and AMT profile name when specifying any one of those parameter."
  Return
 } Else {
 $groupid = ((Invoke-RestMethod -Uri https://$emasrv/api/latest/endpointGroups -ContentType 'application/json' -Method GET -Headers $headers) | Select-Object -Expand EndpointGroupId)
 $amtcertid = ((Invoke-RestMethod -Uri https://$emasrv/api/latest/amtprovisioningCertificates -ContentType 'application/json' -Method GET -Headers $headers) | Where-Object -Property IsAmtProvisioningCert -eq True | Select-Object -Expand AmtCertificateId)
 $amtprofileid = ((Invoke-RestMethod -Uri https://$emasrv/api/latest/amtProfiles -ContentType 'application/json' -Method GET -Headers $headers) | Select-Object -Expand AmtProfileId)
 }
 $body = @{
   'EndpointGroupId'=$groupid
   'AmtProfileId' = $amtprofileid
   'SetsRandomMebxPassword'=$false
   'AdminCredential'= @{
     'Password' = $adminpassword
   }
   'UsesEmaAccount'=$true
   'AmtCertificateId' = $amtcertid
  }
 $json = $body | ConvertTo-Json
 try {
  (Invoke-RestMethod -Uri https://$emasrv/api/latest/amtSetups/auto/set -ContentType 'application/json' -Method POST -Headers $headers -Body $json) | Invoke-Command $output
  Write-Host -Foreground Green "Successfully activated ACM AMT autosetup for endpoint group with ID:
$groupid"
 }
 catch {Write-Host -Foreground Yellow "Unable to activate ACM AMT autosetup.  Did you specify an endpoint group ID, AMT certificate ID and AMT profile ID and were they correct?"}
}

# Enable AMT client control mode autosetup
function Enable-CCMAutoSetup {
 $reauth = $null
 If ([string]::IsNullOrEmpty($user)) {
  $reauth = $false
 } Else {
  $reauth = $true
 }
 If ($reauth -eq $true) {
  Get-AuthToken
 }
 $env:token = [System.Environment]::GetEnvironmentVariable("token","User")
 $env:fqdn = [System.Environment]::GetEnvironmentVariable("fqdn","User")
 $emasrv = $env:fqdn
 $headers = @{'Authorization' = 'Bearer ' + $env:token}
 $adminpassword = $autopass
 $epgnameempty = $null
 $profilenameempty = $null
 If ([string]::IsNullOrEmpty($epgname)) {
  $epgnameempty = $true
 } Else {
  $epgnameempty = $false
 }
 If ([string]::IsNullOrEmpty($profilename)) {
  $profilenameempty = $true
 } Else {
  $profilenameempty = $false
 }
 If ($epgnameempty -eq $true -And $profilenameempty -eq $true) {
  $groupid = ((Invoke-RestMethod -Uri https://$emasrv/api/latest/endpointGroups -ContentType 'application/json' -Method GET -Headers $headers) | Select-Object -Expand EndpointGroupId)
  $amtprofileid = ((Invoke-RestMethod -Uri https://$emasrv/api/latest/amtProfiles -ContentType 'application/json' -Method GET -Headers $headers) | Select-Object -Expand AmtProfileId)
 } ElseIf ($epgnameempty -eq $true -And $profilenameempty -eq $false) {
  Write-Host -Foreground Yellow "You must specify the endpoint group name and AMT profile name when specifying any one of those parameter."
  Return
 } ElseIf ($epgnameempty -eq $false -And $profilenameempty -eq $true) {
  Write-Host -Foreground Yellow "You must specify the endpoint group name and AMT profile name when specifying any one of those parameter."
  Return
 } Else {
  $groupid = ((Invoke-RestMethod -Uri https://$emasrv/api/latest/endpointGroups -ContentType 'application/json' -Method GET -Headers $headers) | Where-Object -Property Name -eq $epgname | Select-Object -Expand EndpointGroupId)
  $amtprofileid = ((Invoke-RestMethod -Uri https://$emasrv/api/latest/amtProfiles -ContentType 'application/json' -Method GET -Headers $headers) | Where-Object -Property Name -eq $profilename | Select-Object -Expand AmtProfileId)
 }
 $body = @{
   'EndpointGroupId' = $groupid
   'AmtProfileId' = $amtprofileid
   'SetsRandomMebxPassword' = $false
   'AdminCredential'= @{
     'Password' = $adminpassword
   }
   'UsesEmaAccount'=$true
  }
 $json = $body | ConvertTo-Json
 try {
  (Invoke-RestMethod -Uri https://$emasrv/api/latest/amtSetups/auto/set -ContentType 'application/json' -Method POST -Headers $headers -Body $json) | Invoke-Command $output
  Write-Host -Foreground Green "Successfully activated CCM AMT autosetup for endpoint group with ID:
$groupid"
 }
 catch {Write-Host -Foreground Yellow "Unable to activate CCM AMT autosetup.  Did you specify an AMT profile and endpoint group ID and were they correct?"}
}

# Get tenants
function Get-Tenants {
 $reauth = $null
 If ([string]::IsNullOrEmpty($user)) {
  $reauth = $false
 } Else {
  $reauth = $true
 }
 If ($reauth -eq $true) {
  Get-AuthToken
 }
 $env:token = [System.Environment]::GetEnvironmentVariable("token","User")
 $env:fqdn = [System.Environment]::GetEnvironmentVariable("fqdn","User")
 $emasrv = $env:fqdn
 $headers = @{'Authorization' = 'Bearer ' + $env:token}
 try {
  Invoke-RestMethod -Uri https://$emasrv/api/latest/tenants -ContentType 'application/json' -Method GET -Headers $headers
 }
 catch {Write-Host -Foreground Yellow "Unable to get tenants from $emasrv.  Did you authenticate with proper credentials?"}
}

# Get AMT profiles
function Get-AMTProfiles {
 $reauth = $null
 If ([string]::IsNullOrEmpty($user)) {
  $reauth = $false
 } Else {
  $reauth = $true
 }
 If ($reauth -eq $true) {
  Get-AuthToken
 }
 $env:token = [System.Environment]::GetEnvironmentVariable("token","User")
 $env:fqdn = [System.Environment]::GetEnvironmentVariable("fqdn","User")
 $emasrv = $env:fqdn
 $headers = @{'Authorization' = 'Bearer ' + $env:token}
 try {
  $amtprofileids = ((Invoke-RestMethod -Uri https://$emasrv/api/latest/amtProfiles -ContentType 'application/json' -Method GET -Headers $headers) | Select-Object -Expand AmtProfileId)
  $amtprofilenames = ((Invoke-RestMethod -Uri https://$emasrv/api/latest/amtProfiles -ContentType 'application/json' -Method GET -Headers $headers) | Select-Object -Expand Name)
  Write-Host "AMT Profile names: $amtprofilenames"
  Write-Host "AMT Profile IDs  : $amtprofileids"
 }
 catch {Write-Host -Foreground Yellow "Unable to get AMT profiles from $emasrv.  Did you authenticate with tenant admin credentials?"}
}

# Get endpoint groups
function Get-EndPointGroups {
 $reauth = $null
 If ([string]::IsNullOrEmpty($user)) {
  $reauth = $false
 } Else {
  $reauth = $true
 }
 If ($reauth -eq $true) {
  Get-AuthToken
 }
 $env:token = [System.Environment]::GetEnvironmentVariable("token","User")
 $env:fqdn = [System.Environment]::GetEnvironmentVariable("fqdn","User")
 $emasrv = $env:fqdn
 $headers = @{'Authorization' = 'Bearer ' + $env:token}
 try {
  $endpointgroupids = ((Invoke-RestMethod -Uri https://$emasrv/api/latest/endpointGroups -ContentType 'application/json' -Method GET -Headers $headers) | Select-Object -Expand EndpointGroupId)
  $endpointgroupnames = ((Invoke-RestMethod -Uri https://$emasrv/api/latest/endpointGroups -ContentType 'application/json' -Method GET -Headers $headers) | Select-Object -Expand Name)
  Write-Host "Endpoint Group names: $endpointgroupnames"
  Write-Host "Endpoint Group IDs  : $endpointgroupids"
 }
 catch {Write-Host -Foreground Yellow "Unable to get endpoint groups from $emasrv.  Did you authenticate with tenant admin credentials?"}
}

# Get AMT provisioning certificates
function Get-Certificates {
 $reauth = $null
 If ([string]::IsNullOrEmpty($user)) {
  $reauth = $false
 } Else {
  $reauth = $true
 }
 If ($reauth -eq $true) {
  Get-AuthToken
 }
 $env:token = [System.Environment]::GetEnvironmentVariable("token","User")
 $env:fqdn = [System.Environment]::GetEnvironmentVariable("fqdn","User")
 $emasrv = $env:fqdn
 $headers = @{'Authorization' = 'Bearer ' + $env:token}
 try {
  $amtcertificateid = ((Invoke-RestMethod -Uri https://$emasrv/api/latest/amtprovisioningCertificates -ContentType 'application/json' -Method GET -Headers $headers) | Where-Object -Property IsAmtProvisioningCert -eq True | Select-Object -Expand AmtCertificateId)
  $amtcertificatename = ((Invoke-RestMethod -Uri https://$emasrv/api/latest/amtprovisioningCertificates -ContentType 'application/json' -Method GET -Headers $headers) | Where-Object -Property IsAmtProvisioningCert -eq True | Select-Object -Expand Name)
  Write-Host "AMT Certificate name: $amtcertificatename"
  Write-Host "AMT Certificate ID  : $amtcertificateid"
 }
 catch {Write-Host -Foreground Yellow "Unable to get certificate list from $emasrv.  Did you authenticate with proper credentials?"}
}

# Get tenant admins
function Get-TenantAdmins {
 If ([string]::IsNullOrEmpty($tenantname)) {
  Write-Host -Foreground Yellow "You must specify the name of the tenant that you want to retrieve admins for with -tenantname."
  Return
 }
 $reauth = $null
 If ([string]::IsNullOrEmpty($user)) {
  $reauth = $false
 } Else {
  $reauth = $true
 }
 If ($reauth -eq $true) {
  Get-AuthToken
 }
 $env:token = [System.Environment]::GetEnvironmentVariable("token","User")
 $env:fqdn = [System.Environment]::GetEnvironmentVariable("fqdn","User")
 $emasrv = $env:fqdn
 $headers = @{'Authorization' = 'Bearer ' + $env:token}
 try {
  $tenantid = ((Invoke-RestMethod -Uri https://$emasrv/api/latest/tenants -Method GET -Headers $headers) | Where-Object -Property Name -eq $tenantname | Select-Object -Expand TenantId)
  $roleid = ((Invoke-RestMethod -Uri https://$emasrv/api/latest/roles -ContentType 'application/json' -Method GET -Headers $headers) | Where-Object -Property TenantId -eq $tenantid | Where-Object -Property Name -eq "Tenant Administrator" | Select-Object -Expand RoleId)
  $userid = ((Invoke-RestMethod -Uri https://$emasrv/api/latest/users -ContentType 'application/json' -Method GET -Headers $headers) | Where-Object -Property TenantId -eq $tenantid | Where-Object -Property RoleId -eq $roleid | Select-Object -Expand UserId)
  $tenantadmin = ((Invoke-RestMethod -Uri https://$emasrv/api/latest/users -ContentType 'application/json' -Method GET -Headers $headers) | Where-Object -Property TenantId -eq $tenantid | Where-Object -Property RoleId -eq $roleid | Select-Object -Expand Username)
  Write-Host "Tenant admin username: $tenantadmin"
  Write-Host "Tenant admin user ID : $userid"
 }
 catch {Write-Host -Foreground Yellow "Unable to get tenant admins from $emasrv.  Did you authenticate with proper credentials?"}
}

# Clear data from variables
function Clear-Data {
 try {
  [Environment]::SetEnvironmentVariable('token', $null,'User')
  [Environment]::SetEnvironmentVariable('fqdn', $null,'User')
  [Environment]::SetEnvironmentVariable('noverify', $null,'User')
  [Environment]::SetEnvironmentVariable('nologging', $null,'User')
  $env:token = [System.Environment]::GetEnvironmentVariable("token","User")
  $env:fqdn = [System.Environment]::GetEnvironmentVariable("fqdn","User")
  $env:noverify = [System.Environment]::GetEnvironmentVariable("noverify","User")
  $env:nologging = [System.Environment]::GetEnvironmentVariable("nologging","User")
  Write-Host -Foreground Green "Connection data successfully cleared from memory."
 }
 catch {Write-Host -Foreground Yellow "Something went wrong and this is odd, we shouldn't see this message...EVER."}
}

# Execution actions or help strings as specified with arguments
# Set certificate handling first if -noverify option set to true
# If run as a script, clearing of the TrustAllCertsPolicy requires closing the PowerShell session
If ($noverify) {
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

# Set logging option for the session
If ($nologging) {
 $output = {Out-Null}
} ElseIf (![string]::IsNullOrEmpty($logfile)) {
 $output = {Out-File -FilePath $logfile -Encoding ASCII -Append}
} Else {
 $output = {Out-File -FilePath $env:temp\EmaConfigLog_$(get-date -f yyyy-MM-dd).txt -Encoding ASCII -Append}
}

# Call function based on first argument passed
If ($action -eq "Get-ADAuthToken") {
 Get-ADAuthToken
} ElseIf ($action -eq "Get-NAAuthToken") {
 Get-NAAuthToken
} ElseIf ($action -eq "Get-AuthToken") {
 Get-AuthToken
} ElseIf ($action -eq "Create-Tenant") {
 Create-Tenant
} ElseIf ($action -eq "Create-TenantAdmin") {
 Create-TenantAdmin
} ElseIf ($action -eq "Create-AMTProfile") {
 Create-AMTProfile
} ElseIf ($action -eq "Create-EndPointGroup") {
 Create-EndPointGroup
} ElseIf ($action -eq "Upload-Certificate") {
 Upload-Certificate
} ElseIf ($action -eq "Enable-ACMAutoSetup") {
 Enable-ACMAutoSetup
} ElseIf ($action -eq "Enable-CCMAutoSetup") {
 Enable-CCMAutoSetup
} ElseIf ($action -eq "Get-Tenants") {
 Get-Tenants
} ElseIf ($action -eq "Get-AMTProfiles") {
 Get-AMTProfiles
} ElseIf ($action -eq "Get-EndPointGroups") {
 Get-EndPointGroups
} ElseIf ($action -eq "Get-Certificates") {
 Get-Certificates
} ElseIf ($action -eq "Get-TenantAdmins") {
 Get-TenantAdmins
} ElseIf ($action -eq "Clear-Data") {
 Clear-Data
} ElseIf ($action -eq "Help" -And $helpparam -eq "Get-ADAuthToken" ) {
 Write-Host "$getadauthtokenhelp"
} ElseIf ($action -eq "Help" -And $helpparam -eq "Get-NAAuthToken") {
 Write-Host "$getnaauthtokenhelp"
} ElseIf ($action -eq "Help" -And $helpparam -eq "Get-AuthToken") {
 Write-Host "$getauthtokenhelp"
} ElseIf ($action -eq "Help" -And $helpparam -eq "Create-Tenant") {
 Write-Host "$createtenanthelp"
} ElseIf ($action -eq "Help" -And $helpparam -eq "Create-TenantAdmin") {
 Write-Host "$createtenantadminhelp"
} ElseIf ($action -eq "Help" -And $helpparam -eq "Create-AMTProfile") {
 Write-Host "$createamtprofilehelp"
} ElseIf ($action -eq "Help" -And $helpparam -eq "Create-EndPointGroup") {
 Write-Host "$createendpointgrouphelp"
} ElseIf ($action -eq "Help" -And $helpparam -eq "Upload-Certificate") {
 Write-Host "$uploadcertificatehelp"
} ElseIf ($action -eq "Help" -And $helpparam -eq "Enable-ACMAutoSetup") {
 Write-Host "$enableacmautosetuphelp"
} ElseIf ($action -eq "Help" -And $helpparam -eq "Enable-CCMAutoSetup") {
 Write-Host "$enableccmautosetuphelp"
} ElseIf ($action -eq "Help" -And $helpparam -eq "Get-Tenants") {
 Write-Host "$gettenantshelp"
} ElseIf ($action -eq "Help" -And $helpparam -eq "Get-AMTProfiles") {
 Write-Host "$getamtprofileshelp"
} ElseIf ($action -eq "Help" -And $helpparam -eq "Get-EndPointGroups") {
 Write-Host "$getendpointgroupshelp"
} ElseIf ($action -eq "Help" -And $helpparam -eq "Get-Certificates") {
 Write-Host "$getcertificateshelp"
} ElseIf ($action -eq "Help" -And $helpparam -eq "Get-TenantAdmins") {
 Write-Host "$gettenantadminshelp"
} ElseIf ($action -eq "Help" -And $helpparam -eq "Clear-Data") {
 Write-Host "$cleardatahelp"
} ElseIf ($action -eq "Help") {
 Write-Host " This utility can configure Intel(R) EMA implementations with a basic configuration.
 
 The Get-ADAuthToken, Get-NAAuthToken or Get-AuthToken actions set values that will be used in subsequent
 executions.  You will need to execute the authentication actions to set the values for the Intel(R) EMA
 server FQDN and the authentication token.  Perform the first authentication action as the global
 administrator so that you have the necessary rights to create a tenant and tenant administrator.  You
 will need to execute the appropriate authentication action again using a tenant administrator account to
 perform the AMT profile, Endpoint group, certificate upload and AMT autosetup actions.

 General usage guidelines:
 Enclose strings with spaces and/or special characters in single quotes such as: -tenantname `'Name w Space'`
 Include -server, -user and -password with any command to re-authenticate to the Intel(R) EMA Server
 Include -noverify with any action to bypass certificate validation  
  
 This utility supports the following actions:
 $getadauthtokenhelp
 $getnaauthtokenhelp
 $getauthtokenhelp
 $createtenanthelp
"
 Read-Host -Prompt "Press enter to continue or CTRL+C to exit..."
 Write-Host -NoNewLine " $createtenantadminhelp
 $createamtprofilehelp
 $createendpointgrouphelp
 $uploadcertificatehelp
"
 Read-Host -Prompt "Press enter to continue or CTRL+C to exit..."
 Write-Host -NoNewLine " $enableacmautosetuphelp
 $enableccmautosetuphelp
 
 The following actions are optional and may be required if using this utility against an Intel(R) EMA installation
 that has, at least, a partial configuration.
 $gettenantshelp
 $getamtprofileshelp
"
 Read-Host -Prompt "Press enter to continue or CTRL+C to exit..."
 Write-Host -NoNewLine " $getendpointgroupshelp
 $getcertificateshelp
 $gettenantadminshelp
 $cleardatahelp

 The following are the supported switches that can be used with actions.  Use ""Help"" ""Action"" to see how a specifc
 action and switch can be used. 
 $switcheshelp"
} ElseIf ($hidden) {
 Write-Host $hiddenhelpstring
} Else {
 Write-Host " Must specify one action.  Available actions:

 Help				Displays help
 Get-ADAuthToken		Get an authentication token using an Active Directory account
 Get-NAAuthToken		Get an authentication token using a normal account
 Get-AuthToken			Get an authentication token by attempting AD auth and then normal account auth
 Create-Tenant			Creates a tenant
 Create-TenantAdmin		Creates a tenant administrator
 Create-AMTProfile		Creates an AMT profile
 Create-EndPointGroup		Creates an endpoint group
 Upload-Certificate		Uploads a certificate
 Enable-ACMAutoSetup		Enables admin control mode auto-setup for an endpoint group
 Enable-CCMAutoSetup		Enables client control mode auto-setup for an endpoint group
 Get-Tenants			Gets a list of tenants
 Get-AMTProfiles		Gets a list of AMT profiles
 Get-EndPointGroups		Gets a list of endpoint groups
 Get-Certificates		Gets a list of AMT provisioning certificates
 Get-TenantAdmins		Gets a list of tenant admins for the specified tenant
 Clear-Data			Clears any connection data from memory

 Use action ""Help"" to see help for all actions or ""Help"" ""Action"" for a specifc action.

 The following are the supported switches that can be used with actions.  Use ""Help"" ""Action"" to see how a specifc
 action and switch can be used. 
 $switcheshelp

 Examples:
 EmaSvrConfig.ps1 Help Get-AuthToken
 EmaSvrConfig.ps1 Get-AuthToken -ad -server ema.domain.com -user admin@domain.com -password SecurePass
 EmaSvrConfig.ps1 Create-Tenant -tenantname `'Tenant Name'` "
} 

# SIG # Begin signature block
# MIIOAgYJKoZIhvcNAQcCoIIN8zCCDe8CAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUX0T2CcFdVosvhXlqcJWhhZnw
# bSugggs4MIIFUDCCBDigAwIBAgIRAL3ZO0mtD/Zp6SSUdJ6onIEwDQYJKoZIhvcN
# AQELBQAwfTELMAkGA1UEBhMCR0IxGzAZBgNVBAgTEkdyZWF0ZXIgTWFuY2hlc3Rl
# cjEQMA4GA1UEBxMHU2FsZm9yZDEaMBgGA1UEChMRQ09NT0RPIENBIExpbWl0ZWQx
# IzAhBgNVBAMTGkNPTU9ETyBSU0EgQ29kZSBTaWduaW5nIENBMB4XDTIxMDUyNjAw
# MDAwMFoXDTIyMDUyNjIzNTk1OVowgY4xCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApD
# YWxpZm9ybmlhMRQwEgYDVQQHDAtTYW50YSBDbGFyYTEaMBgGA1UECgwRSW50ZWwg
# Q29ycG9yYXRpb24xHDAaBgNVBAsME1VuaXRlIERlbW8gS2V5IDIwMjExGjAYBgNV
# BAMMEUludGVsIENvcnBvcmF0aW9uMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
# CgKCAQEAq+xIHn0qI21C+8hn9T4/GIBq+g5qzaH5wdjGusYepkwXPRFzCjL5wuEL
# z6akC2w577vuxVbguE6NJrZFaVjNKDlMfHilmrczPou1hK84E3+YSgVIMSAM/A8a
# FPZTqf1iv5T7icJdeRkAapmIec5L86WHbMzIl3oEm7WdtHeVuPIJ22XMkn8LsdTk
# eYDSg0Ui/cDPdBw0RE0UMq2EbHy+5zVfhMgmbdjSai6CrxXfhxO5l3Q4GU0IoEUk
# uSGa6zan5f1hlP9A/GvXekIuJkYh/cQ2kK+3kAW1YKd82AiApchszeQvr6ASL4dk
# +ioTrGp+ja9XsvkMVjok/s8YFNUitwIDAQABo4IBtzCCAbMwHwYDVR0jBBgwFoAU
# KZFg/4pN+uv5pmq4z/nmS71JzhIwHQYDVR0OBBYEFMA8J2zz3fs5+PkMDqMtdnEk
# JhzWMA4GA1UdDwEB/wQEAwIHgDAMBgNVHRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsG
# AQUFBwMDMBEGCWCGSAGG+EIBAQQEAwIEEDBKBgNVHSAEQzBBMDUGDCsGAQQBsjEB
# AgEDAjAlMCMGCCsGAQUFBwIBFhdodHRwczovL3NlY3RpZ28uY29tL0NQUzAIBgZn
# gQwBBAEwQwYDVR0fBDwwOjA4oDagNIYyaHR0cDovL2NybC5jb21vZG9jYS5jb20v
# Q09NT0RPUlNBQ29kZVNpZ25pbmdDQS5jcmwwdAYIKwYBBQUHAQEEaDBmMD4GCCsG
# AQUFBzAChjJodHRwOi8vY3J0LmNvbW9kb2NhLmNvbS9DT01PRE9SU0FDb2RlU2ln
# bmluZ0NBLmNydDAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuY29tb2RvY2EuY29t
# MCQGA1UdEQQdMBuBGWhlY3Rvci5iZWphcmFub0BpbnRlbC5jb20wDQYJKoZIhvcN
# AQELBQADggEBAB6VlnQXzU/inYA8QZPhU7tztsAqkqIOvD676uWnbD8GuOjBufUr
# G+6bcyT/83wBYoVGbT2fV6KQ/b26HABuchJdck93yQ2O1LTVHDxOWCKvgtKmyD27
# /XKIYuTmCxvcHD9mPZTAc8m02DFoRq38fVvVSsKULR8y01Gt2CLpvjZ2KpQHosIg
# uOv5OMv+GT0D8WY/prJv6fcl2GPMCm7Idq+JharQjO+NPO1kBwLYszHmjMyiJBHt
# HLzzQ5K7Zeqyc4DeO25xN4Qup8KD3yjpHAbJixH9zAjPcxqdBZkwTHPmzzhI2I44
# SnbtaGz6sqQycEQ0IfwYhQTI/AeEUdW4vMQwggXgMIIDyKADAgECAhAufIfMDpNK
# Uv6U/Ry3zTSvMA0GCSqGSIb3DQEBDAUAMIGFMQswCQYDVQQGEwJHQjEbMBkGA1UE
# CBMSR3JlYXRlciBNYW5jaGVzdGVyMRAwDgYDVQQHEwdTYWxmb3JkMRowGAYDVQQK
# ExFDT01PRE8gQ0EgTGltaXRlZDErMCkGA1UEAxMiQ09NT0RPIFJTQSBDZXJ0aWZp
# Y2F0aW9uIEF1dGhvcml0eTAeFw0xMzA1MDkwMDAwMDBaFw0yODA1MDgyMzU5NTla
# MH0xCzAJBgNVBAYTAkdCMRswGQYDVQQIExJHcmVhdGVyIE1hbmNoZXN0ZXIxEDAO
# BgNVBAcTB1NhbGZvcmQxGjAYBgNVBAoTEUNPTU9ETyBDQSBMaW1pdGVkMSMwIQYD
# VQQDExpDT01PRE8gUlNBIENvZGUgU2lnbmluZyBDQTCCASIwDQYJKoZIhvcNAQEB
# BQADggEPADCCAQoCggEBAKaYkGN3kTR/itHd6WcxEevMHv0xHbO5Ylc/k7xb458e
# JDIRJ2u8UZGnz56eJbNfgagYDx0eIDAO+2F7hgmz4/2iaJ0cLJ2/cuPkdaDlNSOO
# yYruGgxkx9hCoXu1UgNLOrCOI0tLY+AilDd71XmQChQYUSzm/sES8Bw/YWEKjKLc
# 9sMwqs0oGHVIwXlaCM27jFWM99R2kDozRlBzmFz0hUprD4DdXta9/akvwCX1+XjX
# jV8QwkRVPJA8MUbLcK4HqQrjr8EBb5AaI+JfONvGCF1Hs4NB8C4ANxS5Eqp5klLN
# hw972GIppH4wvRu1jHK0SPLj6CH5XkxieYsCBp9/1QsCAwEAAaOCAVEwggFNMB8G
# A1UdIwQYMBaAFLuvfgI9+qbxPISOre44mOzZMjLUMB0GA1UdDgQWBBQpkWD/ik36
# 6/mmarjP+eZLvUnOEjAOBgNVHQ8BAf8EBAMCAYYwEgYDVR0TAQH/BAgwBgEB/wIB
# ADATBgNVHSUEDDAKBggrBgEFBQcDAzARBgNVHSAECjAIMAYGBFUdIAAwTAYDVR0f
# BEUwQzBBoD+gPYY7aHR0cDovL2NybC5jb21vZG9jYS5jb20vQ09NT0RPUlNBQ2Vy
# dGlmaWNhdGlvbkF1dGhvcml0eS5jcmwwcQYIKwYBBQUHAQEEZTBjMDsGCCsGAQUF
# BzAChi9odHRwOi8vY3J0LmNvbW9kb2NhLmNvbS9DT01PRE9SU0FBZGRUcnVzdENB
# LmNydDAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuY29tb2RvY2EuY29tMA0GCSqG
# SIb3DQEBDAUAA4ICAQACPwI5w+74yjuJ3gxtTbHxTpJPr8I4LATMxWMRqwljr6ui
# 1wI/zG8Zwz3WGgiU/yXYqYinKxAa4JuxByIaURw61OHpCb/mJHSvHnsWMW4j71RR
# LVIC4nUIBUzxt1HhUQDGh/Zs7hBEdldq8d9YayGqSdR8N069/7Z1VEAYNldnEc1P
# AuT+89r8dRfb7Lf3ZQkjSR9DV4PqfiB3YchN8rtlTaj3hUUHr3ppJ2WQKUCL33s6
# UTmMqB9wea1tQiCizwxsA4xMzXMHlOdajjoEuqKhfB/LYzoVp9QVG6dSRzKp9L9k
# R9GqH1NOMjBzwm+3eIKdXP9Gu2siHYgL+BuqNKb8jPXdf2WMjDFXMdA27Eehz8uL
# qO8cGFjFBnfKS5tRr0wISnqP4qNS4o6OzCbkstjlOMKo7caBnDVrqVhhSgqXtEtC
# tlWdvpnncG1Z+G0qDH8ZYF8MmohsMKxSCZAWG/8rndvQIMqJ6ih+Mo4Z33tIMx7X
# ZfiuyfiDFJN2fWTQjs6+NX3/cjFNn569HmwvqI8MBlD7jCezdsn05tfDNOKMhyGG
# Yf6/VXThIXcDCmhsu+TJqebPWSXrfOxFDnlmaOgizbjvmIVNlhE8CYrQf7woKBP7
# aspUjZJczcJlmAaezkhb1LU3k0ZBfAfdz/pD77pnYf99SeC7MH1cgOPmFjlLpzGC
# AjQwggIwAgEBMIGSMH0xCzAJBgNVBAYTAkdCMRswGQYDVQQIExJHcmVhdGVyIE1h
# bmNoZXN0ZXIxEDAOBgNVBAcTB1NhbGZvcmQxGjAYBgNVBAoTEUNPTU9ETyBDQSBM
# aW1pdGVkMSMwIQYDVQQDExpDT01PRE8gUlNBIENvZGUgU2lnbmluZyBDQQIRAL3Z
# O0mtD/Zp6SSUdJ6onIEwCQYFKw4DAhoFAKB4MBgGCisGAQQBgjcCAQwxCjAIoAKA
# AKECgAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFNP2dPwbwWiVwtyEWMPAh9wB
# h2xhMA0GCSqGSIb3DQEBAQUABIIBAJCK1tZsXCro+0wU/vHKPSoxvE/fKSpnD0/F
# 41qUtgEVImU+CxraXVDBBACPwcaaCTfcNOkPeRQ0/qWeJr9Ciq6lE/a7BAA+Tsbr
# CEzUYzQDko7XKCIFGxDJ6TriPU0DmM/gVxDsX/QjmsBOSlmPuIyjtykKc7WlnEtI
# K4MCsvMwgKJISZtWs9YwYp/quIM1Bvf112jhUp8yiIS2zXuJZUrISmunrJu6m0IC
# ndIm9pRjhMmlmpebYQjQnJ2laSY/SpnGSNmWfbdaWzoPBW9Kw6+A51nyJf8nIUGj
# bkCQECG5VrNzE91gEhSWOIB62rMBLTXUFcNqP4JC6totFi4Zplc=
# SIG # End signature block

Configuration EMAInstall
{

    param
    (
        [Parameter(Mandatory)]
        [String]$hostname,

        [Parameter(Mandatory)]
        [String]$vmName,
       
        [Parameter(Mandatory)]
        [String]$tenantName,

        [Parameter(Mandatory)]
        [String]$adJoin,
       
        [Parameter(Mandatory)]
        [String]$adDomain,
       
        [Parameter(Mandatory)]
        [String]$adDNSpri,
       
        [Parameter(Mandatory)]
        [String]$adDNSsec,
       
        [Parameter(Mandatory)]
        [String]$serverName,
       
        [Parameter(Mandatory)]
        [String]$sqlDBName,
       
        [Parameter(Mandatory)]
        [String]$templateEdition = "advanced",
       
        [Parameter(Mandatory = $false)]
        [String]$azureSql = $true,
       
        [Parameter(Mandatory = $false)]
        [String]$localSql = $false,
       
        [Parameter(Mandatory)]
        [System.Management.Automation.PSCredential]$epgCred,
       
        [Parameter(Mandatory)]
        [System.Management.Automation.PSCredential]$autoCred,
       
        [Parameter(Mandatory)]
        [System.Management.Automation.PSCredential]$globalCred,
       
        [Parameter(Mandatory)]
        [System.Management.Automation.PSCredential]$adCred,
       
        [Parameter(Mandatory)]
        [System.Management.Automation.PSCredential]$sqlCred,
       
        [Parameter(Mandatory)]
        [System.Management.Automation.PSCredential]$adminCred,
       
        [Parameter(Mandatory)]
        [System.Management.Automation.PSCredential]$tenantCred
    ) # end param

    Import-DscResource -ModuleName PSDesiredStateConfiguration

    $certInstall = '    # Script to update certificate bindings in IIS after certificate renewal
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
    $globalUsername = $globalCred.UserName
    $globalPassword = $globalCred.Password
    $gPassPlainText = $globalCred.GetNetworkCredential().Password
    $tenantUsername = $tenantCred.UserName
    $tenantPassword = $tenantCred.Password
    $tPassPlainText = $tenantCred.GetNetworkCredential().Password
    $adUsername = $adCred.UserName
    $adPassword = $adCred.Password
    $adPassPlainText = $adCred.GetNetworkCredential().Password
    $sqlUsername = $sqlCred.UserName
    $sqlPassword = $sqlCred.Password
    $sqlPassPlainText = $sqlCred.GetNetworkCredential().Password
    $epgName = $epgCred.UserName
    $epgPasswordSecure = $epgCred.Password
    $epgPassword = $epgCred.GetNetworkCredential().Password
    $profileName = $autoCred.UserName
    $autoPasswordSecure = $autoCred.Password
    $autoPassword = $autoCred.GetNetworkCredential().Password
    If ($templateEdition -eq "advanced" -And $azureSql -eq $true) {
        $testserverName = $serverName.Contains('.database.windows.net')
        If ($testserverName -eq $false) {
            $serverNameFQDN = "$serverName.database.windows.net"
        } ElseIf ($testserverName -eq $true) {
            $serverNameFQDN = $serverName
        }
    }
    If ($localSql -eq $true) {
        $serverNameFQDN = $serverName
    }
    If ($templateEdition -eq "advanced") {
        If ($adJoin -eq $true -And ($azureSql -eq $true -Or $localSql -eq $true)) {
            $emaArgs = @("FULLINSTALL","--isdistributedserverinit","--swarmlbhost=$hostname","--swarmlbip=127.0.0.1","--ajaxlbhost=$hostname","--ajaxlbip=127.0.0.1","--recoverylbhost=$hostname","--recoverylbip=127.0.0.1","--emaip=127.0.0.1","--hostfirst","--dbserver=$serverNameFQDN","--db=$sqlDBName","--dbuser=$sqlUsername","--dbpass=$sqlPassPlainText","--guser=$globalUsername","--domainauth","--deployajaxandweb","--deploymanageability","--deployswarm","--deployrecovery","--accepteula","--autoexit","--verbose")
            $installcred = $adCred
        } ElseIf ($adJoin -eq $false -And ($azureSql -eq $true -Or $localSql -eq $true)) {
            $emaArgs = @("FULLINSTALL","--isdistributedserverinit","--swarmlbhost=$hostname","--swarmlbip=127.0.0.1","--ajaxlbhost=$hostname","--ajaxlbip=127.0.0.1","--recoverylbhost=$hostname","--recoverylbip=127.0.0.1","--emaip=127.0.0.1","--hostfirst","--dbserver=$serverNameFQDN","--db=$sqlDBName","--dbuser=$sqlUsername","--dbpass=$sqlPassPlainText","--guser=$globalUsername","--gpass=$gPassPlainText","--deployajaxandweb","--deploymanageability","--deployswarm","--deployrecovery","--accepteula","--autoexit","--verbose")
            $installcred = $adminCred
        } ElseIf ($adJoin -eq $true -And $azureSql -eq $false -And $localSql -eq $false) {
            $serverNameFQDN = $serverName
            $emaArgs = @("FULLINSTALL","--isdistributedserverinit","--swarmlbhost=$hostname","--swarmlbip=127.0.0.1","--ajaxlbhost=$hostname","--ajaxlbip=127.0.0.1","--recoverylbhost=$hostname","--recoverylbip=127.0.0.1","--emaip=127.0.0.1","--hostfirst","--dbserver=$serverNameFQDN","--db=$sqlDBName","--guser=$globalUsername","--domainauth","--deployajaxandweb","--deploymanageability","--deployswarm","--deployrecovery","--accepteula","--autoexit","--verbose")
            $installcred = $adminCred
        } ElseIf ($adJoin -eq $false -And $azureSql -eq $false -And $localSql -eq $false) {
            $serverNameFQDN = $serverName
            $emaArgs = @("FULLINSTALL","--isdistributedserverinit","--swarmlbhost=$hostname","--swarmlbip=127.0.0.1","--ajaxlbhost=$hostname","--ajaxlbip=127.0.0.1","--recoverylbhost=$hostname","--recoverylbip=127.0.0.1","--emaip=127.0.0.1","--hostfirst","--dbserver=$serverNameFQDN","--db=$sqlDBName","--guser=$globalUsername","--gpass=$gPassPlainText","--deployajaxandweb","--deploymanageability","--deployswarm","--deployrecovery","--accepteula","--autoexit","--verbose")
            $installcred = $adminCred
        }
        If ($adJoin -eq $true) {
            # $emaArgs = @("FULLINSTALL","--isdistributedserverinit","--swarmlbhost=$hostname","--swarmlbip=127.0.0.1","--ajaxlbhost=$hostname","--ajaxlbip=127.0.0.1","--recoverylbhost=$hostname","--recoverylbip=127.0.0.1","--emaip=127.0.0.1","--hostfirst","--dbserver=$serverNameFQDN","--db=$sqlDBName","--dbuser=$sqlUsername","--dbpass=$sqlPassPlainText","--guser=$globalUsername","--domainauth","--deployajaxandweb","--deploymanageability","--deployswarm","--deployrecovery","--accepteula","--autoexit","--verbose")
            $configoneargs = "C:\Packages\EMA\EmaSvrConfig.ps1 Get-ADAuthToken -noverify -server $hostname -user $globalUsername -password '{0}'" -f $gPassPlainText
            $configthreeargs = "C:\Packages\EMA\EmaSvrConfig.ps1 Create-TenantAdmin -noverify -tenantname '{0}' -tausername $tenantUsername" -f $tenantName 
            $configfourargs = "C:\Packages\EMA\EmaSvrConfig.ps1 Get-ADAuthToken -noverify -server $hostname -user $tenantUsername -password '{0}'" -f $tPassPlainText
        } ElseIf ($adJoin -eq $false) {
            # $emaArgs = @("FULLINSTALL","--isdistributedserverinit","--swarmlbhost=$hostname","--swarmlbip=127.0.0.1","--ajaxlbhost=$hostname","--ajaxlbip=127.0.0.1","--recoverylbhost=$hostname","--recoverylbip=127.0.0.1","--emaip=127.0.0.1","--hostfirst","--dbserver=$serverNameFQDN","--db=$sqlDBName","--dbuser=$sqlUsername","--dbpass=$sqlPassPlainText","--guser=$globalUsername","--gpass=$gPassPlainText","--deployajaxandweb","--deploymanageability","--deployswarm","--deployrecovery","--accepteula","--autoexit","--verbose")
            $configoneargs = "C:\Packages\EMA\EmaSvrConfig.ps1 Get-NAAuthToken -noverify -server $hostname -user $globalUsername -password '{0}'" -f $gPassPlainText
            $configthreeargs = "C:\Packages\EMA\EmaSvrConfig.ps1 Create-TenantAdmin -noverify -tenantname '{0}' -tausername $tenantUsername -tapassword '{1}'" -f $tenantName,$tPassPlainText 
            $configfourargs = "C:\Packages\EMA\EmaSvrConfig.ps1 Get-NAAuthToken -noverify -server $hostname -user $tenantUsername -password '{0}'" -f $tPassPlainText
        }
    } Elseif ($templateEdition -eq "simple") {
        $serverNameFQDN = $serverName
        $emaArgs = @("FULLINSTALL","--isdistributedserverinit","--swarmlbhost=$hostname","--swarmlbip=127.0.0.1","--ajaxlbhost=$hostname","--ajaxlbip=127.0.0.1","--recoverylbhost=$hostname","--recoverylbip=127.0.0.1","--emaip=127.0.0.1","--hostfirst","--dbserver=$serverNameFQDN","--db=$sqlDBName","--guser=$globalUsername","--gpass=$gPassPlainText","--deployajaxandweb","--deploymanageability","--deployswarm","--deployrecovery","--accepteula","--autoexit","--verbose")
        $configoneargs = "C:\Packages\EMA\EmaSvrConfig.ps1 Get-NAAuthToken -noverify -server $hostname -user $globalUsername -password '{0}'" -f $gPassPlainText
        $configthreeargs = "C:\Packages\EMA\EmaSvrConfig.ps1 Create-TenantAdmin -noverify -tenantname '{0}' -tausername $tenantUsername -tapassword '{1}'" -f $tenantName,$tPassPlainText 
        $configfourargs = "C:\Packages\EMA\EmaSvrConfig.ps1 Get-NAAuthToken -noverify -server $hostname -user $tenantUsername -password '{0}'" -f $tPassPlainText
        $installcred = $adminCred
    }
    $configtwoargs = "C:\Packages\EMA\EmaSvrConfig.ps1 Create-Tenant -noverify -tenantname '{0}'" -f $tenantName
    $configfiveargs = "C:\Packages\EMA\EmaSvrConfig.ps1 Create-AMTProfile -noverify -profilename '{0}'" -f $profileName 
    $configsixargs = "C:\Packages\EMA\EmaSvrConfig.ps1 Create-EndPointGroup -noverify -epgname '{0}' -epgpassword '{1}'" -f $epgName,$epgPassword
    $configsevenargs = "C:\Packages\EMA\EmaSvrConfig.ps1 Enable-CCMAutoSetup -noverify -autopass '{0}' -epgname '{1}' -profilename '{2}'" -f $autoPassword,$epgName,$profileName 
    $configeightargs = "C:\Packages\EMA\EmaSvrConfig.ps1 Clear-Data"
    $certoneargs = "--source manual --host $hostname --emailaddress $globalUsername --webroot c:\inetpub\wwwroot --friendlyname ""Intel EMA Web Certificate"" --installation script --script C:\Packages\EMA\CertInstall.ps1 --accepttos"
    $certtwoargs = "C:\Packages\EMA\EmaDeploy.ps1 Install-URLReWrite"

    node localhost
    {

        LocalConfigurationManager
        {
            RebootNodeIfNeeded = $true
            ConfigurationMode = 'ApplyAndMonitor'
			ActionAfterReboot = 'ContinueConfiguration'
			AllowModuleOverwrite = $true
        }
        
        Script Domain_Join
        {
            SetScript = {

                try
                {
                    # Starting Active Directory join processes
                    Start-Sleep -s 10
                    $pkgdir = "$env:systemdrive\Packages\EMA"
                    If(!(test-path $pkgdir)){
                    New-Item -ItemType Directory -Force -Path $pkgdir
                    Write-Host "Working folder has been created"
                    Set-Content -Path "C:\Packages\EMA\Hostname.txt" -Value "Hostname used for this install: $using:hostname"
                    New-Item -Path HKLM:Software\Microsoft\PowerShell\3\ -Name DSC -Force
                    Get-Item -Path HKLM:Software\Microsoft\PowerShell\3\DSC | New-ItemProperty -Name "PSDscAllowPlainTextPassword" -Value "True"
                    Get-Item -Path HKLM:Software\Microsoft\PowerShell\3\DSC | New-ItemProperty -Name "PSDscAllowDomainUser" -Value "True"
                    }
                    If ($using:adJoin -eq $true) {
                        $ifindex = (Get-NetIPInterface | Where-Object AddressFamily -like "IPv4" | Where-Object Dhcp -like "Enabled" | Select-Object -Expand ifIndex)
                        $dnsalpha = $using:adDNSpri
                        $dnsbeta = $using:adDNSsec
                        Set-DnsClientServerAddress -InterfaceIndex $ifindex -ServerAddress ($dnsalpha, $dnsbeta)
                        $domain = $using:adDomain
                        Add-Computer -DomainName $domain -Credential $using:adCred
                        Add-LocalGroupMember -Group "Administrators" -Member "$using:adUsername"
                        Set-Content -Path "C:\Packages\EMA\Domain_Join_Complete.txt" -Value "Active Directory join is: $using:adJoin - Domain join operation completed."
                        shutdown -r -t 10 -f
                    } ElseIf ($using:adJoin -eq $false) {
                        Set-Content -Path "C:\Packages\EMA\Domain_Join_Complete.txt" -Value "Active Directory join is: $using:adJoin - Domain join not performed."
                    } 
                } # end try
                catch 
                {
                    # https://www.tutorialspoint.com/explain-try-catch-finally-block-in-powershell
                    Write-Host "An error ocurred! Please try again..."
                    Write-Host "Error in Line:" $_.Exception.Message
                    Write-Host "Error in Line Number:" $_.InvocationInfo.ScriptLineNumber 
                    Write-Host "Error ItemName:" $_.Exception.ItemName
                } # end catch
            } # end SetScript

            TestScript = {
               if (Test-Path "C:\Packages\EMA\Domain_Join_Complete.txt")
               {
                  Write-Verbose "Domain join has been executed."
                  return $true
               } # end If
               else
               {
                  Write-Host "Domain join has NOT been executed."
                  return $false
               } # end Else
            } # end TestScript
            
            GetScript = {
                $configlog = (Get-Content "C:\Packages\EMA\Domain_Join_Complete.txt")
                return @{ 'result' = "$configlog" }
            } # end GetScript
        } # end resource

        Script Install_Net_4.8
        {
            SetScript = {

                [int]$NetBuildVersion = 528040
                [int]$CurrentRelease = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full').Release
                If ($CurrentRelease -lt $NetBuildVersion) {
                $path = "C:\Packages\EMA"
                If (!(test-path $path)) {
                    New-Item -ItemType Directory -Force -Path $path
                }

                ## Download .NET 4.8 Installer
                $output = "C:\Packages\EMA\ndp48-x86-x64-allos-enu.exe"
                [int]$dc = 0
                do {
                    $hash = $null
                    $dc = $dc+1
                    Invoke-WebRequest -Uri https://go.microsoft.com/fwlink/?linkid=2088631 -OutFile $output
                    $hash = ((Get-FileHash -Path $output -Algorithm SHA1) | Select-Object -Expand Hash)
                    If ($dc -ge 3) {
                        Invoke-WebRequest -Uri https://emacloudstart.z13.web.core.windows.net/packages/net_framework_480.exe -OutFile $output
                        Break
                    }
                } until ($hash -eq 'E322E2E0FB4C86172C38A97DC6C71982134F0570')
                Start-Sleep -s 10
                try
                {
                    $args = "/q /x86 /x64 /redist /norestart"
                    $currentTime = Get-Date
                    Write-Host ".Net 4.8 install starting... $currentTime"
                    Start-Process -Filepath "C:\Packages\EMA\ndp48-x86-x64-allos-enu.exe" -ArgumentList $args -WorkingDirectory "C:\Packages\EMA" -Wait 
                    $currentTime = Get-Date
                    Write-Host ".Net 4.8 install complete.  $currentTime"
                    New-Item -Path HKLM:\SOFTWARE\MyMainKey\RebootKey -Force
                    $global:DSCMachineStatus = 1
                } # end try
                catch {Write-Host "An error occurred! Please try again..."}
                } # end if
            }
            TestScript = {

                return (Test-Path HKLM:\SOFTWARE\MyMainKey\RebootKey)

                [int]$NetBuildVersion = 528040

                if (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full' | ForEach-Object {$_ -match 'Release'})
                {
                    [int]$CurrentRelease = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full').Release
                    if ($CurrentRelease -lt $NetBuildVersion)
                    {
                        Write-Verbose "Current .Net build version is less than 4.8 ($CurrentRelease)"
                        return $false
                    }
                    else
                    {
                        Write-Verbose "Current .Net build version is the same as or higher than 4.8 ($CurrentRelease)"
                        return $true
                    }
                }
                else
                {
                    Write-Verbose ".Net build version not recognized"
                    return $false
                }
            }
            GetScript = {

                return @{result = 'result'}

                if (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full' | %{$_ -match 'Release'})
                {
                    $NetBuildVersion =  (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full').Release
                    return $NetBuildVersion
                }
                else
                {
                    Write-Verbose ".Net build version not recognised"
                    return ".Net 4.8 not found"
                }
            }
        } # end resource

        Script Install_EMA
        {
            SetScript = {
                # Check for and create temp directory if necessary.
                $pathEma = "C:\Packages\EMA"
                If(!(test-path $pathEma))
                {
                    New-Item -ItemType Directory -Force -Path $pathEma
                    Write-Host "Temp folder has been created"
                } # end if

                # Download EMA Install file
                $outputEma = "C:\Packages\EMA\EMAInstall.zip"
                [int]$dc = 0
                do {
                    $hash = $null
                    $dc = $dc+1
                    Invoke-WebRequest -Uri https://downloadmirror.intel.com/646990/Ema_Install_Package_1.8.1.0.exe -Method GET -OutFile $outputEma
                    $hash = ((Get-FileHash -Path $outputEma -Algorithm SHA1) | Select-Object -Expand Hash)
                    If ($dc -ge 3) {
                        Invoke-WebRequest -Uri https://emacloudstart.z13.web.core.windows.net/packages/Ema_Install_Package_1.8.1.0.exe -OutFile $outputEma
                        Break
                    }
                } until ($hash -eq 'E33EB0BA54A3AE2B8F1CBF4FC179112C810E619B')

                # Download IISCrypto
                [int]$dc = 0
                do {
                    $hash = $null
                    $dc = $dc+1
                    Invoke-WebRequest -Uri https://www.nartac.com/Downloads/IISCrypto/IISCryptoCli.exe -OutFile $pathEma\IISCrypto.exe
                    $hash = ((Get-FileHash -Path $pathEma\IISCrypto.exe -Algorithm SHA1) | Select-Object -Expand Hash)
                    If ($dc -ge 3) {
                        Invoke-WebRequest -Uri https://emacloudstart.z13.web.core.windows.net/packages/IISCryptoCli.exe -OutFile $pathEma\IISCrypto.exe
                        Break
                    }
                } until ($hash -eq 'BBF89060525125E70B96ED7512523A1594E02808')

                $targetInstallPath = "C:\Packages\EMA\EMAInstall" 
                if (-not(Test-Path -Path $targetInstallPath))
                {
                    add-type -AssemblyName System.IO.Compression.FileSystem
                    [system.io.compression.zipFile]::ExtractToDirectory('C:\Packages\EMA\EMAInstall.zip',$targetInstallPath)
                } # end if

                try
                {
                    $currentTimeEmaStart = Get-Date
                    Write-Host "EMA install starting... $currentTimeEmaStart"
                    Set-Content -Path "C:\Packages\EMA\SQLServer.txt" -Value "SQL server used for this install: $using:serverNameFQDN"
                    If (-not(Test-Path -Path "C:\ProgramData\Intel\EMA\USBR")) {
                        New-Item -ItemType "directory" -Path "C:\ProgramData\Intel\EMA\USBR"
                    }
                    $ipAddress = (Test-Connection -ComputerName (hostname) -Count 1  | Select -ExpandProperty IPV4Address).IPAddressToString
                    $emaArguments = $using:emaArgs -replace "127.0.0.1",$ipAddress
                    Start-Process -Filepath "C:\Packages\EMA\IISCrypto.exe" -Wait -NoNewWindow -ArgumentList '/template best'
                    # Pause to allow VM to become ready for EMA install
                    Start-Sleep 60
                    Start-Process -Filepath "C:\Packages\EMA\EMAInstall\EMAServerInstaller.exe" -ArgumentList $emaArguments -WorkingDirectory "C:\Packages\EMA\EMAInstall" -Wait
                    If ($using:templateEdition -eq "advanced" -And $using:azureSql -eq $true) {
                        Install-Module -Name SqlServer -Force
                        Start-Sleep 15
                        Invoke-Sqlcmd -ServerInstance $using:serverNameFQDN -Username $using:sqlUsername -Password $using:sqlPassPlainText -Query "ALTER DATABASE [$using:sqlDBName] MODIFY(EDITION='Standard' , SERVICE_OBJECTIVE='S0')"
                    }
                    $currentTimeEmaStop = Get-Date
                    Write-Host "EMA install process complete.  $currentTimeEmaStop"
                } # end try
                catch 
                {
                    # https://www.tutorialspoint.com/explain-try-catch-finally-block-in-powershell
                    Write-Host "An error ocurred! Please try again..."
                    Write-Host "Error in Line:" $_.Exception.Message
                    Write-Host "Error in Line Number:" $_.InvocationInfo.ScriptLineNumber 
                    Write-Host "Error ItemName:" $_.Exception.ItemName
                } # end catch
            } # end SetScript

            TestScript = {

                $script:targetServiceName = "PlatformManager"

                $checkForService = $null

                $checkForService = (Get-Service -Name $targetServiceName -ErrorAction SilentlyContinue).Name

                if ($checkForService -ne $targetServiceName)
                {
                    Write-Verbose "Intel Endpoint Management Assistant is not installed."
                    return $false
                } # end if
                else
                {
                    Write-Verbose "Intel Endpoint Management Assistant is installed."
                    return $true
                } # end else
            } # end TestScript
            
            GetScript = {
                $currentTargetService = ((Get-Service -Name $targetServiceName).Name)
                return @{ 'result' = "$currentTargetService" }
            } # end GetScript
            PsDscRunAsCredential = $installcred
            DependsOn = "[Script]Install_Net_4.8"
        } # end resource

        Script Config_EMA
        {
            SetScript = {

                try
                {
                    # Starting Intel EMA configuration
                    Start-Sleep -s 60
                    $pkgdir = "$env:systemdrive\Packages\EMA"
                    # Download configuration script
                    Invoke-WebRequest -Uri https://emacloudstart.z13.web.core.windows.net/EmaSvrConfig.ps1 -Method GET -OutFile $pkgdir\EmaSvrConfig.ps1
                    Start-Process -FilePath "powershell.exe" -ArgumentList $using:configoneargs -Wait -NoNewWindow -RedirectStandardOutput "C:\Packages\EMA\cmdout.txt"
                    (Get-Content "C:\Packages\EMA\cmdout.txt") | Out-File -FilePath "C:\Packages\EMA\Ema_Config_Log_$(get-date -f yyyy-MM-dd).txt" -Encoding Unicode -Append
                    Remove-Item "C:\Packages\EMA\cmdout.txt"
                    Start-Process -FilePath "powershell.exe" -ArgumentList $using:configtwoargs -Wait -NoNewWindow -RedirectStandardOutput "C:\Packages\EMA\cmdout.txt"
                    (Get-Content "C:\Packages\EMA\cmdout.txt") | Out-File -FilePath "C:\Packages\EMA\Ema_Config_Log_$(get-date -f yyyy-MM-dd).txt" -Encoding Unicode -Append
                    Remove-Item "C:\Packages\EMA\cmdout.txt"
                    Start-Process -FilePath "powershell.exe" -ArgumentList $using:configthreeargs -Wait -NoNewWindow -RedirectStandardOutput "C:\Packages\EMA\cmdout.txt"
                    (Get-Content "C:\Packages\EMA\cmdout.txt") | Out-File -FilePath "C:\Packages\EMA\Ema_Config_Log_$(get-date -f yyyy-MM-dd).txt" -Encoding Unicode -Append
                    Remove-Item "C:\Packages\EMA\cmdout.txt"
                    Start-Process -FilePath "powershell.exe" -ArgumentList $using:configfourargs -Wait -NoNewWindow -RedirectStandardOutput "C:\Packages\EMA\cmdout.txt"
                    (Get-Content "C:\Packages\EMA\cmdout.txt") | Out-File -FilePath "C:\Packages\EMA\Ema_Config_Log_$(get-date -f yyyy-MM-dd).txt" -Encoding Unicode -Append
                    Remove-Item "C:\Packages\EMA\cmdout.txt"
                    Start-Process -FilePath "powershell.exe" -ArgumentList $using:configfiveargs -Wait -NoNewWindow -RedirectStandardOutput "C:\Packages\EMA\cmdout.txt"
                    (Get-Content "C:\Packages\EMA\cmdout.txt") | Out-File -FilePath "C:\Packages\EMA\Ema_Config_Log_$(get-date -f yyyy-MM-dd).txt" -Encoding Unicode -Append
                    Remove-Item "C:\Packages\EMA\cmdout.txt"
                    Start-Process -FilePath "powershell.exe" -ArgumentList $using:configsixargs -Wait -NoNewWindow -RedirectStandardOutput "C:\Packages\EMA\cmdout.txt"
                    (Get-Content "C:\Packages\EMA\cmdout.txt") | Out-File -FilePath "C:\Packages\EMA\Ema_Config_Log_$(get-date -f yyyy-MM-dd).txt" -Encoding Unicode -Append
                    Remove-Item "C:\Packages\EMA\cmdout.txt"
                    Start-Process -FilePath "powershell.exe" -ArgumentList $using:configsevenargs -Wait -NoNewWindow -RedirectStandardOutput "C:\Packages\EMA\cmdout.txt"
                    (Get-Content "C:\Packages\EMA\cmdout.txt") | Out-File -FilePath "C:\Packages\EMA\Ema_Config_Log_$(get-date -f yyyy-MM-dd).txt" -Encoding Unicode -Append
                    Remove-Item "C:\Packages\EMA\cmdout.txt"
                    Start-Process -FilePath "powershell.exe" -ArgumentList $using:configeightargs -Wait -NoNewWindow -RedirectStandardOutput "C:\Packages\EMA\cmdout.txt"
                    (Get-Content "C:\Packages\EMA\cmdout.txt") | Out-File -FilePath "C:\Packages\EMA\Ema_Config_Log_$(get-date -f yyyy-MM-dd).txt" -Encoding Unicode -Append
                    Remove-Item "C:\Packages\EMA\cmdout.txt"
                    Set-Content -Path "C:\Packages\EMA\Ema_Config_Complete.txt" -Value "Intel EMA configuration operations completed."
                } # end try
                catch 
                {
                    # https://www.tutorialspoint.com/explain-try-catch-finally-block-in-powershell
                    Write-Host "An error ocurred! Please try again..."
                    Write-Host "Error in Line:" $_.Exception.Message
                    Write-Host "Error in Line Number:" $_.InvocationInfo.ScriptLineNumber 
                    Write-Host "Error ItemName:" $_.Exception.ItemName
                } # end catch
            } # end SetScript

            TestScript = {
               if (Test-Path "C:\Packages\EMA\Ema_Config_Complete.txt")
               {
                  Write-Verbose "Intel Endpoint Management Assistant configuration has been executed."
                  return $true
               } # end If
               else
               {
                  Write-Host "Intel Endpoint Management Assistant configuration has NOT been executed."
                  return $false
               } # end Else
            } # end TestScript
            
            GetScript = {
                $configlog = (Get-Content "C:\Packages\EMA\Ema_Config_Log_$(get-date -f yyyy-MM-dd).txt")
                return @{ 'result' = "$configlog" }
            } # end GetScript
            DependsOn = "[Script]Install_EMA"
        } # end resource

        Script EMA_Cert
        {
            SetScript = {

                try
                {
                    # Starting certificate configuration processes
                    Start-Sleep -s 10
                    $pkgdir = "$env:systemdrive\Packages\EMA"
                    If(!(test-path $pkgdir)){
                    New-Item -ItemType Directory -Force -Path $pkgdir
                    Write-Host "Working folder has been created"
                    }
                    # Download/create configuration and certificate scripts
                    Invoke-WebRequest -Uri https://emacloudstart.z13.web.core.windows.net/EmaDeploy.ps1 -Method GET -OutFile $pkgdir\EmaDeploy.ps1
                    Set-Content -Path $pkgdir\CertInstall.ps1 -Value $using:certInstall
                    [int]$dc = 0
                    do {
                      $hash = $null
                      $dc = $dc+1
                      Invoke-WebRequest -Uri https://github.com/win-acme/win-acme/releases/download/v2.1.22.1267/win-acme.v2.1.22.1267.x64.pluggable.zip -OutFile $pkgdir\winacme.zip
                      $hash = ((Get-FileHash -Path $pkgdir\winacme.zip -Algorithm SHA1) | Select-Object -Expand Hash)
                      If ($dc -ge 3) {
                        Invoke-WebRequest -Uri https://emacloudstart.z13.web.core.windows.net/packages/win-acme.v2.1.22.1267.x64.pluggable.zip -OutFile $pkgdir\winacme.zip
                        Break
                      }
                    } until ($hash -eq '11AA9EF5FF072FAD55F8358654A12B9EC974CDF6')
                    [int]$dc = 0
                    do {
                      $hash = $null
                      $dc = $dc+1
                      Invoke-WebRequest -Uri https://download.microsoft.com/download/1/2/8/128E2E22-C1B9-44A4-BE2A-5859ED1D4592/rewrite_amd64_en-US.msi -Method GET -OutFile $pkgdir\rewrite_amd64_en-US.msi
                      $hash = ((Get-FileHash -Path $pkgdir\rewrite_amd64_en-US.msi -Algorithm SHA1) | Select-Object -Expand Hash)
                      If ($dc -ge 3) {
                        Invoke-WebRequest -Uri https://emacloudstart.z13.web.core.windows.net/packages/rewrite_amd64_en-US.msi -Method GET -OutFile $pkgdir\rewrite_amd64_en-US.msi
                        Break
                      }
                    } until ($hash -eq '8F41A67FA49110155969DCCFF265B8623A66448F')
                    If (-not(Test-Path -Path "C:\Program Files\wacs")) {
                        New-Item -ItemType "directory" -Path "C:\Program Files\wacs"
                    }
                    Expand-Archive -LiteralPath "$pkgdir\winacme.zip" -DestinationPath "C:\Program Files\wacs"
                    Start-Process -FilePath "C:\Program Files\wacs\wacs.exe" -ArgumentList $using:certoneargs -Wait -NoNewWindow -RedirectStandardOutput "C:\Packages\EMA\cmdout.txt"
                    (Get-Content "C:\Packages\EMA\cmdout.txt") | Out-File -FilePath "C:\Packages\EMA\Ema_Config_Log_$(get-date -f yyyy-MM-dd).txt" -Encoding Unicode -Append
                    Remove-Item "C:\Packages\EMA\cmdout.txt"
                    Start-Process -FilePath "powershell.exe" -ArgumentList $using:certtwoargs -Wait -NoNewWindow -RedirectStandardOutput "C:\Packages\EMA\cmdout.txt"
                    (Get-Content "C:\Packages\EMA\cmdout.txt") | Out-File -FilePath "C:\Packages\EMA\Ema_Config_Log_$(get-date -f yyyy-MM-dd).txt" -Encoding Unicode -Append
                    Remove-Item "C:\Packages\EMA\cmdout.txt"
                    Set-Content -Path "C:\Packages\EMA\Ema_Cert_Complete.txt" -Value "Intel EMA certificate operations completed."
                } # end try
                catch 
                {
                    # https://www.tutorialspoint.com/explain-try-catch-finally-block-in-powershell
                    Write-Host "An error ocurred! Please try again..."
                    Write-Host "Error in Line:" $_.Exception.Message
                    Write-Host "Error in Line Number:" $_.InvocationInfo.ScriptLineNumber 
                    Write-Host "Error ItemName:" $_.Exception.ItemName
                } # end catch
            } # end SetScript

            TestScript = {
               if (Test-Path "C:\Packages\EMA\Ema_Cert_Complete.txt")
               {
                  Write-Verbose "Certificate configuration has been executed."
                  return $true
               } # end If
               else
               {
                  Write-Host "Certificate configuration has NOT been executed."
                  return $false
               } # end Else
            } # end TestScript
            
            GetScript = {
                $configlog = (Get-Content "C:\Packages\EMA\Ema_Installation_Log_$(get-date -f yyyy-MM-dd).txt")
                return @{ 'result' = "$configlog" }
            } # end GetScript
            DependsOn = "[Script]Config_EMA"
        } # end resource
    } # end node
} # end configuration

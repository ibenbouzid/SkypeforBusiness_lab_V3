#
# SfB_install.ps1
#
<# Custom Script for Windows #>
Param (		
		[Parameter(Mandatory)]
        [String]$DomainName,
        [Parameter(Mandatory)]
        [string]$Username,
	    [Parameter(Mandatory)]
        [string]$Password,
		[Parameter(Mandatory)]
        [string]$Share,
		[Parameter(Mandatory)]
        [string]$sasToken,
		[Parameter(Mandatory)]
        [string]$EdgeName,
		[Parameter(Mandatory)]
        [string]$EdgeIntIp,
		[Parameter(Mandatory)]
        [string]$EdgeExtIp,
		[Parameter(Mandatory)]
        [string]$EdgePubIp

       )

$SecurePassword = ConvertTo-SecureString -String $Password -AsPlainText -Force
[PSCredential ]$DomainCreds = New-Object PSCredential ("$DomainName\$Username", $SecurePassword)
$User=$Share
$Share="\\"+$Share+".file.core.windows.net\skype"

# Enabling remote powershell + CredSSP as the Skype AD commands need a Cred SSP session to process
Enable-PSRemoting
Enable-WSManCredSSP -Role client -DelegateComputer * -force
Enable-WSManCredSSP -Role server -force

#Somtimes PSRemoting needs some time before first connection. in the meanwhile we will install lync prrequisite with default NTSystem account
#region Lync Prerequisite

Write-Verbose "Installing SfB pre-requisites @ $(Get-Date)"
#connect to file share on storage account
net use G: $Share /u:$User $sasToken
Mount-DiskImage G:\SfBServer2015.iso
$DVD = (Get-PSDrive | where {$_.Description -eq "CD_ROM"}).Root

start-sleep -Seconds 10
#install Visual C++
Start-Process -FilePath cmd -ArgumentList /c, $DVD'Setup\amd64\vcredist_x64.exe', /q -Wait
#install Lync core
Start-Process -FilePath msiexec -ArgumentList /i, $DVD'Setup\amd64\setup\ocscore.msi', /passive -Wait
#install SQL express
Start-Process -FilePath msiexec -ArgumentList /i, $DVD'Setup\amd64\SQLSysClrTypes.msi', /quiet -Wait
#install SMO
Start-Process -FilePath msiexec -ArgumentList /i, $DVD'Setup\amd64\SharedManagementObjects.msi', /quiet -Wait
#install Lync admin tools
Start-Process -FilePath msiexec -ArgumentList /i, $DVD'Setup\amd64\setup\admintools.msi', /passive -Wait
#install SilverLight
Start-Process -FilePath cmd -ArgumentList /c, "G:\Silverlight_x64.exe", /q -Wait

#install KB updates needed for SfB
Start-Process -FilePath wusa -ArgumentList "G:\Windows8.1-KB2919442-x64.msu", /quiet -Wait -verbose
Start-Process -FilePath wusa -ArgumentList "G:\Windows8.1-KB2919355-x64.msu", /quiet -Wait -verbose
Start-Process -FilePath wusa -ArgumentList "G:\Windows8.1-KB2982006-x64.msu", /quiet, /norestart -Wait -verbose

Dismount-DiskImage G:\SfBServer2015.iso
net use G: /d
#endregion Lync Prerequisite


Invoke-Command  -Credential $DomainCreds -Authentication CredSSP -ComputerName $env:COMPUTERNAME -ScriptBlock {
 
param (
        $workingDir,
        $_Share,
        $_User,
        $_sasToken,
		$_EdgeName,
		$_internalIP,
		$_externalIP,
		$_PublicIP

    )
    # Working variables

#connect to file share on storage account
net use G: $_Share /u:$_User $_sasToken
Mount-DiskImage G:\SfBServer2015.iso
$DVD = (Get-PSDrive | where {$_.Description -eq "CD_ROM"}).Root

## Module Imports ##

Import-Module "C:\Program Files\Common Files\Skype for Business Server 2015\Modules\SkypeForBusiness\SkypeForBusiness.psd1"
Import-Module ActiveDirectory


## Variables ##

$Domain = Get-ADDomain
$DomainDNSName = $Domain.DNSRoot
$Computer = $env:computername + '.'+$Domain.DNSRoot
$DC = Get-ADDomainController
$Sbase = "CN=Configuration,"+$Domain.DistinguishedName
$fileshareName = "LyncShare"
$filesharepath = "F:\"+$fileshareName
$Databasespaths= "F:\SQLLogs","F:\SQLData"
$Logfilespath = "G:\Logs\"+$DomainDNSName+'\'
$NewTopologypath="F:\"+$domain.DNSRoot+"Topology.xml"
New-Item G:\Share,G:\Logs -type directory -ErrorAction SilentlyContinue
New-Item $Logfilespath -type directory -ErrorAction SilentlyContinue

## Prepare the AD Forest
Install-CSAdServerSchema -Confirm:$false -Verbose -Report $Logfilespath"01_Install-CSAdServerSchema.html"
Enable-CSAdForest  -Verbose -Confirm:$false -Report $Logfilespath"02_Enable-CSAdForest.html"
Enable-CSAdDomain -Verbose -Confirm:$false -Report $Logfilespath"03_Enable-CSAdDomain.html"
Add-ADGroupMember -Identity CSAdministrator -Members "Domain Admins"
Add-ADGroupMember -Identity RTCUniversalServerAdmins -Members "Domain Admins"

## Install SQL RTC database
#Start-Process  -FilePath G:\SfBServer2015\Setup\amd64\SQLEXPR_x64.exe  -ArgumentList '/UpdateEnabled=0 /Q /IACCEPTSQLSERVERLICENSETERMS /HIDECONSOLE /ACTION=Install /FEATURES=SQLEngine,Tools /INSTANCENAME=RTC /TCPENABLED=1 /SQLSVCACCOUNT="NT AUTHORITY\NetworkService" /SQLSYSADMINACCOUNTS="Builtin\Administrators" /BROWSERSVCSTARTUPTYPE="Automatic" /AGTSVCACCOUNT="NT AUTHORITY\NetworkService" /SQLSVCSTARTUPTYPE=Automatic' -Wait -NoNewWindow
# Install RTC database for First Edition Server
& 'C:\Program Files\Skype for Business Server 2015\Deployment\bootstrapper.exe' /BootstrapSqlExpress /SourceDirectory:$DVD'Setup\amd64'

## Install Central Management Store databases within RTC
Install-CsDatabase -CentralManagementDatabase -SqlServerFqdn $Computer -SqlInstanceName rtc -DatabasePaths $Databasespaths -Report $Logfilespath'04_InstallCMSDatabases.html'
#Set-CsConfigurationStoreLocation -SqlServerFqdn $Computer -SqlInstanceName rtc -Report $Logfilespath'Set-CsConfigurationStoreLocation.html' 
Start-Process  -FilePath powershell.exe -ArgumentList "Set-CsConfigurationStoreLocation -force -SqlServerFqdn $Computer -SqlInstanceName rtc -Report $Logfilespath'041_Set-CsConfigurationStoreLocation.html'"
start-sleep -Seconds 10  #to wait for the Set-csconfig to complete. Start-process have been used otherwise it it is being stuck with a prompt when a rerun this script multitimes.

## Create File Share used to share the CMS
New-Item $filesharepath -type directory
New-SmbShare -Name $fileshareName $filesharepath
Get-smbshare -name $fileshareName | Grant-SmbShareAccess -AccessRight Full -AccountName Everyone -Force

## Build and Publish Lync Topology
$sipdomain = $DomainDNSName
$externalweburl = "webext"+'.'+$sipdomain
#$_PublicIP = (Invoke-RestMethod https://api.ipify.org?format=json).ip
$edgeUrls="sip."+$sipdomain
$Pstnfqdn= "sbc1."+$DomainDNSName

$defaultTopology= $workingDir+ "\DefaultTopology_Skype.xml"
$xml = New-Object XML
$xml.Load($defaultTopology)
$xml.Topology.InternalDomains.DefaultDomain = $Sipdomain
$xml.Topology.InternalDomains.InternalDomain.name = $Sipdomain
$xml.Topology.Clusters.cluster[0].fqdn = $Computer
$xml.Topology.Clusters.cluster[0].machine.Fqdn = $Computer
$xml.Topology.Clusters.cluster[0].machine.FaultDomain = $Computer
$xml.Topology.Clusters.cluster[0].machine.UpgradeDomain = $Computer
$xml.Topology.Clusters.cluster[1].fqdn = $_EdgeName+'.'+$DomainDNSName
$xml.Topology.Clusters.cluster[1].machine.Fqdn = $_EdgeName+'.'+$DomainDNSName
$xml.Topology.Clusters.cluster[1].machine.NetInterface[0].IPAddress = $_internalIP
$xml.Topology.Clusters.cluster[1].machine.NetInterface[1].IPAddress = $_externalIP
$xml.Topology.Clusters.cluster[1].machine.NetInterface[1].ConfiguredIPAddress = $_PublicIP
$xml.Topology.Clusters.cluster[2].fqdn = $Pstnfqdn
$xml.Topology.Clusters.cluster[2].machine.Fqdn = $Pstnfqdn
$xml.Topology.Services.Service.Webservice.externalsettings.host = $externalweburl
$xml.Topology.Services.Service[3].FileStoreService.ShareName = $fileshareName
$xml.Topology.Services.Service[11].Ports.Port[1].ConfiguredFqdn = $edgeUrls
$xml.Topology.Services.Service[11].Ports.Port[3].ConfiguredFqdn = $edgeUrls
$xml.Topology.Services.Service[11].Ports.Port[6].ConfiguredFqdn = $edgeUrls
$xml.Topology.Services.Service[11].Ports.Port[8].ConfiguredFqdn = $edgeUrls
$xml.Topology.Services.Service[11].Ports.Port[9].ConfiguredFqdn = $edgeUrls
$xml.Topology.Services.Service[11].Ports.Port[10].ConfiguredFqdn = $edgeUrls
$xml.Topology.Services.Service[13].Ports.Port.ConfiguredFqdn = $Pstnfqdn
$xml.Save($NewTopologypath)


Publish-CSTopology -Filename $NewTopologypath -Force -Report $Logfilespath'05_Publish-CSTopology.html'
Enable-CSTopology -Report $Logfilespath'06_Enable-CsTopology.html'

## Install SQL RTCLOCAL and LYNCLOCAL databases with non default parameters : updateEnabled=0
Write-Verbose "Installing local configuration store @ $(Get-Date)"
#Start-Process  -FilePath G:\SfBServer2015\Setup\amd64\SQLEXPR_x64.exe  -ArgumentList '/UpdateEnabled=0 /QUIET /IACCEPTSQLSERVERLICENSETERMS /HIDECONSOLE /ACTION=Install /FEATURES=SQLEngine,Tools /INSTANCENAME=RTCLOCAL /TCPENABLED=1 /SQLSVCACCOUNT="NT AUTHORITY\NetworkService" /SQLSYSADMINACCOUNTS="Builtin\Administrators" /BROWSERSVCSTARTUPTYPE="Automatic" /AGTSVCACCOUNT="NT AUTHORITY\NetworkService" /SQLSVCSTARTUPTYPE=Automatic' -Wait -NoNewWindow
#Start-Process  -FilePath G:\SfBServer2015\Setup\amd64\SQLEXPR_x64.exe  -ArgumentList '/UpdateEnabled=0 /QUIET /IACCEPTSQLSERVERLICENSETERMS /HIDECONSOLE /ACTION=Install /FEATURES=SQLEngine,Tools /INSTANCENAME=LYNCLOCAL /TCPENABLED=1 /SQLSVCACCOUNT="NT AUTHORITY\NetworkService" /SQLSYSADMINACCOUNTS="Builtin\Administrators" /BROWSERSVCSTARTUPTYPE="Automatic" /AGTSVCACCOUNT="NT AUTHORITY\NetworkService" /SQLSVCSTARTUPTYPE=Automatic' -Wait -NoNewWindow

##do the same thing for RTCLOCAL and LYNCLOCAL
& 'C:\Program Files\Skype for Business Server 2015\Deployment\bootstrapper.exe' /Bootstraplocalmgmt /SourceDirectory:$DVD'Setup\amd64'

## Install Local configuration Store (replica of CMS) within RTCLOCAL
#Install-CSDatabase -ConfiguredDatabases -SqlServerFqdn $Computer -DatabasePaths $Databasespaths -Report $Logfilespath'07_InstallLocalstoreDatabases.html'

# Simple urls configuraton
$urlEntry1 = New-CsSimpleUrlEntry -Url "https://dialin.$sipdomain"
$simpleUrl1 = New-CsSimpleUrl -Component "dialin" -Domain "*" -SimpleUrlEntry $urlEntry1 -ActiveUrl "https://dialin.$sipdomain"
$urlEntry2 = New-CsSimpleUrlEntry -Url "https://meet.$sipdomain"
$simpleUrl2 = New-CsSimpleUrl -Component "meet" -Domain "$sipdomain" -SimpleUrlEntry $urlEntry2 -ActiveUrl "https://meet.$sipdomain"
$urlEntry3 = New-CsSimpleUrlEntry -Url "https://admin.$sipdomain"
$simpleUrl3 = New-CsSimpleUrl -Component "Cscp" -Domain "*" -SimpleUrlEntry $urlEntry3 -ActiveUrl "https://admin.$sipdomain"

Remove-CsSimpleUrlConfiguration -Identity "Global"     
set-CsSimpleUrlConfiguration -Identity "Global" -SimpleUrl @{Add=$simpleUrl1,$simpleUrl2,$simpleUrl3}

## Filling the local configuration store RTClocal and enabling Replica
$CSConfigExp = Export-csconfiguration -asbytes
Import-CsConfiguration -Byteinput $CSConfigExp -Localstore
Enable-CsReplica -Report $Logfilespath'08_Enable-CsReplica.html'
Start-CSwindowsService Replica -Report $Logfilespath'09_Start-CSwindowsService-Replica.html'

## Install Lync Component
& 'C:\Program Files\Skype for Business Server 2015\Deployment\Bootstrapper.exe' /SourceDirectory:$DVD'Setup\amd64'

##install local databases contained in SQL instances RTCLOCAL and LYNCLOCAL
Install-CSDatabase -ConfiguredDatabases -SqlServerFqdn $Computer -DatabasePaths $Databasespaths -Report $Logfilespath'07_InstallLocalstoreDatabases.html'

#enable the FE01 computer
Enable-CsComputer -Report $Logfilespath'10_Enable-CsComputer.html'


## Request and Install Certificates ##
$CA = Get-Adobject -LDAPFilter "(&(objectClass=pKIEnrollmentService)(cn=*))" -SearchBase $Sbase
$CAName = $DC.Hostname + "\" + $CA.Name
$certServer = Request-CsCertificate -New -Type Default,WebServicesInternal,WebServicesExternal -ComputerFqdn $Computer -CA $CAName  -FriendlyName "Standard Edition Certficate" -PrivateKeyExportable $True -DomainName "sip.$sipdomain" -allsipdomain -Report $Logfilespath'11_Request-CsCertificate-Webserver.html'
$certOAuth = Request-CsCertificate -New -Type OAuthTokenIssuer -ComputerFqdn $Computer -CA $CAName -FriendlyName "OathCert" -PrivateKeyExportable $True -DomainName $Computer -Report $Logfilespath'12_Request-CsCertificate-Oauth.html'
Set-CsCertificate -Reference $certServer -Type Default,WebservicesInternal,WebServicesExternal -Report $Logfilespath'13_Set-CsCertificate-Webserver.html'
Set-CsCertificate -Reference $certOAuth -Type OAuthTokenIssuer -Report $Logfilespath'14_Set-CsCertificate-OAuth.html'

## Start Skype services ##
Start-CSWindowsService -NoWait -Report $Logfilespath'15_Start-CSwindowsService.html'

#Pin shortcuts to tskbar
$sa = new-object -c shell.application
$pn = $sa.namespace("C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Administrative Tools").parsename('Windows PowerShell ISE.lnk')
$pn.invokeverb('taskbarpin')
$pn = $sa.namespace("$env:CommonProgramFiles\Skype for Business Server 2015").parsename('AdminUIHost.exe')
$pn.invokeverb('taskbarpin')
$pn = $sa.namespace("$env:ProgramFiles\Skype for Business Server 2015\Administrative Tools").parsename('Microsoft.Rtc.Management.TopologyBuilder.exe')
$pn.invokeverb('taskbarpin')
$pn = $sa.namespace("c:\ProgramData\Microsoft\Windows\Start Menu\Programs\Skype for Business Server 2015").parsename('Skype for Business Server Management Shell.lnk')
$pn.invokeverb('taskbarpin')
$pn = $sa.namespace("$env:ProgramFiles\Skype for Business Server 2015\Deployment").parsename('Deploy.exe')
$pn.invokeverb('taskbarpin')

#in order to start skype control pannel withouth a security prompt
Write-Verbose "Adding *.$DomainDNSName to local intranet zone @ $(Get-Date)"
New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\$DomainDNSName" -ErrorAction Continue
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\$DomainDNSName" -Name * -Value 1 -Type DWord -ErrorAction Continue
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap" -Name IEHarden -Value 0 -Type DWord -ErrorAction Continue
#Disable IEES Internet Explorer Enhenced security
$AdminKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
$UserKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}"
Set-ItemProperty -Path $AdminKey -Name "IsInstalled" -Value 0
Set-ItemProperty -Path $UserKey -Name "IsInstalled" -Value 0
Stop-Process -Name Explorer
Write-Host "IE Enhanced Security Configuration (ESC) has been disabled." -ForegroundColor Green

#region Edge srever Config ################################################
#Enable external Edge access and federation
Set-CsAccessEdgeConfiguration -AllowAnonymousUsers $true -AllowFederatedUsers $true -AllowOutsideUsers $true -UseDnsSrvRouting -EnablePartnerDiscovery $true
Set-CsExternalAccessPolicy -Identity "Global" -EnableFederationAccess $True -EnableOutsideAccess $True

#Export the topology for the Edge srever
$EdgeCsConfig = 'G:\Share\Config'+$sipdomain+'.zip'
Remove-Item $EdgeCsConfig -ErrorAction SilentlyContinue
Export-CsConfiguration -FileName $EdgeCsConfig
#endregion Edge server config

#region Enterprise voice routing config ########################################
# Set Parameters
$PstnUsage1 = "LocalPBX"
$PstnUsage2 = "UKDomestic"
$PstnUsage3 = "International"
$SkypeSiteId = (Get-CsSite)[0].Identity
$SkypeSiteName = (Get-CsSite)[0].DisplayName
$PstnGatewayId = (Get-CsService -PstnGateway)[0].identity
$DialinRegion = "EMEA"

#Configure Dial plans and normalization rules
New-CsDialPlan -Identity $SkypeSiteId -SimpleName  $SkypeSiteName'_DialPlan' -DialinConferencingRegion $DialinRegion
Remove-CsVoiceNormalizationRule -Identity $SkypeSiteId'/Keep All'
New-CsVoiceNormalizationRule -Identity $SkypeSiteId'/ToSkypeUKUsers' -Pattern "^(1\d{3})$" -Translation '+44118000$1'
New-CsVoiceNormalizationRule -Identity $SkypeSiteId'/ToFreeSwitchUsers' -Pattern "^(2\d{3})$" -Translation '+44118000$1'
New-CsVoiceNormalizationRule -Identity $SkypeSiteId'/ToInternationalE164' -Pattern "^(\+|00)(\d{10}\d+)$" -Translation '+$2'
New-CsVoiceNormalizationRule -Identity $SkypeSiteId'/ToUKE164' -Pattern "^0(\d{10})$" -Translation '+44$1'

#Configure PSTN usages
Set-CsPstnUsage -Usage @{Replace=$PstnUsage1, $PstnUsage2, $PstnUsage3}

#Configure Voice policies and link to PSTN usage
New-CsVoicePolicy -Identity $SkypeSiteId -AllowCallForwarding $true -PstnUsages @{Add=$PstnUsage1, $PstnUsage2, $PstnUsage3} -AllowPSTNReRouting $true -AllowSimulRing $true -EnableCallPark $true -EnableCallTransfer $true -EnableDelegation $true -EnableMaliciousCallTracing $true -EnableTeamCall $true
New-CsVoicePolicy -Identity $PstnUsage1 -AllowCallForwarding $true -PstnUsages @{Add=$PstnUsage1} -AllowPSTNReRouting $true -AllowSimulRing $true -EnableCallPark $true -EnableCallTransfer $true -EnableDelegation $true -EnableMaliciousCallTracing $true -EnableTeamCall $true
New-CsVoicePolicy -Identity $PstnUsage2 -AllowCallForwarding $true -PstnUsages @{Add=$PstnUsage1, $PstnUsage2} -AllowPSTNReRouting $true -AllowSimulRing $true -EnableCallPark $true -EnableCallTransfer $true -EnableDelegation $true -EnableMaliciousCallTracing $true -EnableTeamCall $true


#Configure Trunk, Voice policies and link to PSTN usage
New-CsTrunkConfiguration -Identity $PstnGatewayId -EnableReferSupport $false -SRTPMode Optional
New-CsVoiceRoute -Identity $PstnUsage1'_Route' -NumberPattern "^\+441180002\d{3}" -PstnUsages @{Add=$PstnUsage1} -PstnGatewayList @{Add=$PstnGatewayId} 
New-CsVoiceRoute -Identity $PstnUsage2'_Route' -NumberPattern "^\+44\d{10}" -PstnUsages @{Add=$PstnUsage2} -PstnGatewayList @{Add=$PstnGatewayId} 
New-CsVoiceRoute -Identity $PstnUsage3'_Route' -NumberPattern "^\+\d{10}\d+" -PstnUsages @{Add=$PstnUsage3} -PstnGatewayList @{Add=$PstnGatewayId} 

#Unassigned numbers Config
$AnnServiceId = (Get-CsService | where {$_.role -eq 'ApplicationServer'})[0].Identity
$ForwardSipuri = "sip:pgas@"+$DomainDNSName
New-CsAnnouncement -Identity $AnnServiceId -Name "Forward Announcement" -TextToSpeechPrompt "This number is temporarily out of service, we will transfer your call" -Language "en-GB" -TargetUri $ForwardSipuri
New-CsUnassignedNumber -Identity $SkypeSiteName'_UNset1' -NumberRangeStart '+441180001010' -NumberRangeEnd '+441180001020' -AnnouncementService $AnnServiceId -AnnouncementName "Forward Announcement"

#endregion #######################################Enterprise voice routing config#################

#region ##################Dialin Conferencing config######################################
$DialinUri = "sip:"+$DialinRegion+'@'+$DomainDNSName
New-CsDialInConferencingAccessNumber -PrimaryUri $DialinUri -DisplayNumber "+44-118-000-1000" -LineUri "tel:+441180001000" -Pool (Get-CsPool)[0].Identity -PrimaryLanguage "en-GB" -Regions $DialinRegion -SecondaryLanguages "fr-FR", "ar-SA"
#endregion

#Remove installation file Drive
Dismount-DiskImage G:\SfBServer2015.iso
net use G: /d

#Enable users
cd $workingDir
.\Enable-CsUsers.ps1 -SipDomain $sipdomain

} -ArgumentList $PSScriptRoot, $Share, $User, $sasToken, $EdgeName, $EdgeIntIp, $EdgeExtIp, $EdgePubIp
#Disable-PSRemoting
#Disable-WSManCredSSP -role client
#Disable-WSManCredSSP -role server


#Copy O365 Lab Scripts to user Desktop
Invoke-WebRequest -Uri https://github.com/ibenbouzid/Office365Scripts/archive/master.zip -OutFile .\Office365Scripts.zip
Add-Type -AssemblyName System.IO.Compression.FileSystem
[System.IO.Compression.ZipFile]::ExtractToDirectory('.\Office365Scripts.zip','.')
Copy-Item -Path ".\Office365Scripts-master" -Destination C:\Users\$UserName\Desktop\Scripts -Recurse -ErrorAction Continue


#The registery key modified earlier need a computer restart
Restart-Computer
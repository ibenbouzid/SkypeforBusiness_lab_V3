#
# EDGE_Install.ps1
#
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
        [string]$CAComputerName,

		[Parameter(Mandatory)]
        [string]$CertPassword,

		[Parameter(Mandatory)]
        [string]$PublicCert

       )

$SecurePassword = ConvertTo-SecureString -String $Password -AsPlainText -Force
$SecureCertPassword = ConvertTo-SecureString -String $CertPassword -AsPlainText -Force
[PSCredential ]$LocalCreds = New-Object PSCredential ("$env:COMPUTERNAME\$Username", $SecurePassword)
[PSCredential ]$DomainCreds = New-Object PSCredential ("$DomainName\$Username", $SecurePassword)
$User=$Share
$Share="\\"+$Share+".file.core.windows.net\skype"
$PublicCertbool= [System.Convert]::ToBoolean($PublicCert)

#Install all the prereqs
Add-WindowsFeature RSAT-ADDS, NET-Framework-Core, NET-Framework-45-Core, NET-Framework-45-ASPNET,`
                  Web-Net-Ext45, NET-WCF-HTTP-Activation45, Windows-Identity-Foundation, Telnet-Client


#This allow to authenticate from a different domain, or with an account local to the remote server
New-Itemproperty -name LocalAccountTokenFilterPolicy -path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -propertyType DWord -value 1 -ErrorAction Continue

# Enabling remote powershell + CredSSP ################## Credssp login is needed to request the certificate from a PS remote session
Enable-PSRemoting
Enable-WSManCredSSP -Role client -DelegateComputer * -force
Enable-WSManCredSSP -Role server -force

#Enable AllowFreshCredentialsWhenNTLMOnly local group policy to be able to use credssp on a non domain joined machine
New-Item 'HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation\AllowFreshCredentialsWhenNTLMOnly' -force -ErrorAction Continue

New-Itemproperty -name 1 -path HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation\AllowFreshCredentialsWhenNTLMOnly -propertyType string -value wsman/* -Force -ErrorAction Continue
New-ItemProperty -name AllowFreshCredentialsWhenNTLMOnly -path HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation -PropertyType Dword -value 1 -ErrorAction Continue
New-ItemProperty -name ConcatenateDefaults_AllowFreshNTLMOnly -path HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation -PropertyType Dword -value 1 -ErrorAction Continue


#	# Working variables
#     param (
#        $workingDir,
#        $_Share,
#        $_User,
#        $_sasToken,
#		$_DomainName,
#		$_CAComputerName
#    )


##connect to file share on storage account
#net use G: $_Share /u:$_User $_sasToken
net use G: $Share /u:$User $sasToken

start-sleep -Seconds 10
#install Visual C++
Start-Process -FilePath cmd -ArgumentList /c, "G:\SfBServer2015\Setup\amd64\vcredist_x64.exe", /q -Wait
#install Lync core
Start-Process -FilePath msiexec -ArgumentList /i, "G:\SfBServer2015\Setup\amd64\setup\ocscore.msi", /passive -Wait
#install SQL express
Start-Process -FilePath msiexec -ArgumentList /i, "G:\SfBServer2015\Setup\amd64\SQLSysClrTypes.msi", /quiet -Wait
#install SMO
Start-Process -FilePath msiexec -ArgumentList /i, "G:\SfBServer2015\Setup\amd64\SharedManagementObjects.msi", /quiet -Wait


## Module Imports ##

Import-Module "C:\Program Files\Common Files\Skype for Business Server 2015\Modules\SkypeForBusiness\SkypeForBusiness.psd1"



## Variables ##
$_DomainName = $DomainName
$Logfilespath = "G:\Logs\"+$_DomainName+'\'
$Databasespaths= "F:\SQLLogs","F:\SQLData"
$CSConfigExp = 'G:\Share\Config'+$_DomainName+'.zip'
$RootCA= "G:\Share\"+$_DomainName+"-CA.crt"
$CAName = $_CAComputerName+'.'+$_DomainName+'\'+$_DomainName+'-CA'
#$CAName = $CAComputerName+'.'+$_DomainName+'\csalab-VM-SFB-AD01-CA'

#Import private AD RootCA Certificate to Trusted Root Store
Import-Certificate -Filepath $RootCA -CertStoreLocation Cert:\LocalMachine\Root

#Import public SSL Root CA if any  
$RootCAfilepath = "G:\cert\SSL_RootCA.crt"
Import-Certificate -Filepath (get-childitem $RootCAfilepath) -CertStoreLocation Cert:\LocalMachine\Root -ErrorAction Continue

start-sleep -Seconds 10
& 'C:\Program Files\Skype for Business Server 2015\Deployment\bootstrapper.exe' /Bootstraplocalmgmt /SourceDirectory:"G:\SfBServer2015\Setup\amd64"

#start-sleep -Seconds 10
##Install SQL databases RTCLOCAL and LYNCLOCAL
#Start-Process  -FilePath G:\SfBServer2015\Setup\amd64\SQLEXPR_x64.exe  -ArgumentList '/UpdateEnabled=0 /QUIET /IACCEPTSQLSERVERLICENSETERMS /HIDECONSOLE /ACTION=Install /FEATURES=SQLEngine,Tools /INSTANCENAME=RTCLOCAL /TCPENABLED=1 /SQLSVCACCOUNT="NT AUTHORITY\NetworkService" /SQLSYSADMINACCOUNTS="Builtin\Administrators" /BROWSERSVCSTARTUPTYPE="Automatic" /AGTSVCACCOUNT="NT AUTHORITY\NetworkService" /SQLSVCSTARTUPTYPE=Automatic' -Wait -NoNewWindow
#Start-Process  -FilePath G:\SfBServer2015\Setup\amd64\SQLEXPR_x64.exe  -ArgumentList '/UpdateEnabled=0 /QUIET /IACCEPTSQLSERVERLICENSETERMS /HIDECONSOLE /ACTION=Install /FEATURES=SQLEngine,Tools /INSTANCENAME=LYNCLOCAL /TCPENABLED=1 /SQLSVCACCOUNT="NT AUTHORITY\NetworkService" /SQLSYSADMINACCOUNTS="Builtin\Administrators" /BROWSERSVCSTARTUPTYPE="Automatic" /AGTSVCACCOUNT="NT AUTHORITY\NetworkService" /SQLSVCSTARTUPTYPE=Automatic' -Wait -NoNewWindow
#& 'C:\Program Files\Skype for Business Server 2015\Deployment\bootstrapper.exe' /Bootstraplocalmgmt /SourceDirectory:"G:\SfBServer2015\Setup\amd64"
#Start-CSwindowsService Replica -Report $Logfilespath'02_Test-apres-bootsrapper_EDGE.html'


## Filling the local configuration store RTClocal and enabling Replica
Import-CsConfiguration -FileName $CSConfigExp -Localstore
Enable-CsReplica -Report $Logfilespath'17_Enable-CsReplica_EDGE.html'
Start-CSwindowsService Replica -Report $Logfilespath'18_Start-CSwindowsService-Replica_EDGE.html'


## Install Local databases RTClocal and lync local in the specified path (By default the following bootstraper will do it in C drive instead)
Install-CSDatabase -LocalDatabases -DatabasePaths $Databasespaths -Report $Logfilespath'181_InstallLocalstoreDatabases.html'

### Install Lync EDGE Component
& 'C:\Program Files\Skype for Business Server 2015\Deployment\Bootstrapper.exe' /SourceDirectory:"G:\SfBServer2015\Setup\amd64"

###Enable Edge
Enable-CsComputer -Report $Logfilespath'19_Enable-CsComputer_EDGE.html'



net use G: /d

#Pin shortcuts to taskbar in the admin session
Invoke-Command  -Credential $LocalCreds -Authentication CredSSP -ComputerName $env:COMPUTERNAME -ScriptBlock {

	# Working variables
     param (
        $workingDir,
        $_Share,
        $_User,
        $_sasToken,
		$_DomainName,
		$_CAComputerName,
		$_certPassword,
		$_PublicCert
    )
	$Logfilespath = "G:\Logs\"+$_DomainName+'\'
	#$CAName = $_CAComputerName+'.'+$_DomainName+'\csalab-VM-SFB-AD01-CA'
	$CAName = $_CAComputerName+'.'+$_DomainName+'\'+$_DomainName+'-CA'

	##connect to file share on storage account
	net use G: $_Share /u:$_User $_sasToken
	#start-sleep -Seconds 10 

		#Request Internal Edge Private Certificate from RootCA
		$certServerInternal = Request-CsCertificate -New -Type Internal -CA $CAName -FriendlyName "Internal Edge Certificate" -PrivateKeyExportable $True -AllSipDomain -Report $Logfilespath'20_Request-CsCertificate_Internal_EDGE.html'
		Set-CsCertificate -Reference $certServerInternal -Type Internal -Report $Logfilespath'21_Set-CsCertificate-Webserver-Internal.html'


	if ($_PublicCert) {
		#Install External Edge Public Certificate from Shared Folder
		$Edgecert = 'G:\cert\edge.'+$_DomainName+'.pfx'
		$ExtCertThumbprint = (Import-PfxCertificate -Exportable -Password $_certPassword -CertStoreLocation cert:\localmachine\my -FilePath $Edgecert).thumbprint   
		Set-CsCertificate -Thumbprint $ExtCertThumbprint -Type AccessEdgeExternal,DataEdgeExternal,AudioVideoAuthentication -Report $Logfilespath'23_Set-CsCertificate-Webserver-External.html'
	}
	else {
		#Request External Edge Private Certificate from RootCA
		$certServerExternal = Request-CsCertificate -New -Type AccessEdgeExternal,DataEdgeExternal,AudioVideoAuthentication -CA $CAName -FriendlyName "External Edge Certificate" -Template webserver -PrivateKeyExportable $True -DomainName $_DomainName -Report $Logfilespath'22_Request-CsCertificate_Internal_EDGE.html'
		Set-CsCertificate -Reference $certServerExternal -Type AccessEdgeExternal,DataEdgeExternal,AudioVideoAuthentication -Report $Logfilespath'23_Set-CsCertificate-Webserver-External.html'

 	}
	 
	## Start Skype Edge services ##
	Start-CSWindowsService -NoWait -Report $Logfilespath'24_Start-CSwindowsService.html'

	net use G: /d



$sa = new-object -c shell.application
$pn = $sa.namespace("C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Administrative Tools").parsename('Windows PowerShell ISE.lnk')
$pn.invokeverb('taskbarpin')
$pn = $sa.namespace("c:\ProgramData\Microsoft\Windows\Start Menu\Programs\Skype for Business Server 2015").parsename('Skype for Business Server Management Shell.lnk')
$pn.invokeverb('taskbarpin')
$pn = $sa.namespace("$env:ProgramFiles\Skype for Business Server 2015\Deployment").parsename('Deploy.exe')
$pn.invokeverb('taskbarpin')
}  -ArgumentList $PSScriptRoot, $Share, $User, $sasToken,$DomainName, $CAComputerName, $SecureCertPassword , $PublicCertbool

Disable-PSRemoting
Disable-WSManCredSSP -role client
Disable-WSManCredSSP -role server

Restart-Computer

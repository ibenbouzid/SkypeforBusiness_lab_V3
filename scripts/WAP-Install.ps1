#
# WAP_Install.ps1
#
Param (		
		[Parameter(Mandatory)]
        [String]$DomainName,

        [Parameter(Mandatory)]
        [string]$Username,

	    [Parameter(Mandatory)]
        [string]$Password,
		
		[Parameter(Mandatory)]
        [string]$CAComputerName,

		[Parameter(Mandatory)]
        [string]$Share,

		[Parameter(Mandatory)]
        [string]$sasToken,

		[Parameter(Mandatory)]
        [string]$StsServiceName,
		
		[Parameter(Mandatory)]
        [string]$StsServiceIpaddr,

		[Parameter(Mandatory)]
        [string]$CertPassword,
		[Parameter(Mandatory)]
        [string]$PublicCert,

		[Parameter(Mandatory)]
        [string]$MediationServName

       )

$SecurePassword = ConvertTo-SecureString -String $Password -AsPlainText -Force
$SecureCertPassword = ConvertTo-SecureString -String $CertPassword -AsPlainText -Force
[PSCredential ]$DomainCreds = New-Object PSCredential ("$DomainName\$Username", $SecurePassword)
[PSCredential ]$LocalCreds = New-Object PSCredential ("$env:COMPUTERNAME\$Username", $SecurePassword)
$User=$Share
$Share="\\"+$Share+".file.core.windows.net\skype"
$PublicCertbool= [System.Convert]::ToBoolean($PublicCert)

# Add Web Application Proxy Role
Install-WindowsFeature RSAT-RemoteAccess, RSAT-AD-PowerShell, Web-Application-Proxy -IncludeManagementTools
 
#This allow to authenticate from a different domain, or with an account local to the remote server
New-Itemproperty -name LocalAccountTokenFilterPolicy -path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -propertyType DWord -value 1 -ErrorAction SilentlyContinue

# Enabling remote powershell + CredSSP ################## Credssp login is needed to request the certificate from a PS remote session
Enable-PSRemoting
Enable-WSManCredSSP -Role client -DelegateComputer * -force
Enable-WSManCredSSP -Role server -force

#Enable AllowFreshCredentialsWhenNTLMOnly local group policy to be able to use credssp on a non domain joined machine
#In windows server 2016 Enable-WSManCredSSP create the AllowFreshCredentialsWhenNTLMOnly by default but with the server name without the dns prefix we have to remove the value and recreate with *
#New-Item -name AllowFreshCredentialsWhenNTLMOnly -path HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation -ItemType folder -ErrorAction Continue
New-Item 'HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation\AllowFreshCredentialsWhenNTLMOnly' -force -ErrorAction Continue
Remove-ItemProperty -name 1 -path HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation\AllowFreshCredentialsWhenNTLMOnly -ErrorAction Continue
New-Itemproperty -name 1 -path HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation\AllowFreshCredentialsWhenNTLMOnly -propertyType string -value "wsman/*" -ErrorAction Continue


Invoke-Command  -Credential $LocalCreds -Authentication CredSSP -ComputerName $env:COMPUTERNAME -ScriptBlock {
 
	# Working variables
     param (
        $workingDir,
        $_Share,
        $_User,
        $_sasToken,
		$_certPassword,
		$_stsServiceName,
		$_stsServiceIpaddr,
		$_DomainCreds,
		$_DomainName,
		$_CAComputerName,
		$_PublicCert,
		$_MediationServName,
		$_Username
    )


	### Variables
	# Skype
	$_Sipdomain= $_DomainName
	$_SkypeWebServicesRoot = "webext."
	$OfficeWebAppsRoot = "owas."
	$externalweburl = $_SkypeWebServicesRoot+$_Sipdomain
	#For private Certificate only
	$CertificateWAPsubject = $externalweburl



    #connect to file share on storage account
    net use G: $_Share /u:$_User $_sasToken
    
    #go to our packages scripts folder
    Set-Location $workingDir
     
	#region#   Populate Host File
	#Add host Function: Add entry to hosts file
	Function AddHost{
		param (
			$Ipaddr,
			$HostName
		)
		$hostsFile = "$env:windir\System32\drivers\etc\hosts"

		$newHostEntry = "`t$Ipaddr`t$HostName"
		if((Get-Content -Path $hostsFile) -contains $NewHostEntry)
		{   Write-Verbose -Verbose "The hosts file already contains the entry: $newHostEntry.  File not updated.";    }
		else
		{   Add-Content -Path $hostsFile -Value $NewHostEntry;   }
	}
	#Add sts service because WAP is not domain joined
	AddHost -Ipaddr $_stsServiceIpaddr -HostName $_stsServiceName

	#Add Lyncdiscover in host file as it shouldn't be resolved internally
	$LyncdiscoverIpaddr =	([System.Net.Dns]::GetHostAddresses($externalweburl)).IPAddressToString
	$LyncdicoverName = "lyncdiscover."+$_Sipdomain
	AddHost -Ipaddr $LyncdiscoverIpaddr -HostName $LyncdicoverName
	#endregion

	#region#   Request/Install Certificates
	#Import Private AD Root CA
	$RootCA= "G:\Share\"+$_DomainName+"-CA.crt"
	Import-Certificate -Filepath $RootCA -CertStoreLocation Cert:\LocalMachine\Root

	#Import Public SSL Root CA if any   
    $RootCAfilepath = "G:\cert\SSL_RootCA.crt"
	Import-Certificate -Filepath (get-childitem $RootCAfilepath) -CertStoreLocation Cert:\LocalMachine\Root -ErrorAction Continue

	#install the certificate that will be used for ADFS Service
	$STScert = 'G:\Share\sts.'+$_DomainName+'.pfx'
    $certificateSTSThumbprint = (Import-PfxCertificate -Exportable -Password $_certPassword -CertStoreLocation cert:\localmachine\my -FilePath $STScert).thumbprint

	if ($_PublicCert) {
		#install the WAP certificate
		$WApcert = 'G:\cert\wap.'+$_DomainName+'.pfx' 
		$CertificateWAPThumbprint = (Import-PfxCertificate -Exportable -Password $_certPassword -CertStoreLocation cert:\localmachine\my -FilePath $WApcert).thumbprint
		  
	}
	else {
		
		# CA for Online Request
		$CertificateAuthority = $_CAComputerName+'.'+$_DomainName+'\'+$_DomainName+'-CA'

		# WAP cert config
		$CertificateWAPsans = $externalweburl,"lyncdiscover.$_Sipdomain","meet.$_Sipdomain","dialin.$_Sipdomain","owas.$_Sipdomain"
		$CertificateWAPsubjectCN = "CN=" + $CertificateWAPsubject
		
		Import-Module .\NewCertReq.ps1
		# Request Web Application Proxy certificate
		New-CertificateRequest -subject $CertificateWAPsubjectCN -SANs $CertificateWAPsans -OnlineCA $CertificateAuthority

		#Get thumbprint of WAP certificate
		$CertificateWAPThumbprint = (dir Cert:\LocalMachine\My | where {$_.subject -match $CertificateWAPsubject})[0].thumbprint
 
 	}
	#endregion
	
	#region#   Install and populate Reverse Proxy
	# install WAP
    Install-WebApplicationProxy –CertificateThumbprint $certificateSTSThumbprint -FederationServiceName $_stsServiceName -FederationServiceTrustCredential $_DomainCreds
 
	# Publish Lync Urls
	Add-WebApplicationProxyApplication -Name 'Skype Web Services' -ExternalPreAuthentication PassThrough -ExternalUrl "https://$_SkypeWebServicesRoot$_Sipdomain/" -BackendServerUrl ("https://"+$_SkypeWebServicesRoot+$_Sipdomain+":4443/") -ExternalCertificateThumbprint $CertificateWAPThumbprint
	Add-WebApplicationProxyApplication -Name 'Skype Lyncdiscover' -ExternalPreAuthentication PassThrough -ExternalUrl "https://lyncdiscover.$_Sipdomain/" -BackendServerUrl ("https://lyncdiscover."+$_Sipdomain+":4443/") -ExternalCertificateThumbprint $CertificateWAPThumbprint
	Add-WebApplicationProxyApplication -Name 'Skype Dialin' -ExternalPreAuthentication PassThrough -ExternalUrl "https://dialin.$_Sipdomain/" -BackendServerUrl ("https://dialin."+$_Sipdomain+":4443/") -ExternalCertificateThumbprint $CertificateWAPThumbprint
	Add-WebApplicationProxyApplication -Name 'Skype Meet' -ExternalPreAuthentication PassThrough -ExternalUrl "https://meet.$_Sipdomain/" -BackendServerUrl ("https://meet."+$_Sipdomain+":4443/") -ExternalCertificateThumbprint $CertificateWAPThumbprint
	Add-WebApplicationProxyApplication -Name 'Office Web Apps Server' -ExternalPreAuthentication PassThrough -ExternalUrl "https://$OfficeWebAppsRoot$_Sipdomain/" -BackendServerUrl ("https://"+$OfficeWebAppsRoot+$_Sipdomain+"/") -ExternalCertificateThumbprint $CertificateWAPThumbprint
	Add-WebApplicationProxyApplication -Name 'Federation service' -ExternalPreAuthentication PassThrough -ExternalUrl "https://$_stsServiceName/" -BackendServerUrl ("https://"+$_stsServiceName+"/") -ExternalCertificateThumbprint $certificateSTSThumbprint
	#endregion

	#region#   Install Freeswitch PSTN Gateway
	$Newconfig = 'C:\Program Files\FreeSWITCH\conf\freeswitch.xml'
	#$DomainName = "uctech.uk"
	#$FrontEnd = "VM-SFB-FE01"
	$FrontEnd = $_MediationServName
	$MediationTCPPort = "5068" 
	$MediationFqdn = $FrontEnd+'.'+$_DomainName+':'+$MediationTCPPort
	#$IntIP = "10.0.0.7"
	#$ExtIP = "192.168.0.4" 
	#$PubIP = "13.81.4.228"

	#Get primary and secondary Nic's IPv4 address
	Get-NetIPConfiguration | foreach {if ($_.IPv4DefaultGateway) {$ExtIP = $_.IPv4Address.IPAddress} else {$IntIP = $_.IPv4Address.IPAddress}}
	#Get Public IP address
	$PubIP = (Invoke-RestMethod https://api.ipify.org?format=json).ip

	#Download Freeswitch from Storage account or from the web
	copy-Item "G:\FreeSWITCH*.msi" -Destination FreeSWITCH.msi -ErrorAction Continue -Force
	$ItemExists = Get-Item FreeSWITCH.msi -ErrorAction Continue
	If (!$ItemExists) {
		write "item do not exist"
		Invoke-WebRequest -Uri http://files.freeswitch.org/windows_installer/installer/x64/FreeSWITCH-1.6.15-x64-Release.msi -OutFile FreeSWITCH.msi
	}

	#install Freeswitch
	Start-Process -FilePath msiexec -ArgumentList /i, FreeSWITCH.msi, /quiet -Wait

	#Remove the vannila config files
	Remove-Item 'C:\Program Files\FreeSWITCH\conf\*' -Force -Recurse

	#Create freeswitch.xml config and populate with parameters
	$defaultconfig= $workingDir+ "\freeswitch.xml"
	$xml = New-Object XML
	$xml.Load($defaultconfig)
	$xml.document.'x-pre-process'[1].data = "mediation-fqdn="+$MediationFqdn
	$xml.document.'x-pre-process'[2].data = "internal-ip="+$IntIP
	$xml.document.'x-pre-process'[3].data = "external-ip="+$EXTIP
	$xml.document.'x-pre-process'[4].data = "public-ip="+$PubIP
	$xml.Save($Newconfig)

	#Open firewall ports
	#SIP ports
	netsh advfirewall firewall add rule name="Freeswitch5060" dir=in action=allow protocol=TCP localport=5060
	netsh advfirewall firewall add rule name="Freeswitch5066" dir=in action=allow protocol=TCP localport=5066
	netsh advfirewall firewall add rule name="Freeswitch5080" dir=in action=allow protocol=UDP localport=5080
	#RTP ports
	netsh advfirewall firewall add rule name="FreeswitchRTP" dir=in action=allow protocol=UDP localport=16000-16010
	
	#Start Freeswith service
	Set-Service FreeSWITCH -StartupType Automatic
	Start-Service FreeSWITCH
	#endregion################################################End Freeswitch PSTN gateway config
	
	######Copy Xlite
	copy-Item "G:\X-Lite*.exe" -Destination C:\Users\$_Username\Desktop\X-Lite.exe -ErrorAction Continue -Force
	
	#unmount G drive
	net use G: /d

	#Pin shortcuts to taskbar
	$sa = new-object -c shell.application
	$pn = $sa.namespace("C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Administrative Tools").parsename('Windows PowerShell ISE.lnk')
	$pn.invokeverb('taskbarpin')

} -ArgumentList $PSScriptRoot, $Share, $User, $sasToken, $SecureCertPassword, $StsServiceName, $StsServiceIpaddr, $DomainCreds, $DomainName, $CAComputerName, $PublicCertbool, $MediationServName, $Username

	

#Disable-PSRemoting
#Disable-WSManCredSSP -role client
#Disable-WSManCredSSP -role server
Restart-Computer
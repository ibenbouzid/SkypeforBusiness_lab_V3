#
# ADFS_Install.ps1
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
        [string]$StsServiceName,

		[Parameter(Mandatory)]
        [string]$CertPassword,

		[Parameter(Mandatory)]
        [string]$CAComputerName,
		[Parameter(Mandatory)]
        [string]$PublicCert

       )

$SecurePassword = ConvertTo-SecureString -String $Password -AsPlainText -Force
[PSCredential ]$DomainCreds = New-Object PSCredential ("$DomainName\$Username", $SecurePassword)
$SecureCertPassword = ConvertTo-SecureString -String $CertPassword -AsPlainText -Force
$User=$Share
$Share="\\"+$Share+".file.core.windows.net\skype"
$PublicCertbool= [System.Convert]::ToBoolean($PublicCert)

#This allow to authenticate from a different domain, or with an account local to the remote server
New-Itemproperty -name LocalAccountTokenFilterPolicy -path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -propertyType DWord -value 1 -Force -ErrorAction SilentlyContinue

# Enabling remote powershell + CredSSP as KDSRootkey command need a Cred SSP session to process
#Enable-PSRemoting
Enable-WSManCredSSP -Role client -DelegateComputer * -force
Enable-WSManCredSSP -Role server -force
	
#Enable AllowFreshCredentialsWhenNTLMOnly local group policy to be able to use credssp on a non domain joined machine
#In windows server 2016 Enable-WSManCredSSP create the AllowFreshCredentialsWhenNTLMOnly by default but with the server name without the dns prefix we have to remove the value and recreate with *
#New-Item -name AllowFreshCredentialsWhenNTLMOnly -path HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation -ItemType folder -ErrorAction Continue
New-Item 'HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation\AllowFreshCredentialsWhenNTLMOnly' -force -ErrorAction Continue
New-Itemproperty -name 1 -path HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation\AllowFreshCredentialsWhenNTLMOnly -propertyType string -value "wsman/*" -Force -ErrorAction Continue
New-ItemProperty -name AllowFreshCredentialsWhenNTLMOnly -path HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation -PropertyType Dword -value 1 -ErrorAction Continue
New-ItemProperty -name ConcatenateDefaults_AllowFreshNTLMOnly -path HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation -PropertyType Dword -value 1 -ErrorAction Continue

# ADFS Install
Add-WindowsFeature ADFS-Federation -IncludeManagementTools

#Invoke-Command  -Credential $DomainCreds -ComputerName $env:COMPUTERNAME -ScriptBlock {
Invoke-Command  -Credential $DomainCreds -Authentication CredSSP -ComputerName $env:COMPUTERNAME -ScriptBlock {
 
	# Working variables
     param (
        $workingDir,
        $_Share,
        $_User,
        $_sasToken,
		$_certPassword,
		$_stsServiceName,
		$_DomainCreds,
		$_DomainName,
		$_CAComputerName,
		$_PublicCert
    )

    #connect to file share on storage account
    net use G: $_Share /u:$_User $_sasToken
    
    #go to our packages scripts folder
    Set-Location $workingDir


    
	if ($_PublicCert) {
		#Import public STS service root CA   
		$RootCAfilepath = "G:\cert\SSL_RootCA.crt"
		Import-Certificate -Filepath (get-childitem $RootCAfilepath) -CertStoreLocation Cert:\LocalMachine\Root -ErrorAction Continue

		#Install the certificate that will be used for ADFS Service
		$STScert = 'G:\cert\sts.'+$_DomainName+'.pfx'
		Import-PfxCertificate -Exportable -Password $_certPassword -CertStoreLocation cert:\localmachine\my -FilePath $STScert  
	}
	else {
		
		# Private CA for Online Request
		$CertificateAuthority = $_CAComputerName+'.'+$_DomainName+'\'+$_DomainName+'-CA'
	    $stsSubjectCN = "CN=" + $_stsServiceName
		Import-Module .\NewCertReq.ps1
		# Request Web Application Proxy certificate
		New-CertificateRequest -subject $stsSubjectCN -OnlineCA $CertificateAuthority
  	}   
	 
	#get thumbprint of certificate
	#$cert = Get-ChildItem -Path Cert:\LocalMachine\my | ?{$_.Subject -eq "CN=$_stsServiceName, OU=Free SSL, OU=Domain Control Validated"} 
	$certificateThumbprint = (get-childitem Cert:\LocalMachine\My | where {$_.subject -eq "CN="+$_stsServiceName} | Sort-Object -Descending NotBefore)[0].thumbprint
 
	#Export the STS certificate into the shared folder
	$STScert = 'G:\Share\sts.'+$_DomainName+'.pfx'
    Export-pfxCertificate -Cert (get-childitem Cert:\LocalMachine\My\$certificateThumbprint) -FilePath $STScert -Password $_certPassword -Force

	#Configure ADFS Farm
    Import-Module ADFS
	$FSDisplayName = "Welcome to "+ $_DomainName
	Install-AdfsFarm -CertificateThumbprint $certificateThumbprint -FederationServiceName $_stsServiceName -Credential $_DomainCreds `
	 -FederationServiceDisplayName $FSDisplayName -ServiceAccountCredential $_DomainCreds -OverwriteConfiguration 

	#Remove installation file Drive
	net use G: /d

	#Pin shortcuts to taskbar
   $sa = new-object -c shell.application
   $pn = $sa.namespace("C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Administrative Tools").parsename('Windows PowerShell ISE.lnk')
   $pn.invokeverb('taskbarpin')

} -ArgumentList $PSScriptRoot, $Share, $User, $sasToken, $SecureCertPassword, $StsServiceName, $DomainCreds, $DomainName, $CAComputerName, $PublicCertbool


#Disable-PSRemoting
#Disable-WSManCredSSP -role client
#Disable-WSManCredSSP -role server
Restart-Computer
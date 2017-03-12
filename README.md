# Azure SkypeforBusiness lab V2
Azure template for a Skype for Business

# Create a Skype for Business 2015 Standard Lab

This template will deploy and configure automatically a complete Skype for Business 2015 setup in a minimum of #3hr30min, a kind of onprem deployment lab, mainly for training and test purpose. 
This the second focus on Skype Hybrid with Shared Sip config with Office 365 which includes :
- VM-SFB-AD01 Active Directory
- VM-SFB-FE01 Skype for Business Front End Standard Edition
- VM-SFB-ADFS01 Adctive Directory Federation Service server mandatory for WAP reverse proxy deployment and used for SSO with Azure Active Directory
- VM-SFB-RP01 Reverse Proxy that publish Federation service and Skype URLs
- VM-SFB-EDGE01 Skype For Business EDGE Server fro remote connectivity, Hybrid and Federation purpose.

The Azure template will create the VM's, perform the installation of domain controller, windows feature , SfB software and perform all the configuration up to the creation of users. Azure DSC and scrpit extentions are leveraged.

Before starting the deployment there is some steps to follow:

1. Create an azure storage account with a fileshare named "skype" where Skype for Business software (content of the ISO) will be accessible.
2. Create a correct folder structure where to put SfB software see below
3. Download Skype for Business 2015 eval software and put the content of the ISO in "\skype\SfBserver2015\"
4. Download Skype Basic or Skype 2016 eval, rename it to "setup.exe" and put it in "\skype\SfB2016\"
5. Download Silverlight_x64.exe and Azure AD connect and put it in "\skype" folder
6. Download 3 mandatory Windows Server 2012 updtates (KB2919355, KB2919442, KB2982006) and put them into "\Skype" folder
7. Depending on whether Hybrid is needed or not a certificate request for public CA will be needed prior to installation (see below for guidlines)
7. Then Click the button below to deploy
8. You will have to fill some parameters like your storage account name and the sastoken as well as some other mandatory parameters like the dns prefix of your lab. Please remember to use only numbers plus lower case letters for your resource group name because it is concatenated to create a storage account name which support only lower case. Use Western Europe instead of Uk south it doesn't support yet the types of VM's used.


<a href="https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fibenbouzid%2FSkypeforBusiness_lab_V2%2Fmaster%2Fazuredeploy.json" target="_blank">
    <img src="http://azuredeploy.net/deploybutton.png"/>
</a>

<a href="http://armviz.io/#/?load=https%3A%2F%2Fraw.githubusercontent.com%2Fibenbouzid%2FSkypeforBusiness_lab_V2%2Fmaster%2Fazuredeploy.json" target="_blank">
    <img src="http://armviz.io/visualizebutton.png"/>
</a>

You can either deploy through the azure deploy button (which take less time) or via the azuredeploy.ps1 powershell script which requires to previously setup your machine with the right Azure modules.

# Storage Account and Folder Structure
The folder structure inside your storage account should look like this

<a >
<img src="https://raw.githubusercontent.com/ibenbouzid/SkypeforBusiness_lab_V2/master/images/FolderStructure.jpg"/>
</a>

Here is SfBServer2015 and SfB2016 folders components
<a >
<img src="https://raw.githubusercontent.com/ibenbouzid/SkypeforBusiness_lab_V2/master/images/SfBServer2015.jpg"/>
<img src="https://raw.githubusercontent.com/ibenbouzid/SkypeforBusiness_lab_V2/master/images/SfB2016.jpg"/>
</a>


# Software Download

You can download Skype for business eval version here :
https://www.microsoft.com/en-gb/evalcenter/evaluate-skype-for-business-server

And the Skype 2016 or Basic client Here
https://products.office.com/en-gb/skype-for-business/download-app?tab=tabs-3

Azure AD connect :
https://www.microsoft.com/en-us/download/details.aspx?id=47594

# Certificate Guidlines
The lab will need 3 certificates that will be exposed externally:
- sts.yourdomain.com.pfx (SSL for federation service url: whatever you want eg : sts.yourdomain.com)
- wap.yourdomain.com.pfx (SAN for Skype urls:SN:webext.yourdomain.com CN:webext.yourdomain.com,dialin.yourdomain.com,meet.yourdomain.com,lyncdiscover.yourdomain.com)
- edge.yourdomain.com.pfx (SSL for Access edge : sip.yourdomain.com)

For each of theses certificates the template gives you the option whether public or private. If Public is set to "false" the template will request a private CA from the domain controler. If public is set to "true" the template will expect that a public certificates is available and will try to download it from your storage account using the path "skype\cert"
One could be set to public and others to private for example if you are not able to buy a SAN certificate for WAP you could get a free Public SSL for the federation service this will enable hybrid and ADFS SSO testing but not Shared sip configuration.

It is possible to get free SSL through the Let's encrypt project : https://www.sslforfree.com/
Because not all public CA's are deployed to servers but mainly client you could add your public root CA into the folder "Skype\cert" with the name "SSL_RootCA.crt"

Certificate names: please respect carefully the certificate names above and give care to the case otherwise your 3 houres deployment will be unsucessful. Thoses certificates should be in pfx format (except SSL_RootCA.crt) and use the same password. There is many ways to convert other certificates format to pfx just ask the web.

# How to fillin parameters

 "domainName": The FQDN of the AD Domain eg: contoso.com or adatum.local
     
 "adminUsername": The name of the Administrator of all your VM's and Domain Admin
     
 "adminPassword": The password for the Administrator account: must be at least 12 caracters
    
 "ShareLocation": the name of your azure storage account - not the url - eg "mystorage" where you created your "skype" folder with all the source files 
 
 "ShareAccessKey": The token to used to access your storage account. You can find it on your storage account settings.

 "StsServiceName": The name of your ADFS service eg sts.contoso.com that is present in the SSL certificate

 "STSPublicCertificate": True if using public certificate for Federation Service

 "WAPPublicCertificate": True if using public certificate for Skype URL's
    
 "EdgePublicCertificate": True if using public certificate for Edge Server

 "CertificatePassword" : Only needed if at least one public certificate, should be the same password for all public certificate

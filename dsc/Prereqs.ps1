#
# Prereqs.ps1
#
Configuration Prereqs
{

Param (		
		[Parameter(Mandatory)]
        [String]$DomainName,

        [Parameter(Mandatory)]
        [PSCredential]$Admincreds,
		    
		[string]$Source = "G:\sources\sxs",
		[Int]$RetryCount=20,
        [Int]$RetryIntervalSec=30 )


Import-DscResource -ModuleName PSDesiredStateConfiguration, xPendingReboot, xDisk, cDisk
[PSCredential ]$DomainCreds = New-Object PSCredential ("${DomainName}\$($Admincreds.UserName)", $Admincreds.Password)

# Lync Server 2013 prerequisit features

  Node localhost
  {  
    	 # xPendingReboot Reboot1
      #{ 
      #      Name = "BeforePrereqsInstall"
      #}
      # Script PrereqsInstall
      #{
      #      SetScript = {

      #          Add-WindowsFeature -name "RSAT-DNS-Server","RSAT-ADDS","Web-Server","Web-Static-Content",`
	     #   "Web-Default-Doc","Web-Http-Errors", "Web-Asp-Net","Web-Net-Ext","Web-ISAPI-Ext","Web-ISAPI-Filter","Web-Http-Logging",`
	     #   "Web-Log-Libraries","Web-Request-Monitor","Web-Http-Tracing","Web-Basic-Auth","Web-Windows-Auth","Web-Client-Auth","Web-Filtering",`
	     #   "Web-Stat-Compression","Web-Dyn-Compression","NET-WCF-HTTP-Activation45","Web-Asp-Net45","Web-Mgmt-Tools","Web-Scripting-Tools","Web-Mgmt-Compat",`
      #  	"Desktop-Experience","BITS","Windows-Identity-Foundation","Server-Media-Foundation","Web-Dir-Browsing" -ErrorAction Continue   
      #      }
      #      GetScript =  { @{} }
      #      TestScript = { $false }
      #}
	  Script PrereqsInstall
      {
            SetScript = {

			Add-WindowsFeature -name "Desktop-Experience","BITS","Server-Media-Foundation"  -ErrorAction Continue

            }
            GetScript =  { @{} }
            TestScript = { $false }
      }
	    WindowsFeature DnsTools
	    {
	        Ensure = "Present"
            Name = "RSAT-DNS-Server"
	    }
		WindowsFeature RSATDNS 
        { 
            Ensure = "Present" 
            Name = "RSAT-ADDS"		
        }
        WindowsFeature WebServerRole
        {
            # Installs the following features
            <#
                Web-Server
                Web-WebServer
                Web-Common-Http
                Web-Default-Doc
                Web-Dir-Browsing
                Web-Http-Errors
                Web-Static-Content
                Web-Health
                Web-Http-Logging
                Web-Performance
                Web-Stat-Compression
                Web-Security
                Web-Filtering
            #>
            Name = "Web-Server"
            Ensure = "Present"
            Source = $Source
            }
        WindowsFeature WebAppDev
        {
            Name = "Web-App-Dev"
            Ensure = "Present"
            Source = $Source
            DependsOn = "[WindowsFeature]WebServerRole"
            }
        WindowsFeature WebAspNet
        {
            Name = "Web-Asp-Net"
            Ensure = "Present"
            Source = $Source
            DependsOn = "[WindowsFeature]WebServerRole"
            }
        WindowsFeature WebNetExt
        {
            Name = "Web-Net-Ext"
            Ensure = "Present"
            Source = $Source
            DependsOn = "[WindowsFeature]WebServerRole"
            }
        WindowsFeature WebISAPIExt
        {
            Name = "Web-ISAPI-Ext"
            Ensure = "Present"
            Source = $Source
            DependsOn = "[WindowsFeature]WebServerRole"
            }
        WindowsFeature WebISAPIFilter
        {
            Name = "Web-ISAPI-Filter"
            Ensure = "Present"
            Source = $Source
            DependsOn = "[WindowsFeature]WebServerRole"
            }
        WindowsFeature WebLogLibraries
        {
            Name = "Web-Log-Libraries"
            Ensure = "Present"
            Source = $Source
            DependsOn = "[WindowsFeature]WebServerRole"
            }
        WindowsFeature WebRequestMonitor
        {
            Name = "Web-Request-Monitor"
            Ensure = "Present"
            Source = $Source
            DependsOn = "[WindowsFeature]WebServerRole"
        }
		WindowsFeature WebHttpTracing
        {
            Name = "Web-Http-Tracing"
            Ensure = "Present"
            Source = $Source
            DependsOn = "[WindowsFeature]WebServerRole"
        }
		WindowsFeature WebBasicAuth
        {
            Name = "Web-Basic-Auth"
            Ensure = "Present"
            Source = $Source
            DependsOn = "[WindowsFeature]WebServerRole"
        }
		WindowsFeature WebWindowsAuth
        {
            Name = "Web-Windows-Auth"
            Ensure = "Present"
            Source = $Source
            DependsOn = "[WindowsFeature]WebServerRole"
        }
		WindowsFeature WebClientAuth
        {
            Name = "Web-Client-Auth"
            Ensure = "Present"
            Source = $Source
            DependsOn = "[WindowsFeature]WebServerRole"
        }
		WindowsFeature WebDynCompression
        {
            Name = "Web-Dyn-Compression"
            Ensure = "Present"
            Source = $Source
            DependsOn = "[WindowsFeature]WebServerRole"
        }
		WindowsFeature NETWCFHTTPActivation45
        {
            Name = "NET-WCF-HTTP-Activation45"
            Ensure = "Present"
            Source = $Source
            DependsOn = "[WindowsFeature]WebServerRole"
        }
		WindowsFeature WebAspNet45
        {
            Name = "Web-Asp-Net45"
            Ensure = "Present"
            Source = $Source
            DependsOn = "[WindowsFeature]WebServerRole"
        }
        WindowsFeature WebMgmtTools
        {
            Name = "Web-Mgmt-Tools"
            Ensure = "Present"
            Source = $Source
            DependsOn = "[WindowsFeature]WebServerRole"
            }
        WindowsFeature WebMgmtConsole
        {
            Name = "Web-Mgmt-Console"
            Ensure = "Present"
            Source = $Source
            DependsOn = "[WindowsFeature]WebServerRole"
        }
		WindowsFeature WebScriptingTools
        {
            Name = "Web-Scripting-Tools"
            Ensure = "Present"
            Source = $Source
            DependsOn = "[WindowsFeature]WebServerRole"
            }
        WindowsFeature WebMgmtCompat
        {
            Name = "Web-Mgmt-Compat"
            Ensure = "Present"
            Source = $Source
            DependsOn = "[WindowsFeature]WebServerRole"
        }
        #WindowsFeature BITS
        #{
        #    Name = "BITS"
        #    Ensure = "Present"
        #    Source = $Source
        #    DependsOn = "[WindowsFeature]WebServerRole"
        #}
		WindowsFeature WindowsIdentityFoundation
        {
            Name = "Windows-Identity-Foundation"
            Ensure = "Present"
            Source = $Source
            DependsOn = "[WindowsFeature]WebServerRole"
            }
        #WindowsFeature ServerMediaFoundation
        #{
        #    Name = "Server-Media-Foundation"
        #    Ensure = "Present"
        #    Source = $Source
        #    DependsOn = "[WindowsFeature]WebServerRole"
        #}
         xWaitforDisk Disk2
        {
             DiskNumber = 2
             RetryIntervalSec =$RetryIntervalSec
             RetryCount = $RetryCount
        }
		cDiskNoRestart ADDataDisk
        {
            DiskNumber = 2
            DriveLetter = "F"
        }
		  #WindowsFeature DesktopExperience
    #    {
    #        Name = "Desktop-Experience"
    #        Ensure = "Present"
    #        Source = $Source
    #        DependsOn = "[WindowsFeature]WebServerRole"
    #    }
	  xPendingReboot Reboot2
      { 
            Name = "AfterPrereqsInstall"
			DependsOn = "[WindowsFeature]WindowsIdentityFoundation", "[cDiskNoRestart]ADDataDisk"
      }

	  LocalConfigurationManager 
      {
            ConfigurationMode = 'ApplyOnly'
            RebootNodeIfNeeded = $true
            ActionAfterReboot = "ContinueConfiguration"
      }
  }
}
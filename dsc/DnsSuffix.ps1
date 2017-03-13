#
# DnsSuffix.ps1
#
Configuration DnsSuffix
{

Param (		
		[Parameter(Mandatory)]
        [String]$DomainName,

        [Int]$RetryCount=20,
        [Int]$RetryIntervalSec=30 )

Import-DscResource -ModuleName PSDesiredStateConfiguration, xPendingReboot, xDisk, cDisk


  Node localhost
  {  
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

       Script SetDNSSuffix 
      {
            SetScript = {  
			#Script to Change the DNS suffix     
			 Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\" -Name "NV Domain" -Value $using:DomainName
			 #Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\" -Name "Domain" -Value $using:$DomainName

			 #Reboot the machine
			  New-Item -Path HKLM:\SOFTWARE\MyMainKey\RebootKey -Force
             $global:DSCMachineStatus = 1 

            }
			TestScript = 
			{
				$currentSuffix = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\" -Name "NV Domain" -ErrorAction SilentlyContinue)."NV Domain"

				if ($currentSuffix -ne $using:DomainName){
				 return $false
				}
				return $true
			}   
			GetScript = 
			{
				$currentSuffix = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\" -Name "NV Domain" -ErrorAction SilentlyContinue)."NV Domain"

				return $currentSuffix
			}
		}
  
	  LocalConfigurationManager 
     {
            ConfigurationMode = 'ApplyOnly'
            RebootNodeIfNeeded = $true
            ActionAfterReboot = "ContinueConfiguration"
      }
  }
}
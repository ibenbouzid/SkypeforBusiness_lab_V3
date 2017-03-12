#
# NewCertReq.ps1
#
#source : https://blog.kloud.com.au/2013/07/30/ssl-san-certificate-request-and-import-from-powershell/
##
#
function New-CertificateRequest {
    param (
        [Parameter(Mandatory=$true, HelpMessage = "Please enter the subject beginning with CN=")]
        [ValidatePattern("CN=")]
        [string]$subject,
        [Parameter(Mandatory=$false, HelpMessage = "Please enter the SAN domains as a comma separated list")]
        [array]$SANs,
        [Parameter(Mandatory=$false, HelpMessage = "Please enter the Online Certificate Authority")]
        [string]$OnlineCA,
        [Parameter(Mandatory=$false, HelpMessage = "Please enter the Online Certificate Authority")]
        [string]$CATemplate = "WebServer"
    )
 
    ### Preparation
    $subjectDomain = $subject.split(',')[0].split('=')[1]
    if ($subjectDomain -match "\*.") {
        $subjectDomain = $subjectDomain -replace "\*", "star"
    }
    $CertificateINI = "$subjectDomain.ini"
    $CertificateREQ = "$subjectDomain.req"
    $CertificateRSP = "$subjectDomain.rsp"
    $CertificateCER = "$subjectDomain.cer"
 
    ### INI file generation
    new-item -type file $CertificateINI -force
    add-content $CertificateINI '[Version]'
    add-content $CertificateINI 'Signature="$Windows NT$"'
    add-content $CertificateINI ''
    add-content $CertificateINI '[NewRequest]'
    $temp = 'Subject="' + $subject + '"'
    add-content $CertificateINI $temp
    add-content $CertificateINI 'Exportable=TRUE'
    add-content $CertificateINI 'KeyLength=2048'
    add-content $CertificateINI 'KeySpec=1'
    add-content $CertificateINI 'KeyUsage=0xA0'
    add-content $CertificateINI 'MachineKeySet=True'
    add-content $CertificateINI 'ProviderName="Microsoft RSA SChannel Cryptographic Provider"'
    add-content $CertificateINI 'ProviderType=12'
    add-content $CertificateINI 'SMIME=FALSE'
    add-content $CertificateINI 'RequestType=PKCS10'
    add-content $CertificateINI '[Strings]'
    add-content $CertificateINI 'szOID_ENHANCED_KEY_USAGE = "2.5.29.37"'
    add-content $CertificateINI 'szOID_PKIX_KP_SERVER_AUTH = "1.3.6.1.5.5.7.3.1"'
    add-content $CertificateINI 'szOID_PKIX_KP_CLIENT_AUTH = "1.3.6.1.5.5.7.3.2"'
    if ($SANs) {
        add-content $CertificateINI 'szOID_SUBJECT_ALT_NAME2 = "2.5.29.17"'
        add-content $CertificateINI '[Extensions]'
        add-content $CertificateINI '2.5.29.17 = "{text}"'
 
        foreach ($SAN in $SANs) {
            $temp = '_continue_ = "dns=' + $SAN + '&"'
            add-content $CertificateINI $temp
        }
    }
 
    ### Certificate request generation
    if (test-path $CertificateREQ) {del $CertificateREQ}
    certreq -q -new $CertificateINI $CertificateREQ
 
    ### Online certificate request and import
    if ($OnlineCA) {
        if (test-path $CertificateCER) {del $CertificateCER}
        if (test-path $CertificateRSP) {del $CertificateRSP}
        certreq -q -submit -attrib "CertificateTemplate:$CATemplate" -config $OnlineCA $CertificateREQ $CertificateCER
 
        certreq -q -accept $CertificateCER
    }
}
# Call this script from a powershell command prompt using this command:
# Invoke-WebRequest -uri "https://raw.githubusercontent.com/SUBnet192/Build/master/Build-AdminJumpPoint.ps1" -UseBasicParsing | Invoke-Expression

function Get-WebFile {
<#  
.SYNOPSIS  
   Downloads a file from a web site.
.DESCRIPTION
   Downloads a file from a web site. 
.PARAMETER Url
    URL for the file to download.
.PARAMETER File
    The full path to receive the file.
.PARAMETER UseDefaultCredentials
    Use the currently authenticated user's credentials.  
.PARAMETER Proxy
    Used to connect via a proxy.
.PARAMETER Credential
    Provide alternate credentials.
.NOTES  
    Name: Get-WebFile
    Derived from Boe Prox's Get-WebPage
    See: http://poshcode.org/2498
    Author: Dave Hull
    DateCreated: 20140116
.EXAMPLE  
    Get-WebFile -url "http://www.bing.com/robots.txt" -file c:\temp\robots.txt
    
Description
------------
Returns the robots.txt file from bing.com
.EXAMPLE  
    Get-WebPage -url "http://www.bing.com/robots.txt" -file c:\temp\robots.txt
#> 
[cmdletbinding(
	DefaultParameterSetName = 'url',
	ConfirmImpact = 'low'
)]
    Param(
        [Parameter(
            Mandatory = $True,
            Position = 0,
            ParameterSetName = '',
            ValueFromPipeline = $True)]
            [string][ValidatePattern("^(http|https)\://*")]$Url,
        [Parameter(
            Position = 1,
            Mandatory = $False,
            ParameterSetName = 'defaultcred')]
            [switch]$UseDefaultCredentials,
        [Parameter(
            Mandatory = $False,
            ParameterSetName = '')]
            [string]$Proxy,
        [Parameter(
            Mandatory = $False,
            ParameterSetName = 'altcred')]
            [switch]$Credential,
        [Parameter(
            Mandatory = $True,
            ParameterSetName = '')]
            [string]$file                        
                        
        )
    Begin {     
        $psBoundParameters.GetEnumerator() | % { 
           Write-Verbose "Parameter: $_" 
        }
   
        $netAssembly = [Reflection.Assembly]::GetAssembly([System.Net.Configuration.SettingsSection])

        if($netAssembly) {
            $bindingFlags = [Reflection.BindingFlags] "Static,GetProperty,NonPublic"
            $settingsType = $netAssembly.GetType("System.Net.Configuration.SettingsSectionInternal")

            $instance = $settingsType.InvokeMember("Section", $bindingFlags, $null, $null, @())

            if($instance) {
                $bindingFlags = "NonPublic","Instance"
                $useUnsafeHeaderParsingField = $settingsType.GetField("useUnsafeHeaderParsing", $bindingFlags)

                if($useUnsafeHeaderParsingField) {
                    $useUnsafeHeaderParsingField.SetValue($instance, $true)
                }
            }
        }

        #Create the initial WebClient object
        Write-Verbose "Creating web client object"
        $wc = New-Object Net.WebClient 
    
        #Use Proxy address if specified
        If ($PSBoundParameters.ContainsKey('Proxy')) {
            #Create Proxy Address for Web Request
            Write-Verbose "Creating proxy address and adding into Web Request"
            $wc.Proxy = New-Object -TypeName Net.WebProxy($proxy,$True)
        }       
        #Determine if using Default Credentials
        If ($PSBoundParameters.ContainsKey('UseDefaultCredentials')) {
            #Set to True, otherwise remains False
            Write-Verbose "Using Default Credentials"
            $wc.UseDefaultCredentials = $True
        }
        #Determine if using Alternate Credentials
        If ($PSBoundParameters.ContainsKey('Credentials')) {
            #Prompt for alternate credentals
            Write-Verbose "Prompt for alternate credentials"
            $wc.Credential = (Get-Credential).GetNetworkCredential()
        }         
        
    }
    Process {    
        Try {
            #Get the contents of the webpage
            Write-Verbose "Downloading file from web site"
            $wc.DownloadFile($url, $file)       
        } Catch {
            Write-Warning "$($Error[0])"
        }   
    }
}

# Force TLS 1.2 (Required by PowerShell Gallery and Chocolatey)
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Preparation
Set-PSRepository PSGallery -InstallationPolicy Trusted
Set-ExecutionPolicy RemoteSigned -Force

# Create work folders
New-Item -Path C:\ -Name Scripts -ItemType Directory -Force
New-Item -Path C:\ -Name Sources -ItemType Directory -Force

# Create default powershell profile for All Users / All Hosts
Get-WebFile -URL "https://raw.githubusercontent.com/SUBnet192/Build/master/psprofile.ps1" -File $PROFILE.AllusersAllHosts

# Install RSAT
Install-WindowsFeature -IncludeAllSubFeature RSAT

# Install Microsoft Cloud Services Powershell modules
Install-Module -Name Az
Install-Module -Name AzureAD
Install-Module -Name MSOnline
Install-Module -Name Microsoft.Graph
Install-Module -Name ExchangeOnlineManagement
Install-Module -Name MicrosoftTeams

# Install VMware PowerCLI
Install-Module -Name VMware.PowerCLI -AllowClobber
Set-PowerCLIConfiguration -Scope AllUsers -ParticipateInCEIP $false -InvalidCertificateAction Ignore -confirm:$false 

#Miscellaneous Powershell Modules - Ignore missing modules warnings, a reboot is required.
Install-Module -Name Orca
Install-Module -Name Testimo
Install-Module -Name DSInternals
Install-Module -Name PSPKI
Install-Module -Name dbatools
Install-Module -Name Evergreen
Find-Module -Name SUBNET192* | Install-Module

# Chocolatey tools
 Set-ExecutionPolicy Bypass -Scope Process -Force; Invoke-WebRequest -uri "https://chocolatey.org/install.ps1" -UseBasicParsing | Invoke-Expression
 Choco install chocolateygui -y

 # Essential tools
 Choco install notepadplusplus -y
 Choco install googlechrome -y
 Choco install adobereader -y
 Choco install 7zip -y
 Choco install winscp -y
 Choco install filezilla -y
 Choco install openssh -y
 Choco install git -y
 Choco install ad-tidy-free -y

 # Microsoft Tools
 Choco install sysinternals -y
 Choco install vscode -y
 Choco install vscode-powershell -y
 Choco install azcopy -y

 # SQL Related
 Choco install sql-server-management-studio -y
 Choco install dbatools -y

 # Vmware related
 Choco install rvtools -y

# Remove Hyper-V
Disable-WindowsOptionalFeature -Online -FeatureName RSAT-Hyper-V-Tools-Feature
DISM /Online /Disable-Feature:Microsoft-Hyper-V

# SpecOps GPUpdate
Get-WebFile -URL "https://download.specopssoft.com/Release/gpupdate/specopsgpupdatesetup.exe" -File C:\Sources\specops.exe
7z x C:\Sources\specops.exe -oC:\Temp\
Start-Process -FilePath "$env:systemroot\system32\msiexec.exe" -ArgumentList '/i "C:\Temp\Products\SpecOpsGPUpdate\SpecopsGpupdate-x64.msi"' -Wait
Remove-Item -Path C:\Temp -Recurse -Force

# Install WAC
$dlPath = 'C:\Sources\WAC.msi'
Get-WebFile -URL 'http://aka.ms/WACDownload' -File $dlPath

$port = 443
msiexec /i $dlPath /qn /L*v log.txt SME_PORT=$port SSL_CERTIFICATE_OPTION=generate

# Reboot to complete installation
Restart-Computer

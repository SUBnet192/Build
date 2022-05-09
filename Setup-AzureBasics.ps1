# Call this script from a powershell command prompt using this command:
# Invoke-WebRequest -usebasicparsing -uri "https://raw.githubusercontent.com/SUBnet192/Build/master/Setup-AzureBasics.ps1" | Invoke-Expression

# Trust PowerShell Gallery
Set-PSRepository PSGallery -InstallationPolicy Trusted | Out-Null

# Install Default Modules
Install-Module -Name PSWindowsUpdate | Out-Null

# Set Execution Policy
Set-ExecutionPolicy RemoteSigned -Force | Out-Null

# Create Default Script Path
New-Item -Path C:\ -Name Scripts -ItemType Directory -Force | Out-Null

# Set Timezone
Set-Timezone "Eastern Standard Time"

# Enable Remote Desktop
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server'-name "fDenyTSConnections" -Value 0

# Create default powershell profile for All Users / All Hosts
Invoke-WebRequest -usebasicparsing -Uri "https://raw.githubusercontent.com/SUBnet192/Build/master/psprofile.ps1" -Outfile $PROFILE.AllusersAllHosts

# Execute Windows Update
Install-WindowsUpdate -Confirm: $False

# Reboot to complete installation
Restart-Computer

# Call this script from a powershell command prompt using this command:
# Invoke-WebRequest -usebasicparsing -uri "https://raw.githubusercontent.com/SUBnet192/Build/master/Setup-CoreBasics.ps1" | Invoke-Expression

# Set Powershell as default shell
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\' -Name Shell -Value 'powershell.exe' | Out-Null

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

# Set CD-ROM to R:
Set-WmiInstance -InputObject ( Get-WmiObject -Class Win32_volume -Filter "DriveLetter = 'd:'" ) -Arguments @{DriveLetter='r:'}

# Install latest VMware Tools
# https://raw.githubusercontent.com/haavarstein/Applications/master/VMware/Tools/Install.ps1
Invoke-WebRequest -usebasicparsing -uri "https://raw.githubusercontent.com/haavarstein/Applications/master/VMware/Tools/Install.ps1" | Invoke-Expression

# Create default powershell profile for All Users / All Hosts
Invoke-WebRequest -usebasicparsing -Uri "https://raw.githubusercontent.com/SUBnet192/Build/master/psprofile.ps1" -Outfile $PROFILE.AllusersAllHosts

# Format new hard disks if available
Get-Disk | Where partitionstyle -eq 'raw' | Initialize-Disk -PartitionStyle GPT -PassThru | New-Partition -AssignDriveLetter -UseMaximumSize | Format-Volume -FileSystem NTFS -Confirm:$false

# Execute Windows Update
Install-WindowsUpdate -Confirm: $False

# Reboot to complete installation
Restart-Computer

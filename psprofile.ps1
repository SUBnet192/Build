#======================================================================================
# Enable TLS 1.2
#======================================================================================

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

#======================================================================================
# Set UTF-8 output for french accents
#======================================================================================

$OutputEncoding = [console]::InputEncoding = [console]::OutputEncoding = New-Object System.Text.UTF8Encoding

#======================================================================================
# Set console color scheme
#======================================================================================

$console = $host.ui.rawui
$console.BackgroundColor = 'Black'
$console.ForegroundColor = 'White'
$colors = $Host.PrivateData
$colors.ErrorForegroundColor = 'Red'
$colors.ErrorBackgroundColor = 'Black'
$colors.WarningForegroundColor = 'Yellow'
$colors.WarningBackgroundColor = 'Black'
$colors.DebugForegroundColor = 'Yellow'
$colors.DebugBackgroundColor = 'Black'
$colors.VerboseForegroundColor = 'Green'
$colors.VerboseBackgroundColor = 'Black'
$colors.ProgressForegroundColor = 'Gray'
$colors.ProgressBackgroundColor = 'Black'
Clear-Host

#======================================================================================
# Ctrl-Tab to show matching commands/available parameters
#======================================================================================

Set-PSReadLineKeyHandler -Chord CTRL+Tab -Function Complete
Set-PSReadLineOption -ShowToolTips -BellStyle Visual

#======================================================================================
# function Edit PowerShell Profile
#======================================================================================

function Edit-PSProfile()
{ 
   code $PROFILE.AllUsersAllHosts 
}

#======================================================================================
# function Update Powershell Profile
#======================================================================================

function Update-PSProfile
{
   Invoke-WebRequest -UseBasicParsing -Uri "https://raw.githubusercontent.com/SUBnet192/Scripts/master/psprofile.ps1" -OutFile $PROFILE.AllusersAllHosts
}

#======================================================================================
# function Set Modules Update Scheduled Task
#======================================================================================

function Set-ModulesUpdateSchedule
{
   $trigger = New-ScheduledTaskTrigger -Daily -At 5am;
   $action = New-ScheduledTaskAction -Execute "powershell.exe" `
      -Argument '-Command "Start-Transcript %USERPROFILE%\ModulesUpdate.log; Update-EveryModule -Verbose"'

   $task = Get-ScheduledTask -TaskName 'Update Every PSModule' -ErrorAction:SilentlyContinue
   if ($null -eq $task)
   {
      Register-ScheduledTask -Action $action -Trigger $trigger -TaskName "Update Every PSModule" -RunLevel Highest
   }
}

#======================================================================================
# function Update Every Module
#======================================================================================

function Update-EveryModule
{
   <#
   .SYNOPSIS
   Updates all modules from the PowerShell gallery.
   .DESCRIPTION
   Updates all local modules that originated from the PowerShell gallery.
   Removes all old versions of the modules.
   .PARAMETER ExcludedModules
   Array of modules to exclude from updating.
   .PARAMETER SkipMajorVersion
   Skip major version updates to account for breaking changes.
   .PARAMETER KeepOldModuleVersions
   Array of modules to keep the old versions of.
   .PARAMETER ExcludedModulesforRemoval
   Array of modules to exclude from removing old versions of.
   The Az module is excluded by default.
   .EXAMPLE
   Update-EveryModule -excludedModulesforRemoval 'Az'
   .NOTES
   Created by Barbara Forbes
   @ba4bes
   .LINK
   https://4bes.nl
   #>

   [cmdletbinding(SupportsShouldProcess = $true)]
   param (
      [parameter()]
      [array]$ExcludedModules = @(),
      [parameter()]
      [switch]$SkipMajorVersion,
      [parameter()]
      [switch]$KeepOldModuleVersions,
      [parameter()]
      [array]$ExcludedModulesforRemoval = @("Az")
   )

   # Get all installed modules that have a newer version available
   Write-Verbose "Checking all installed modules for available updates."
   $CurrentModules = Get-InstalledModule | Where-Object { $ExcludedModules -notcontains $_.Name -and $_.repository -eq "PSGallery" }

   # Walk through the Installed modules and check if there is a newer version
   $CurrentModules | ForEach-Object {
      Write-Verbose "Checking $($_.Name)"
      Try
      {
         $GalleryModule = Find-Module -Name $_.Name -Repository PSGallery -ErrorAction Stop
      }
      Catch
      {
         Write-Error "Module $($_.Name) not found in gallery $_"
         $GalleryModule = $null
      }
      if ($GalleryModule.Version -gt $_.Version)
      {
         if ($SkipMajorVersion -and $GalleryModule.Version.Split('.')[0] -gt $_.Version.Split('.')[0])
         {
            Write-Warning "Skipping major version update for module $($_.Name). Galleryversion: $($GalleryModule.Version), local version $($_.Version)"
         }
         else
         {
            Write-Verbose "$($_.Name) will be updated. Galleryversion: $($GalleryModule.Version), local version $($_.Version)"
            try
            {
               if ($PSCmdlet.ShouldProcess(
                        ("Module {0} will be updated to version {1}" -f $_.Name, $GalleryModule.Version),
                     $_.Name,
                     "Update-Module"
                  )
               )
               {
                  Update-Module $_.Name -ErrorAction Stop -Force
                  Write-Verbose "$($_.Name)  has been updated"
               }
            }
            Catch
            {
               Write-Error "$($_.Name) failed: $_ "
               continue
            }
            if ($KeepOldModuleVersions -ne $true)
            {
               Write-Verbose "Removing old module $($_.Name)"
               if ($ExcludedModulesforRemoval -contains $_.Name)
               {
                  Write-Verbose "$($allversions.count) versions of this module found [ $($module.name) ]"
                  Write-Verbose "Please check this manually as removing the module can cause instabillity."
               }
               else
               {
                  try
                  {
                     if ($PSCmdlet.ShouldProcess(
                        ("Old versions will be uninstalled for module {0}" -f $_.Name), $_.Name, "Uninstall-Module"
                        )
                     )
                     {
                        Get-InstalledModule -Name $_.Name -AllVersions | Where-Object { $_.version -ne $GalleryModule.Version } | Uninstall-Module -Force -ErrorAction Stop
                        Write-Verbose "Old versions of $($_.Name) have been removed"
                     }
                  }
                  catch
                  {
                     Write-Error "Uninstalling old module $($_.Name) failed: $_"
                  }
               }
            }
         }
      }
      elseif ($null -ne $GalleryModule)
      {
         Write-Verbose "$($_.Name) is up to date"
      }
   }
}


#======================================================================================
# Get Activation Status
#======================================================================================

function Get-ActivationStatus {
[CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [string]$DNSHostName = $Env:COMPUTERNAME
    )
    process {
        try {
            $wpa = Get-WmiObject SoftwareLicensingProduct -ComputerName $DNSHostName `
            -Filter "ApplicationID = '55c92734-d682-4d71-983e-d6ec3f16059f'" `
            -Property LicenseStatus -ErrorAction Stop
        } catch {
            $status = New-Object ComponentModel.Win32Exception ($_.Exception.ErrorCode)
            $wpa = $null    
        }
        $out = New-Object psobject -Property @{
            ComputerName = $DNSHostName;
            Status = [string]::Empty;
        }
        if ($wpa) {
            :outer foreach($item in $wpa) {
                switch ($item.LicenseStatus) {
                    0 {$out.Status = "Unlicensed"}
                    1 {$out.Status = "Licensed"; break outer}
                    2 {$out.Status = "Out-Of-Box Grace Period"; break outer}
                    3 {$out.Status = "Out-Of-Tolerance Grace Period"; break outer}
                    4 {$out.Status = "Non-Genuine Grace Period"; break outer}
                    5 {$out.Status = "Notification"; break outer}
                    6 {$out.Status = "Extended Grace"; break outer}
                    default {$out.Status = "Unknown value"}
                }
            }
        } else {$out.Status = $status.Message}
        $out
    }
}

#======================================================================================
# Clear All Event Logs
#======================================================================================

function Clear-AllEventLogs
{
   param([switch] $quiet)

   $count = 0
   $size = 0
   $skip = 0

	(Get-WinEvent -ListLog * -Force -ErrorAction SilentlyContinue) | ForEach-Object {
      if ($_.RecordCount -gt 0)
      {
         if (!$quiet) { Write-Host '.' -NoNewline }
         $name = $_.LogName
         try
         {
            # Here we use the .NET API directly rather than 'wevtutil 'cl'. Just as fast.

            $size += $_.FileSize
            [System.Diagnostics.Eventing.Reader.EventLogSession]::GlobalSession.ClearLog($name)
            $count++
         }
         catch
         {
            $skip++
         }
      }
   }

   if (!$quiet)
   {
      [double] $kb = $size / 1024
      Write-Host "`n"
      Write-Host("Cleared {0} logs saving {1} KB" -f $count, $kb) -Foreground DarkYellow

      if ($skip -gt 0)
      {
         Write-Host("Skipped {0} logs" -f $skip) -Foreground DarkYellow
      }
   }
}

#======================================================================================
# Clear Temp Folders
#======================================================================================

function Clear-TempFolders
{
   param([switch] $Quiet)

   function ClearFolder
   {
      param($path)

      if (!(Test-Path $path)) { return }

      $fils = [System.IO.Directory]::GetFiles($path, '*').Count
      $dirs = [System.IO.Directory]::GetDirectories($path, '*').Count

      Write-Verbose "... clearing $path"
      Remove-Item -Path "$path\*" -Force -Recurse -ErrorAction:SilentlyContinue

      $fc = $fils - [System.IO.Directory]::GetFiles($path, '*').Count
      $dc = $dirs - [System.IO.Directory]::GetDirectories($path, '*').Count

      $script:filCount += $fc
      $script:dirCount += $dc

      if (!$Quiet)
      {
         Write-Host "... removed $fc files, $dc directories from $path" -ForegroundColor DarkGray
      }
   }
   $used = (Get-PSDrive C).Used
   $script:filCount = 0
   $script:dirCount = 0

   ClearFolder 'C:\Temp'
   ClearFolder 'C:\Tmp'
   ClearFolder 'C:\Windows\Temp'
   ClearFolder (Join-Path $env:LocalAppData 'Temp')

   if (!$Quiet)
   {
      $disk = Get-PSDrive C | Select-Object Used, Free
      $pct = ($disk.Used / ($disk.Used + $disk.Free)) * 100
      $recovered = $used - $disk.Used
      Write-Host "... removed $filCount files, $dirCount directories"
      Write-Host ("... recovered {0:0.00} MB on drive C, {1:0.00}% used" -f ($recovered / 1024000), $pct)
   }
}

#======================================================================================
# Unblock downloaded files
#======================================================================================

function Unblock-DownloadedFiles
{
	Get-ChildItem .\ -Recurse | Unblock-File
}

#======================================================================================
# Get Mount Points
#======================================================================================

function Get-Mountpoints
{
   $TotalGB = @{Name = "Capacity(GB)"; expression = { [math]::round(($_.Capacity / 1073741824), 2) } }
   $FreeGB = @{Name = "FreeSpace(GB)"; expression = { [math]::round(($_.FreeSpace / 1073741824), 2) } }
   $FreePerc = @{Name = "Free(%)"; expression = { [math]::round(((($_.FreeSpace / 1073741824) / ($_.Capacity / 1073741824)) * 100), 0) } }
   $volumes = Get-WmiObject win32_volume | Where-Object { $null -eq $_.DriveLetter }
   $volumes | Select-Object SystemName, Label, $TotalGB, $FreeGB, $FreePerc
}

#======================================================================================
# Find Empty Folders
#======================================================================================

function Find-EmptyFolders
{
(Get-ChildItem C:\Scripts -r | Where-Object { $_.PSIsContainer -eq $True }) | Where-Object { $_.GetFileSystemInfos().Count -eq 0 } | Select-Object FullName
}

#======================================================================================
# Test if Administrative session
#======================================================================================

function Test-Administrator
{  
   $user = [Security.Principal.WindowsIdentity]::GetCurrent()
   (New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)  
}

#======================================================================================
# Start Elevated session
#======================================================================================

function Start-PsElevatedSession
{ 
   #Open a new elevated powershell window
   If ( ! (Test-Administrator) )
   {
      Start-Process powershell -Verb runas
   }
   Else { Write-Warning "Session is already elevated" }
} 

#======================================================================================
# function Edit Hosts file
#======================================================================================

function Edit-Hosts
{
   $file = "$env:windir\System32\drivers\etc\hosts"
   if (!(Test-Path $file))
   {
      Write-Host "... cannot find $file" -ForegroundColor Yellow
      return
   }
   Start-PsElevatedSession

   if (Get-Command 'code.cmd')
   {
      # npp handles files without extensions directly
      code $file
   }
   else
   {
      notepad $file
   }
}

#======================================================================================

function Show-MOTD
{
   # Perform WMI Queries
   $Wmi_OperatingSystem = Get-WmiObject -Query 'Select lastbootuptime,TotalVisibleMemorySize,FreePhysicalMemory,caption,version From win32_operatingsystem'
   $Wmi_Processor = Get-WmiObject -Query 'Select Name From Win32_Processor'
   $Wmi_LogicalDisk = Get-WmiObject -Query 'Select Size,FreeSpace From Win32_LogicalDisk Where DeviceID="C:"'

   # Assign variables
   $Date = Get-Date
   $OS = $Wmi_Operatingsystem.Caption	
   $Kernel = $Wmi_Operatingsystem.Version
   $Uptime = "$(($Uptime = $Date - $Wmi_Operatingsystem.ConvertToDateTime($Wmi_Operatingsystem.LastBootUpTime)).Days) days, $($Uptime.Hours) hours, $($Uptime.Minutes) minutes"
   $Shell = "{0}.{1}" -f $PSVersionTable.PSVersion.Major, $PSVersionTable.PSVersion.Minor
   $CPU = $Wmi_Processor.Name -replace '\(C\)', '' -replace '\(R\)', '' -replace '\(TM\)', '' -replace 'CPU', '' -replace '\s+', ' '
   $Memory = "{0}mb/{1}mb Used" -f (([math]::round($Wmi_Operatingsystem.TotalVisibleMemorySize / 1KB)) - ([math]::round($Wmi_Operatingsystem.FreePhysicalMemory / 1KB))), ([math]::round($Wmi_Operatingsystem.TotalVisibleMemorySize / 1KB))
   $Disk = "{0}gb/{1}gb Used" -f (([math]::round($Wmi_LogicalDisk.Size / 1GB)) - ([math]::round($Wmi_LogicalDisk.FreeSpace / 1GB))), ([math]::round($Wmi_LogicalDisk.Size / 1GB))

   Write-Host ("")
   Write-Host ("")
   Write-Host ("         ,.=:^!^!t3Z3z.,                  ") -ForegroundColor Red
   Write-Host ("        :tt:::tt333EE3                    ") -ForegroundColor Red
   Write-Host ("        Et:::ztt33EEE ") -NoNewline -ForegroundColor Red
   Write-Host (" @Ee.,      ..,     ") -NoNewline -ForegroundColor Green
   Write-Host $Date -ForegroundColor Green
   Write-Host ("       ;tt:::tt333EE7") -NoNewline -ForegroundColor Red
   Write-Host (" ;EEEEEEttttt33#     ") -ForegroundColor Green
   Write-Host ("      :Et:::zt333EEQ.") -NoNewline -ForegroundColor Red
   Write-Host (" SEEEEEttttt33QL     ") -NoNewline -ForegroundColor Green
   Write-Host ("User: ") -NoNewline -ForegroundColor Red
   Write-Host ("$env:username") -ForegroundColor Cyan
   Write-Host ("      it::::tt333EEF") -NoNewline -ForegroundColor Red
   Write-Host (" @EEEEEEttttt33F      ") -NoNewline -ForegroundColor Green
   Write-Host ("Hostname: ") -NoNewline -ForegroundColor Red
   Write-Host ("$env:computername") -ForegroundColor Cyan
   Write-Host ("     ;3=*^``````'*4EEV") -NoNewline -ForegroundColor Red
   Write-Host (" :EEEEEEttttt33@.      ") -NoNewline -ForegroundColor Green
   Write-Host ("OS: ") -NoNewline -ForegroundColor Red
   Write-Host $OS -ForegroundColor Cyan
   Write-Host ("     ,.=::::it=., ") -NoNewline -ForegroundColor Cyan
   Write-Host ("``") -NoNewline -ForegroundColor Red
   Write-Host (" @EEEEEEtttz33QF       ") -NoNewline -ForegroundColor Green
   Write-Host ("Kernel: ") -NoNewline -ForegroundColor Red
   Write-Host ("NT ") -NoNewline -ForegroundColor Cyan
   Write-Host $Kernel -ForegroundColor Cyan
   Write-Host ("    ;::::::::zt33) ") -NoNewline -ForegroundColor Cyan
   Write-Host ("  '4EEEtttji3P*        ") -NoNewline -ForegroundColor Green
   Write-Host ("Uptime: ") -NoNewline -ForegroundColor Red
   Write-Host $Uptime -ForegroundColor Cyan
   Write-Host ("   :t::::::::tt33.") -NoNewline -ForegroundColor Cyan
   Write-Host (":Z3z.. ") -NoNewline -ForegroundColor Yellow
   Write-Host (" ````") -NoNewline -ForegroundColor Green
   Write-Host (" ,..g.        ") -NoNewline -ForegroundColor Yellow
   Write-Host ("Shell: ") -NoNewline -ForegroundColor Red
   Write-Host ("Powershell $Shell") -ForegroundColor Cyan
   Write-Host ("   i::::::::zt33F") -NoNewline -ForegroundColor Cyan
   Write-Host (" AEEEtttt::::ztF         ") -NoNewline -ForegroundColor Yellow
   Write-Host ("") -ForegroundColor Cyan
   Write-Host ("  ;:::::::::t33V") -NoNewline -ForegroundColor Cyan
   Write-Host (" ;EEEttttt::::t3          ") -NoNewline -ForegroundColor Yellow
   Write-Host ("") -ForegroundColor Cyan
   Write-Host ("  E::::::::zt33L") -NoNewline -ForegroundColor Cyan
   Write-Host (" @EEEtttt::::z3F          ") -NoNewline -ForegroundColor Yellow
   Write-Host ("CPU: ") -NoNewline -ForegroundColor Red
   Write-Host $CPU[0] -ForegroundColor Cyan
   Write-Host (" {3=*^``````'*4E3)") -NoNewline -ForegroundColor Cyan
   Write-Host (" ;EEEtttt:::::tZ``          ") -NoNewline -ForegroundColor Yellow
   Write-Host ("Memory: ") -NoNewline -ForegroundColor Red
   Write-Host $Memory -ForegroundColor Cyan
   Write-Host ("             ``") -NoNewline -ForegroundColor Cyan
   Write-Host (" :EEEEtttt::::z7            ") -NoNewline -ForegroundColor Yellow
   Write-Host ("Disk: ") -NoNewline -ForegroundColor Red
   Write-Host $Disk -ForegroundColor Cyan
   Write-Host ("                 'VEzjt:;;z>*``           ") -ForegroundColor Yellow
   Write-Host ("                      ````                  ") -ForegroundColor Yellow
   Write-Host ("")
}

#======================================================================================
# 'Go' command and targets
#======================================================================================

$GLOBAL:go_locations = @{ }

if ( $GLOBAL:go_locations -eq $null )
{
   $GLOBAL:go_locations = @{ }
}

function Go ([string] $location)
{
   if ( $go_locations.ContainsKey($location) )
   {
      Set-Location $go_locations[$location];
   }
   else
   {
      Write-Output "The following locations are defined:";
      Write-Output $go_locations;
   }
}
$go_locations.Add("home", (Get-Item ([environment]::GetFolderPath("MyDocuments"))).Parent.FullName)
$go_locations.Add("desktop", [environment]::GetFolderPath("Desktop"))
$go_locations.Add("dl", ((New-Object -ComObject Shell.Application).NameSpace('shell:Downloads').Self.Path))
$go_locations.Add("docs", [environment]::GetFolderPath("MyDocuments"))
$go_locations.Add("scripts", "C:\Scripts")

#======================================================================================
# Custom prompt
#======================================================================================

function Global:Prompt
{
   $Time = Get-Date -Format "HH:mm"
   $Directory = (Get-Location).Path
   Write-Host "[$((Get-History).Count + 1)] " -NoNewline
   Write-Host "[$Time] " -ForegroundColor Yellow -NoNewline
   Write-Host "$Directory >" -NoNewline

   return " "
}

#======================================================================================
# Define aliases
#======================================================================================

Set-Alias -Name su -Value Start-PsElevatedSession
Set-Alias -Name Reboot -Value Restart-Computer
Set-Alias -Name Halt -Value Stop-Computer

#======================================================================================
# Final execution
#======================================================================================

Set-ExecutionPolicy RemoteSigned -Scope CurrentUser -Force
Go scripts

#======================================================================================
# Some Sysadmin sillyness
#======================================================================================

Show-MOTD

Write-Host $block -ForegroundColor Green

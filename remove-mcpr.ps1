<#
Version: 1.1
Author: Oliver Kieselbach
Script: IntunePSTemplate.ps1
Description:
Intune Management Extension - PowerShell script template with logging,
error codes, standard error output handling and x64 PowerShell execution.
Release notes:
Version 1.0: Original published version. 
Version 1.1: Added standard error output handling. 
The script is provided "AS IS" with no warranties.
#>

$exitCode = 0



if (![System.Environment]::Is64BitProcess)
{
     # start new PowerShell as x64 bit process, wait for it and gather exit code and standard error output
    $sysNativePowerShell = "$($PSHOME.ToLower().Replace("syswow64", "sysnative"))\powershell.exe"

    $pinfo = New-Object System.Diagnostics.ProcessStartInfo
    $pinfo.FileName = $sysNativePowerShell
    $pinfo.Arguments = "-ex bypass -file `"$PSCommandPath`""
    $pinfo.RedirectStandardError = $true
    $pinfo.RedirectStandardOutput = $true
    $pinfo.CreateNoWindow = $true
    $pinfo.UseShellExecute = $false
    $p = New-Object System.Diagnostics.Process
    $p.StartInfo = $pinfo
    $p.Start() | Out-Null

    $exitCode = $p.ExitCode

    $stderr = $p.StandardError.ReadToEnd()

    if ($stderr) { Write-Error -Message $stderr }
}
else
{
    # start logging to TEMP in file "scriptname".log
    Start-Transcript -Path "$env:TEMP\$($(Split-Path $PSCommandPath -Leaf).ToLower().Replace(".ps1",".log"))" | Out-Null



    try {

        function Get-InstalledApplications() {
            [cmdletbinding(DefaultParameterSetName = 'GlobalAndAllUsers')]
        
            Param (
                [Parameter(ParameterSetName="Global")]
                [switch]$Global,
                [Parameter(ParameterSetName="GlobalAndCurrentUser")]
                [switch]$GlobalAndCurrentUser,
                [Parameter(ParameterSetName="GlobalAndAllUsers")]
                [switch]$GlobalAndAllUsers,
                [Parameter(ParameterSetName="CurrentUser")]
                [switch]$CurrentUser,
                [Parameter(ParameterSetName="AllUsers")]
                [switch]$AllUsers
            )
        
            # Excplicitly set default param to True if used to allow conditionals to work
            if ($PSCmdlet.ParameterSetName -eq "GlobalAndAllUsers") {
                $GlobalAndAllUsers = $true
            }
        
            # Check if running with Administrative privileges if required
            if ($GlobalAndAllUsers -or $AllUsers) {
                $RunningAsAdmin = (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
                if ($RunningAsAdmin -eq $false) {
                    Write-Error "Finding all user applications requires administrative privileges"
                    break
                }
            }
        
            # Empty array to store applications
            $Apps = @()
            $32BitPath = "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
            $64BitPath = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
        
            # Retreive globally insatlled applications
            if ($Global -or $GlobalAndAllUsers -or $GlobalAndCurrentUser) {
                Write-Host "Processing global hive"
                $Apps += Get-ItemProperty "HKLM:\$32BitPath"
                $Apps += Get-ItemProperty "HKLM:\$64BitPath"
            }
        
            if ($CurrentUser -or $GlobalAndCurrentUser) {
                Write-Host "Processing current user hive"
                $Apps += Get-ItemProperty "Registry::\HKEY_CURRENT_USER\$32BitPath"
                $Apps += Get-ItemProperty "Registry::\HKEY_CURRENT_USER\$64BitPath"
            }
        
            if ($AllUsers -or $GlobalAndAllUsers) {
                Write-Host "Collecting hive data for all users"
                $AllProfiles = Get-CimInstance Win32_UserProfile | Select LocalPath, SID, Loaded, Special | Where {$_.SID -like "S-1-5-21-*"}
                $MountedProfiles = $AllProfiles | Where {$_.Loaded -eq $true}
                $UnmountedProfiles = $AllProfiles | Where {$_.Loaded -eq $false}
        
                Write-Host "Processing mounted hives"
                $MountedProfiles | % {
                    $Apps += Get-ItemProperty -Path "Registry::\HKEY_USERS\$($_.SID)\$32BitPath"
                    $Apps += Get-ItemProperty -Path "Registry::\HKEY_USERS\$($_.SID)\$64BitPath"
                }
        
                Write-Host "Processing unmounted hives"
                $UnmountedProfiles | % {
        
                    $Hive = "$($_.LocalPath)\NTUSER.DAT"
                    Write-Host " -> Mounting hive at $Hive"
        
                    if (Test-Path $Hive) {
                    
                        REG LOAD HKU\temp $Hive
        
                        $Apps += Get-ItemProperty -Path "Registry::\HKEY_USERS\temp\$32BitPath"
                        $Apps += Get-ItemProperty -Path "Registry::\HKEY_USERS\temp\$64BitPath"
        
                        # Run manual GC to allow hive to be unmounted
                        [GC]::Collect()
                        [GC]::WaitForPendingFinalizers()
                    
                        REG UNLOAD HKU\temp
        
                    } else {
                        Write-Warning "Unable to access registry hive at $Hive"
                    }
                }
            }
        
            Write-Output $Apps
        }

        
        # Check for existing removal tool - deletes and redownloads to account for any future changes made to the removal tool
        if((test-path "c:\windows\temp\MCPR.zip") -eq $true){
            write-host "Found old zip file - Removing..."
            remove-item -LiteralPath "c:\windows\temp\MCPR.zip" -ErrorAction Ignore
        }
        else{
            write-host "No zip file found - Skipping..."
            
        }
        if((test-path "c:\windows\temp\MCPR") -eq $true){
            write-host "Found old EXE directory - Removing..."
            remove-item "c:\windows\temp\MCPR" -ErrorAction Ignore -Recurse -Force
        }
        else{
            write-host "No DIR Found - Skipping..."
            
        }
            
        <#
        The storage account has public web access / guest access enabled
        I'm working on switching to SAS Token secure download
        the storage account is in our GCS Tenant
        #>
        Write-Host 'Downloading MCPR Tool...'
        Invoke-webrequest 'https://***********/MCPR.zip' -outfile c:\windows\temp\MCPR.zip

        # Follow instructions at top of page to package file correctly
        write-host 'Extracting...'
        Expand-Archive -path c:\windows\temp\MCPR.zip -DestinationPath c:\windows\temp

        # Execute a script - do not use 'Start-Process' as this method fails
        Write-Host 'Executing...'
        $sb = start-job -scriptblock {
            set-location -path "C:\windows\temp\MCPR"
            .\remove-mcafee.bat
            }

        wait-job $sb.Name

        write-host 'Waiting for Uninstall to complete'
        start-sleep -seconds 60


        <# The MCPR Tool Doesn't get everything - the second pass will attempt to uninstall remaining apps with MSIEXEC #>
        $recheck = Get-InstalledApplications

        foreach ($app in $recheck){
            if ($app.displayname -like '*McAfee*'){
            write-host -ForegroundColor red "McAfee still detected"
            write-host $app.displayname
            write-host -ForegroundColor Green "Attempting MSIEXEC uninstall"
            $msicode = $app.pschildname
            $sb2 = start-job -InputObject $msicode -ScriptBlock {
                start-process "C:\windows\system32\msiexec.exe" -argumentlist "/uninstall $input /quiet /qn"
            }
            wait-job $sb2.name
            start-sleep -Seconds 60
            }
        elseif ($app.displayname -eq '5A894077.McAfeeSecurity'){
            Write-host "AppX McAfee Detected, will uninstall in next module"
        }
        else{
            #write-host "Not Detected"
            }
        }
        <# McAfee Personal Security is installed via Windows App Store as a Pre-Provisioned AppX Package and may be removed easily 

        This script will check for the app, remove the pre-packaged appx, and initiate uninstall of any user specific installs

        Will then wait for 15 seconds and check again to verify it has been removed
        #>

        #Enumerate all pre-provisioned packages
        $mcafee = Get-AppxProvisionedPackage -Online


        #Loop through each package and check if the display name matches
        foreach ($app2 in $mcafee){
            if ($app2.displayname -eq '5A894077.McAfeeSecurity'){
                write-host "McAfee Personal Security Detected pre-loaded, removing..." -ForegroundColor Yellow
                try{
                    #Use the Package Name variable because it contains the version number of the pre-loaded app and is unique
                    Remove-AppxProvisionedPackage -online -packagename $app2.PackageName
                    }
                catch{
                    write-error "unable to remove pre-provisioned package"
                    }
                #Give windows some time to catch up    
                start-sleep -seconds 15
                #If you try to remove the App before the pre-provisioned package, it fails with error 0x80070002
                #Running the command below will properly remove the app for all users after the pre-loaded app is nuked
                Get-AppxPackage -name 5A894077.McAfeeSecurity | Remove-AppxPackage -AllUsers
                }
            else{
                #write-host "no match - Skipping " -NoNewline -ForegroundColor Green
                #write-host $app2.displayname
                }
            }
        
        $checkavproduct = Get-WmiObject -Namespace "root\SecurityCenter2" -Class AntiVirusProduct
        foreach ($avobject in $checkavproduct){
            if ($avobject.displayname -contains "Mcafee VirusScan"){
                write-host "McAfee Detected - Removing"
                remove-wmiobject -path $avobject.path
            }
            elseif ($avobject.displayname -contains "Spybot - Search and Destroy"){
                write-host "Spybot Detected - Removing"
                remove-wmiobject -path $avobject.Path
            }
            else{
                write-host "Mcafee not detected in SecurityCenter2 - Skipping"
            }
        }
        
        
        
        <# Mcafee uninstall may not be properly detected by Defender for endpoint

        The code below checks for both regkey values that disable defender for endpoint if another AV/ASPY is detected

        If found, it removes the keys
        
        #>
        
        $disableav = get-itemproperty -path 'HKLM:\Software\Policies\Microsoft\Windows Defender' -name "DisableAntivirus" -ErrorAction SilentlyContinue
        $disablespy = get-itemproperty -path 'HKLM:\Software\Policies\Microsoft\Windows Defender' -name "DisableAntiSpyware" -ErrorAction SilentlyContinue

        if (!$disableav){
            Write-host "No Key Found - Skipping Removal of AV Regkey"
        }
        else{
            remove-itemproperty -path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' -name "DisableAntivirus"
        }
        if (!$disablespy){
            Write-host "No Key Found - Skipping Removal of Anti-Spyware Regkey"
        }
        else{
            remove-itemproperty -path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' -name "DisableAntispyware"
        }
            
        #Give windows some time to catch up
        start-sleep -Seconds 15
        $recheck2 = Get-AppxPackage -name 5A894077.McAfeeSecurity
            if ($recheck2.name -eq '5A894077.McAfeeSecurity'){
                write-host "McAfee Personal Security Removal Failed" -ForegroundColor Red
                $exitcode = -1
                }
            else{
                write-host "McAfee Personal Security Removal Complete" -ForegroundColor Green
                
                }
        start-sleep -seconds 15

        $finalcheck = Get-InstalledApplications

        foreach ($app3 in $finalcheck){
            if($app3.displayname -contains 'McAfee'){
                $name = $app3.displayname
                write-host -ForegroundColor red -BackgroundColor gray "$name Still Detected"
                $exitcode = -1
            }
        }
        if($exitcode = 0){
            write-host -ForegroundColor green "Successfully removed all traces of McAfee!!"
        }
        $exitcode = 0
        }
    catch{

        $exitCode = -1

    }

    Stop-Transcript | Out-Null
}

exit $exitCode

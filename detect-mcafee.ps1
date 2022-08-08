<# Add Get-InstalledApplications Function 
    This is a superior way to enumerate and action all installed items on a computer
#>

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

<# Call function to enumerate all apps installed on system #>

$allapps = Get-InstalledApplications

<# Intune will register a success with exit code 0 - any other number is a failure #>

$code = 0

<# Loop through all apps - check for McAfee in the name - add number to exit code if found - no mcafee products found will exit code 0 which is success #>

foreach ($app in $allapps){
    write-host $app.displayname
    if($app.displayname -like '*McAfee*'){
        write-host "McAfee Detected"
        $code = $code + 1
    }
    else{
        write-host "Not Found"
    }
}


<# McAfee Personal Security is installed via Windows App Store and may be removed easily 

   This script will check for the app and exit as a failure if detected which will trigger the remediation script
#>

$mcafeepersonalsec = get-appxpackage -allusers 5A894077.McAfeeSecurity

if ($mcafeepersonalsec.name -eq "5A894077.McAfeeSecurity"){
    Write-host "Found McAfee Personal Security"
    exit 1
}
else{
    Write-host "McAfee Personal Security Not Found - Exiting Successfully"
    
}

exit $code
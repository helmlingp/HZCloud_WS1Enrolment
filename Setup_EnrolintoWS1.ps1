<#
.Synopsis
    Creates scripts and sets registry keys to enable Persistent Desktop enrollment into Workspace ONE
 .NOTES
    Created:   	    November 2021
    Updated:        July 2022
    Created by:	    Phil Helmling, @philhelmling
    Organization:   VMware, Inc.
    Filename:       Setup_EnrolintoWS1.ps1
    GitHub:         https://github.com/helmlingp/HZCloud_WS1Enrolment
.DESCRIPTION
    Creates scripts and sets registry keys to enable Persistent Desktop enrollment into Workspace ONE.
    * Creates %WINDIR%\Setup\Scripts\SetupComplete.cmd that is executed on first user logon. This script calls EnrolintoWS1.ps1 
    passing Workspace ONE environment and staging user credentials as parameters.
    * Creates %WINDIR%\Setup\Scripts\EnrolintoWS1.ps1 which checks if device is image or provisioned desktop.
    * Sets registry key to ensure HCoA agent does not rename the SetupComplete.cmd.
    * Copies AirWatchAgent.msi to %WINDIR%\Setup\Scripts folder. goto https://getwsone.com to download or goto 
    https://<DS_FQDN>/agents/ProtectionAgent_AutoSeed/AirwatchAgent.msi to download it, substituting <DS_FQDN> with the FQDN for the Device Services Server.
.REQUIREMENTS
    * AirWatchAgent.msi in the current folder
    * WS1 enrollment credentials and server details
.EXAMPLE
  .\Setup_EnrolintoWS1.ps1 -username USERNAME -password PASSWORD -Server DESTINATION_SERVER_URL -OGName DESTINATION_OG_NAME
#>
param (
    [Parameter(Mandatory=$false)]
    [string]$username=$script:Username,
    [Parameter(Mandatory=$false)]
    [string]$password=$script:password,
    [Parameter(Mandatory=$false)]
    [string]$OGName=$script:OGName,
    [Parameter(Mandatory=$false)]
    [string]$Server=$script:Server
)

Function Test-Folder {
    param (
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$Path
  )
    
    if (!(Test-Path -LiteralPath $Path)) {
        try{
            New-Item -Path $Path -ItemType "Directory" -ErrorAction Ignore -Force #| Out-Null
        }
        catch {
            Write-Error -Message "Unable to create directory '$Path'. Error was: $_" -ErrorAction Stop
        }
        "Successfully created directory '$Path'."
    }
}

function Write-Log2{
    [CmdletBinding()]
    Param(
        [string]$Message,
        [Alias('LogPath')]
        [Alias('LogLocation')]
        [string]$Path=$Local:Path,
        [Parameter(Mandatory=$false)]
        [ValidateSet("Success","Error","Warn","Info")]
        [string]$Level="Info"
    )

    $ColorMap = @{"Success"="Green";"Error"="Red";"Warn"="Yellow"};
    $FontColor = "White";
    If($ColorMap.ContainsKey($Level)){$FontColor = $ColorMap[$Level];}
    $DateNow = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content -Path $Path -Value ("$DateNow     ($Level)     $Message")
    Write-Host "$DateNow::$Level`t$Message" -ForegroundColor $FontColor;
}

#Variables
$current_path = $PSScriptRoot;
$destfolder = "$env:WINDIR\Setup\Scripts";
$OEMPATH = "C:\Recovery\OEM";
$file = "AirwatchAgent.msi";
$name = "AllowSetupComplete";
$value = "1";
$key = "Registry::HKLM\Software\VMware, Inc.\VMware VDM\DaaS Agent";
$DateNow = Get-Date -Format "yyyyMMdd_hhmm";
$pathfile = "$destfolder\Setup_EnrolintoWS1_$DateNow";
$Script:logLocation = "$pathfile.log";

Test-Folder -Path $destfolder
Write-Log2 -Path "$logLocation" -Message "Setup_EnrolintoWS1 Started" -Level Success

#Ask for WS1 tenant and staging credentials if not already provided
if ([string]::IsNullOrEmpty($script:Server)){
    $script:Username = Read-Host -Prompt 'Enter the Staging Username'
    $script:password = Read-Host -Prompt 'Enter the Staging User Password'
    $script:Server = Read-Host -Prompt 'Enter the Workspace ONE UEM Server URL'
    $script:OGName = Read-Host -Prompt 'Enter the Organizational Group Name'
}
Write-Log2 -Path "$logLocation" -Message "Workspace ONE environment details obtained" -Level Info
#EnrolintoWS1.ps1 script that does enrolment
$EnrolintoWS1 = @'
<#
.Synopsis
    Enrols a persistent VDI desktop into WS1 from %WINDIR%\Setup\Scripts\SetupComplete.cmd
 .NOTES
    Created:   	    November 2021
    Updated:        July 2022 
    Created by:	    Phil Helmling, @philhelmling
    Organization:   VMware, Inc.
    Filename:       EnrolintoWS1.ps1
    GitHub:         
.DESCRIPTION
    **This script does not need to be edited**
    
    Called by %WINDIR%\Setup\Scripts\SetupComplete.cmd
    Enrols a persistent VDI desktop into WS1
    SetupComplete.cmd provides parameters for enrolment 
    Requires AirWatchAgent.msi in the C:\Recovery\OEM folder

    Detects if VM is image or pool desktop. Will only enrol pool desktops.

.EXAMPLE
  .\EnrolintoWS1.ps1 -username USERNAME -password PASSWORD -Server DESTINATION_SERVER_URL -OGName DESTINATION_OG_NAME
#>
param (
  [Parameter(Mandatory=$true)]
  [string]$username=$script:username,
  [Parameter(Mandatory=$true)]
  [string]$password=$script:password,
  [Parameter(Mandatory=$true)]
  [string]$OGName=$script:OGName,
  [Parameter(Mandatory=$true)]
  [string]$Server=$script:Server
)

function Write-Log2{
  [CmdletBinding()]
  Param
  (
      [string]$Message,
      [Alias('LogPath')]
      [Alias('LogLocation')]
      [string]$Path=$Local:Path,
      [Parameter(Mandatory=$false)]
      [ValidateSet("Success","Error","Warn","Info")]
      [string]$Level="Info"
  )

      $ColorMap = @{"Success"="Green";"Error"="Red";"Warn"="Yellow"};
      $FontColor = "White";
      If($ColorMap.ContainsKey($Level)){$FontColor = $ColorMap[$Level];}
      $DateNow = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
      Add-Content -Path $Path -Value ("$DateNow     ($Level)     $Message")
      Write-Host "$DateNow::$Level`t$Message" -ForegroundColor $FontColor;
}

#Variables
$destfolder = "$env:WINDIR\Setup\Scripts";
$name = "Pool Display Name";
$keypath = "Registry::HKLM\Software\VMware, Inc.\VMware VDM\Node Manager";
$DateNow = Get-Date -Format "yyyyMMdd_hhmm";
$pathfile = "$destfolder\EnrolintoWS1_$DateNow";
$Script:logLocation = "$pathfile.log";
$enrollmentcomplete = $false;
$image = $true;

Write-Log2 -Path "$logLocation" -Message "Starting EnrolintoWS1 Process" -Level Success
Write-Log2 -Path "$logLocation" -Message "Testing if HCoA Image" -Level Success

if(Get-ItemProperty -Path $keypath -Name $name -ErrorAction SilentlyContinue){
    $i = 1
    do {
        if((Get-ItemPropertyValue -Path $keypath -Name $name -ErrorAction SilentlyContinue).Length -eq 0) {
            Write-Log2 -Path "$logLocation" -Message "HCoA Agent not initialized, starting loop $i" -Level Info
            $i++
            start-sleep 60
        } else {
            $image = $false
            $i = 16
        }
    } until ($i -ge 16) if($image -eq $true){
        if($enrollmentcomplete -eq $false){Write-Log2 -Path "$logLocation" -Message "Device is Image, not enrolling" -Level Warn}
    } else {
        Write-Log2 -Path "$logLocation" -Message "HCoA Agent initialized" -Level Info
        while ($enrollmentcomplete -ne $true) {
            Write-Log2 -Path "$logLocation" -Message "Starting Workspace ONE enrollment" -Level Info
            Start-Process msiexec.exe -ArgumentList "/i","C:\Recovery\OEM\AirwatchAgent.msi","/qn","ENROLL=Y","DOWNLOADWSBUNDLE=false","SERVER=$Server","LGNAME=$OGName","USERNAME=$username","PASSWORD=$password";
            do {start-sleep 60} until ((Get-ItemProperty -path "Registry::HKLM\SOFTWARE\AIRWATCH\EnrollmentStatus" -ErrorAction SilentlyContinue).Status -eq 'Completed');
            start-sleep 60;
            Write-Log2 -Path "$logLocation" -Message "Workspace ONE enrollment complete" -Level Success
            $enrollmentcomplete = $true;
        }
    }
} else {
    if($enrollmentcomplete -eq $false){Write-Log2 -Path "$logLocation" -Message "Device is Image, not enrolling" -Level Warn}
}
'@
#SetupComplete that runs automatically by Windows after machine is SYSPREP'd and first user logon
$SetupComplete = @"
echo Off
rem Use this batch file to call a script to enrol a Windows Desktop into Workspace ONE UEM
rem Replace USERNAME, PASSWORD, DESTINATION_SERVER_URL, DESTINATION_OG_NAME parameters
rem November 2021

set LOCALAPPDATA=%USERPROFILE%\AppData\Local
powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -NoProfile -File "%~dp0EnrolintoWS1.ps1" -username $script:username -password $script:password -Server $script:Server -OGName $script:OGName
"@

#Create SetupComplete.cmd and EnrolintoWS1.ps1 Scripts
$FileName = "$destfolder\EnrolintoWS1.ps1"
If (Test-Path -Path $FileName){Remove-Item $FileName -force;Write-Log2 -Path "$logLocation" -Message "removed existing EnrolintoWS1.ps1" -Level Warn}
New-Item -Path $destfolder -ItemType "file" -Name "EnrolintoWS1.ps1" -Value $EnrolintoWS1 -Force -Confirm:$false
Write-Log2 -Path "$logLocation" -Message "create new EnrolintoWS1.ps1" -Level Info
$FileName = "$destfolder\SetupComplete.cmd"
If (Test-Path -Path $FileName){Remove-Item $FileName -force;Write-Log2 -Path "$logLocation" -Message "removed existing SetupComplete.cmd" -Level Warn}
New-Item -Path $destfolder -ItemType "file" -Name "SetupComplete.cmd" -Value $SetupComplete -Force -Confirm:$false
Write-Log2 -Path "$logLocation" -Message "create new SetupComplete.cmd" -Level Info

#Set Registry Key to prevent HCoA Agent renaming SetupComplete.cmd
if(Test-Path -Path $key){
    New-ItemProperty -Path $key -Name "AllowSetupComplete" -PropertyType "DWord" -Value 1 -Force -Confirm:$false
    Write-Log2 -Path "$logLocation" -Message "AllowSetupComplete registry value already exists, resetting" -Level Info
} else {
    New-Item -Path $key -Force -Confirm:$false
    New-ItemProperty -Path $key -Name "AllowSetupComplete" -PropertyType "DWord" -Value 1 -Force -Confirm:$false
    Write-Log2 -Path "$logLocation" -Message "create AllowSetupComplete DWORD=1 registry value" -Level Info
}

#Copy AirwatchAgent.msi to C:\Recovery\OEM
Test-Folder -Path $OEMPATH
$airwatchagent = Get-ChildItem -Path $current_path -Include *AirwatchAgent.msi* -Recurse -ErrorAction SilentlyContinue
if($airwatchagent){
    Copy-Item -Path $airwatchagent -Destination "$OEMPATH\$File" -Force
    Write-Log2 -Path "$logLocation" -Message "copy AirwatchAgent.msi to C:\Recovery\OEM" -Level Info
}
Write-Log2 -Path "$logLocation" -Message "Completed Setup_EnrolintoWS1" -Level Success
### PowerShell Profile Refactor
### Version 1.03 - Refactored

# Initial GitHub.com connectivity check with 1 second timeout
$canConnectToGitHub = Test-Connection 8.8.8.8 -Count 1 -Quiet -TimeoutSeconds 1

# Import Modules and External Profiles
# Ensure Terminal-Icons module is installed before importing
if (-not (Get-Module -ListAvailable -Name Terminal-Icons)) {
    Install-Module -Name Terminal-Icons -Scope CurrentUser -Force -SkipPublisherCheck
}
Import-Module -Name Terminal-Icons
$ChocolateyProfile = "$env:ChocolateyInstall\helpers\chocolateyProfile.psm1"
if (Test-Path($ChocolateyProfile)) {
    Import-Module "$ChocolateyProfile"
}

# Check for Profile Updates
function Update-Profile {
    if (-not $global:canConnectToGitHub) {
        Write-Host "Skipping profile update check due to GitHub.com not responding within 1 second." -ForegroundColor Yellow
        return
    }

    try {
        $url = "https://raw.githubusercontent.com/iamfitsum/powershell-profile/main/Microsoft.PowerShell_profile.ps1"
        
        # Get local file timestamp
        $localTimestamp = (Get-Item $PROFILE).LastWriteTime
        
        # Make a HEAD request to get file metadata
        $headRequest = Invoke-WebRequest -Uri $url -Method Head
        $remoteTimestamp = $headRequest.Headers.LastModified

        if ($remoteTimestamp -gt $localTimestamp) {
            # Download and update the profile
            Invoke-WebRequest -Uri $url -OutFile "$env:temp/Microsoft.PowerShell_profile.ps1"
            Copy-Item -Path "$env:temp/Microsoft.PowerShell_profile.ps1" -Destination $PROFILE -Force
            Write-Host "Profile has been updated. Please restart your shell to reflect changes" -ForegroundColor Magenta
        } else {
            Write-Host "Your profile is up to date." -ForegroundColor Green
        }
    } catch {
        Write-Error "Unable to check for `$profile updates. Error: $_"
    }
}

Update-Profile

function Update-PowerShell {
    # Check if the system can connect to GitHub before attempting to update PowerShell
    if (-not $canConnectToGitHub) {
        Write-Host "Skipping PowerShell update check due to lack of internet connectivity." -ForegroundColor Yellow
        return
    }
    $lastUpdateCheck = [datetime] (Get-ItemProperty -Path HKCU:\Software\PowerShell -Name LastUpdateCheck -ErrorAction SilentlyContinue).LastUpdateCheck
    $currentTime = [datetime] (Get-Date)
    $updateInterval = New-TimeSpan -Days 1

    # Check if the last update check was more than a day ago or if it's the first check
    if (-not $lastUpdateCheck -or ($currentTime - $lastUpdateCheck) -ge $updateInterval) {
        try {
            Write-Host "Checking for PowerShell updates..." -ForegroundColor Cyan
            $currentVersion = $PSVersionTable.PSVersion.ToString()
            $gitHubApiUrl = "https://api.github.com/repos/PowerShell/PowerShell/releases/latest"
            $latestVersion = (Invoke-RestMethod -Uri $gitHubApiUrl).tag_name.Trim('v')

            if ($currentVersion -lt $latestVersion) {
                Write-Host "Updating PowerShell..." -ForegroundColor Yellow
                winget upgrade "Microsoft.PowerShell" --accept-source-agreements --accept-package-agreements
                Write-Host "PowerShell has been updated. Please restart your shell to reflect changes" -ForegroundColor Magenta
            } else {
                Write-Host "Your PowerShell is up to date." -ForegroundColor Green
            }

            # Store the current timestamp as the last update check time
            $null = New-Item -Path HKCU:\Software\PowerShell -Force
            Set-ItemProperty -Path HKCU:\Software\PowerShell -Name LastUpdateCheck -Value $currentTime
        } catch {
            Write-Error "Failed to update PowerShell. Error: $_"
        }
    } else {
        Write-Host "Skipping PowerShell update check. Last check was within the last 24 hours." -ForegroundColor Yellow
    }
}

Update-PowerShell

# Admin Check and Prompt Customization
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
function prompt {
    if ($isAdmin) { "[" + (Get-Location) + "] # " } else { "[" + (Get-Location) + "] $ " }
}
$adminSuffix = if ($isAdmin) { " [ADMIN]" } else { "" }
$Host.UI.RawUI.WindowTitle = "PowerShell {0}$adminSuffix" -f $PSVersionTable.PSVersion.ToString()

# Utility Functions
function Test-CommandExists {
    param($command)
    return (Get-Command $command -ErrorAction SilentlyContinue) -is [System.Management.Automation.CommandInfo]
}


# Editor Configuration
$editorMapping = @{
    'nvim' = 'nvim'
    'pvim' = 'pvim'
    'vim' = 'vim'
    'vi' = 'vi'
    'code' = 'code'
    'notepad++' = 'notepad++'
    'sublime_text' = 'sublime_text'
}

$defaultEditor = 'notepad'
$EDITOR = $defaultEditor

foreach ($editor in $editorMapping.Keys) {
    if (Test-CommandExists $editor) {
        $EDITOR = $editorMapping[$editor]
        break
    }
}

Set-Alias -Name vim -Value $EDITOR


function Edit-Profile {
    vim $PROFILE.CurrentUserAllHosts
}
function touch($file) { "" | Out-File $file -Encoding ASCII }
function ff($name) {
    Get-ChildItem -recurse -filter "*${name}*" -ErrorAction SilentlyContinue | ForEach-Object {
        Write-Output "$($_.directory)\$($_)"
    }
}

# Network Utilities
function Get-PubIP { (Invoke-WebRequest http://ifconfig.me/ip).Content }

# System Utilities
function dirs {
    if($args.Count -gt 0)
    {
        Get-ChildItem -Recurse -Include "$args" | Foreach-Object FullName
    }
    else
    {
        Get-ChildItem -Recurse | Foreach-Object FullName
    }
}

function admin {
    if ($args.Count -gt 0) {
        $argList = "& '$args'"
        Start-Process wt -Verb runAs -ArgumentList "pwsh.exe -NoExit -Command $argList"
    } else {
        Start-Process wt -Verb runAs
    }
}

# Set UNIX-like aliases for the admin command, so sudo <command> will run the command with elevated rights.
Set-Alias -Name su -Value admin
Set-Alias -Name sudo -Value admin

function uptime {
    if ($PSVersionTable.PSVersion.Major -eq 5) {
        Get-WmiObject win32_operatingsystem | Select-Object @{Name='LastBootUpTime'; Expression={$_.ConverttoDateTime($_.lastbootuptime)}} | Format-Table -HideTableHeaders
    } else {
        net statistics workstation | Select-String "since" | ForEach-Object { $_.ToString().Replace('Statistics since ', '') }
    }
}

function reload-profile {
    & $profile
}

function unzip ($file) {
    Write-Output("Extracting", $file, "to", $pwd)
    $fullFile = Get-ChildItem -Path $pwd -Filter $file | ForEach-Object { $_.FullName }
    Expand-Archive -Path $fullFile -DestinationPath $pwd
}
function hb {
    if ($args.Length -eq 0) {
        Write-Error "No file path specified."
        return
    }
    
    $FilePath = $args[0]
    
    if (Test-Path $FilePath) {
        $Content = Get-Content $FilePath -Raw
    } else {
        Write-Error "File path does not exist."
        return
    }
    
    $uri = "http://bin.christitus.com/documents"
    try {
        $response = Invoke-RestMethod -Uri $uri -Method Post -Body $Content -ErrorAction Stop
        $hasteKey = $response.key
        $url = "http://bin.christitus.com/$hasteKey"
        Write-Output $url
    } catch {
        Write-Error "Failed to upload the document. Error: $_"
    }
}
function grep($regex, $dir) {
    if ( $dir ) {
        Get-ChildItem $dir | select-string $regex
        return
    }
    $input | select-string $regex
}

function df {
    get-volume
}

function sed($file, $find, $replace) {
    (Get-Content $file).replace("$find", $replace) | Set-Content $file
}

function which($name) {
    Get-Command $name | Select-Object -ExpandProperty Definition
}

function export($name, $value) {
    set-item -force -path "env:$name" -value $value;
}

function pkill($name) {
    Get-Process $name -ErrorAction SilentlyContinue | Stop-Process
}

function pgrep($name) {
    Get-Process $name
}

function head {
  param($Path, $n = 10)
  Get-Content $Path -Head $n
}

function tail {
  param($Path, $n = 10)
  Get-Content $Path -Tail $n
}

# Quick File Creation
function nf { param($name) New-Item -ItemType "file" -Path . -Name $name }

# Directory Management
function mkcd { param($dir) mkdir $dir -Force; Set-Location $dir }

### Quality of Life Aliases

# Navigation Shortcuts
function docs { Set-Location -Path $HOME\Documents }

function dtop { Set-Location -Path $HOME\Desktop }

# Quick Access to Editing the Profile
function ep { vim $PROFILE }

# Simplified Process Management
function k9 { Stop-Process -Name $args[0] }

# Enhanced Listing
function la { Get-ChildItem -Path . -Force | Format-Table -AutoSize }
function ll { Get-ChildItem -Path . -Force -Hidden | Format-Table -AutoSize }

# Git Shortcuts
function gs { git status }

function ga { git add . }

function gc { param($m) git commit -m "$m" }

function gp { git push }

function g { z Github }

function gcom {
    git add .
    git commit -m "$args"
}
function lazyg {
    git add .
    git commit -m "$args"
    git push
}

# Quick Access to System Information
function sysinfo { Get-ComputerInfo }

# Networking Utilities
function flushdns { Clear-DnsClientCache }

# Clipboard Utilities
function cpy { Set-Clipboard $args[0] }

function pst { Get-Clipboard }

# Enhanced PowerShell Experience
Set-PSReadLineOption -Colors @{
    Command = 'Yellow'
    Parameter = 'Green'
    String = 'DarkCyan'
}

## Final Line to set prompt
oh-my-posh init pwsh --config 'C:\Users\Fitsum\AppData\Local\Programs\oh-my-posh\themes\jblab_2021.omp.json' | Invoke-Expression

if (Get-Command zoxide -ErrorAction SilentlyContinue) {
    Invoke-Expression (& { (zoxide init powershell | Out-String) })
} else {
    Write-Host "zoxide command not found. Attempting to install via winget..."
    try {
        winget install -e --id ajeetdsouza.zoxide
        Write-Host "zoxide installed successfully. Initializing..."
        Invoke-Expression (& { (zoxide init powershell | Out-String) })
    } catch {
        Write-Error "Failed to install zoxide. Error: $_"
    }
}
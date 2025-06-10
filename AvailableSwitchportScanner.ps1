param(
    [Parameter(Mandatory = $false)]
    [string]$SwitchIP,
    [Parameter(Mandatory = $false)]
    [string]$Username,
    [Parameter(Mandatory = $false)]
    [System.Security.SecureString]$Password,
    [Parameter(Mandatory = $false)]
    [int]$InactivityThresholdDays = 7
)

# Ensure Posh-SSH is installed
if (-not (Get-Module -ListAvailable -Name Posh-SSH)) {
    Write-Host "Installing Posh-SSH..." -ForegroundColor Yellow
    if (-not (Get-PackageProvider -Name NuGet -ListAvailable -ErrorAction SilentlyContinue)) {
        Install-PackageProvider -Name NuGet -Force -Scope CurrentUser | Out-Null
    }
    Install-Module -Name Posh-SSH -Force -Scope CurrentUser -ErrorAction Stop
}
Import-Module Posh-SSH

# Prompt for inputs if not provided
if (-not $SwitchIP) {
    $SwitchIP = Read-Host -Prompt "Enter the switch IP"
}
if (-not $Username) {
    $Username = Read-Host -Prompt "Enter the SSH username"
}
if (-not $Password) {
    $Password = Read-Host -Prompt "Enter the SSH password" -AsSecureString
}
if ($Password -is [string]) {
    $Password = ConvertTo-SecureString $Password -AsPlainText -Force
}
$Cred = New-Object System.Management.Automation.PSCredential($Username, $Password)

# Connect via SSH
try {
    Write-Host "Connecting to $SwitchIP..." -ForegroundColor Yellow
    $session = New-SSHSession -ComputerName $SwitchIP -Credential $Cred -AcceptKey -ConnectionTimeout 15 -ErrorAction Stop
}
catch {
    Write-Host "Connection failed: $_" -ForegroundColor Red
    $_ | Out-File "debug_ssh.txt" -Append
    exit
}
Write-Host "Connected to $SwitchIP" -ForegroundColor Green

# Open shell stream
$shell = New-SSHShellStream -SessionId $session.SessionId
Start-Sleep -Milliseconds 1000
$shell.Read() | Out-Null

function Invoke-CiscoShellCommand {
    param (
        [string]$Command,
        [int]$WaitTimeSeconds = 2
    )
    try {
        $shell.WriteLine($Command)
        Start-Sleep -Seconds $WaitTimeSeconds
        $output = $shell.Read()
        if ($output -match "^%") {
            Write-Host "Command '$Command' failed: $output" -ForegroundColor Red
            $output | Out-File "debug_ssh.txt" -Append
            return $null
        }
        return $output
    }
    catch {
        Write-Host "Error executing '$Command': $_" -ForegroundColor Red
        $_ | Out-File "debug_ssh.txt" -Append
        return $null
    }
}

# Disable pagination and set terminal width
Invoke-CiscoShellCommand "terminal length 0" | Out-Null
Invoke-CiscoShellCommand "terminal width 0" | Out-Null

# Check switch uptime
$uptime = Invoke-CiscoShellCommand "show version | include uptime"
Write-Host "`n[Uptime]:`n$uptime"
if ($uptime -match "uptime is (\d+) (week|day|hour|minute)") {
    $value = [int]$matches[1]
    $unit = $matches[2]
    $days = switch ($unit) {
        "week" { $value * 7 }
        "day" { $value }
        "hour" { $value / 24 }
        "minute" { $value / 1440 }
    }
    if ($days -lt 180) {
        Write-Host "WARNING: Switch uptime is less than 6 months ($($days.ToString('F2')) days). TDR results may be inaccurate." -ForegroundColor Yellow
    }
}

# Collect switch data
$status = Invoke-CiscoShellCommand "show interfaces status"
$desc = Invoke-CiscoShellCommand "show interfaces description"
$poe = Invoke-CiscoShellCommand "show power inline"
$interfaces = Invoke-CiscoShellCommand "show interfaces | include (GigabitEthernet|TenGigabitEthernet|Last input)" -WaitTimeSeconds 15

# Save raw outputs for debugging
$debugMode = $true
if ($debugMode) {
    $status | Out-File "debug_status.txt"
    $desc | Out-File "debug_desc.txt"
    $poe | Out-File "debug_poe.txt"
    $interfaces | Out-File "debug_interfaces.txt"
}

Write-Host "`n[show interfaces status]:`n$status"
Write-Host "`n[show interfaces description]:`n$desc"
Write-Host "`n[show power inline]:`n$poe"
Write-Host "`n[show interfaces]:`n(Truncated for brevity; full output in debug_interfaces.txt)"

# Function to normalize interface names
function Normalize-InterfaceName {
    param (
        [string]$InterfaceName
    )
    if ($InterfaceName -match "^(GigabitEthernet|TenGigabitEthernet|FortyGigabitEthernet|TwentyFiveGigE|AppGigabitEthernet|Gi|Te|Fo|Twe)(.+)$") {
        $prefix = $matches[1]
        $suffix = $matches[2]
        switch ($prefix) {
            "GigabitEthernet" { return "Gi$suffix" }
            "TenGigabitEthernet" { return "Te$suffix" }
            "FortyGigabitEthernet" { return "Fo$suffix" }
            "TwentyFiveGigE" { return "Twe$suffix" }
            "AppGigabitEthernet" { return "AppGi$suffix" }
            "Gi" { return "Gi$suffix" }
            "Te" { return "Te$suffix" }
            "Fo" { return "Fo$suffix" }
            "Twe" { return "Twe$suffix" }
        }
    }
    return $InterfaceName
}

# Function to parse Last input/output time
function Get-InactivityDays {
    param (
        [string]$TimeString
    )
    if ($TimeString -eq "never") {
        Write-Host "Detected 'Last input never' or 'Last output never' for interface" -ForegroundColor Cyan
        return [double]::MaxValue
    }
    if ($TimeString -match "^(\d+):(\d+):(\d+)$") {
        $hours = [int]$matches[1]
        $minutes = [int]$matches[2]
        $seconds = [int]$matches[3]
        return ($hours * 3600 + $minutes * 60 + $seconds) / 86400
    }
    if ($TimeString -match "^(\d+)w(\d+)d") {
        $weeks = [int]$matches[1]
        $days = [int]$matches[2]
        return $weeks * 7 + $days
    }
    if ($TimeString -match "^(\d+)d") {
        return [int]$matches[1]
    }
    if ($TimeString -match "^(\d+)h") {
        return [int]$matches[1] / 24
    }
    if ($TimeString -match "^(\d+)m") {
        return [int]$matches[1] / 1440
    }
    Write-Host "WARNING: Unrecognized time format: $TimeString" -ForegroundColor Yellow
    return 0
}

# Parse show interfaces output
$interfaceData = @{}
$currentInterface = $null
$unmatchedLines = @()
$attemptedLines = @()
$parsedInterfaces = @()
foreach ($line in ($interfaces -split "`n")) {
    $attemptedLines += $line
    if ($line -match "^([^\s\/]+(?:\s*[^\s\/]+)?\d+\/\d+\/\d+)\s+is") {
        $currentInterface = Normalize-InterfaceName -InterfaceName $matches[1]
        $interfaceData[$currentInterface] = @{ LastInput = $null; LastOutput = $null }
        Write-Host "Parsed interface: $currentInterface" -ForegroundColor Cyan
    }
    elseif ($currentInterface -and $line -match "Last input\s+([^,]+),\s+output\s+([^,]+),\s+output hang") {
        $interfaceData[$currentInterface].LastInput = $matches[1].Trim()
        $interfaceData[$currentInterface].LastOutput = $matches[2].Trim()
        $parsedInterfaces += "Interface: $currentInterface, LastInput: $($interfaceData[$currentInterface].LastInput), LastOutput: $($interfaceData[$currentInterface].LastOutput)"
    }
    elseif ($line -match "^\S+\s+is" -and $line -notmatch "^(Vlan|Port-channel|Loopback)") {
        $unmatchedLines += $line
    }
}

# Log debug files
if ($debugMode) {
    $attemptedLines | Out-File "debug_attempted_interfaces.txt"
    $parsedInterfaces | Out-File "debug_interfaces_parsed.txt"
    if ($unmatchedLines) {
        $unmatchedLines | Out-File "debug_unmatched_interfaces.txt"
        Write-Host "WARNING: $($unmatchedLines.Count) interface lines not parsed. See debug_unmatched_interfaces.txt" -ForegroundColor Yellow
    }
}

# Validate parsing
$statusPorts = ($status -split "`n" | Where-Object { $_ -match "^((?:Gi|Te|Fo|Twe)(?:\d+\/){0,2}\d+)\s+" }) | ForEach-Object { $matches[1] }
$missingPorts = $statusPorts | Where-Object { -not $interfaceData.ContainsKey($_) }
if ($missingPorts) {
    Write-Host "WARNING: $($missingPorts.Count) ports from 'show interfaces status' not found in 'show interfaces'. First 5: $($missingPorts | Select-Object -First 5 | Join-String -Separator ', '). Check debug_interfaces.txt." -ForegroundColor Yellow
}
if ($interfaceData.Count -eq 0) {
    Write-Host "ERROR: No interfaces parsed from 'show interfaces'. Check debug_interfaces.txt and debug_ssh.txt." -ForegroundColor Red
    Remove-SSHSession -SessionId $session.SessionId
    exit
}

# Identify candidate ports
$candidatePorts = @()
$portsWithPatchCables = @()
$portsPassthroughOrShorter = @()

foreach ($line in $status -split "`n") {
    if ($line -match "^((?:Gi|Te|Fo|Twe)(?:\d+\/){0,2}\d+)\s+.*?\s+notconnect\b") {
        $port = $matches[1]

        # Check 1: Description contains 'Standard'
        $descMatch = ($desc -split "`n" | Where-Object { $_ -match "^$port\s+.*[Ss]tandard.*" })
        if (-not $descMatch) {
            Write-Host "✗ $port description does not contain 'Standard' - skipping" -ForegroundColor Yellow
            continue
        }

        # Check 2: PoE is 0.0W
        $poeMatch = ($poe -split "`n" | Where-Object { $_ -match "^$port\s+.*\s0\.0\s" })
        if (-not $poeMatch) {
            Write-Host "✗ $port has non-zero PoE - skipping" -ForegroundColor Yellow
            continue
        }

        # Check 3: Last input/output inactivity > $InactivityThresholdDays
        if ($interfaceData.ContainsKey($port)) {
            $lastInput = $interfaceData[$port].LastInput
            $lastOutput = $interfaceData[$port].LastOutput
            if ($null -eq $lastInput -or $null -eq $lastOutput) {
                Write-Host "✗ $port no Last input/output data found (Last input: $lastInput, Last output: $lastOutput) - skipping" -ForegroundColor Yellow
                continue
            }
            $inputDays = Get-InactivityDays -TimeString $lastInput
            $outputDays = Get-InactivityDays -TimeString $lastOutput
            if ($inputDays -lt $InactivityThresholdDays -or $outputDays -lt $InactivityThresholdDays) {
                Write-Host "✗ $port activity detected (Last input: $lastInput, Last output: $lastOutput) - skipping" -ForegroundColor Yellow
                continue
            }
            Write-Host "✓ $port inactivity check passed (Last input: $lastInput, Last output: $lastOutput)" -ForegroundColor Green
        }
        else {
            Write-Host "✗ $port not found in interface data. Expected interface: $port. Check debug_interfaces.txt for matching entries." -ForegroundColor Yellow
            continue
        }

        Write-Host "✓ $port is a candidate (notconnect + 'Standard' + 0.0W + inactive for > $InactivityThresholdDays days) - running TDR test..." -ForegroundColor Green
        $candidatePorts += $port

        # Run TDR test
        $tdrCommand = "test cable-diagnostics tdr interface $port"
        Invoke-CiscoShellCommand $tdrCommand | Out-Null
        Start-Sleep -Seconds 10
        $tdrResult = Invoke-CiscoShellCommand "show cable-diagnostics tdr interface $port"

        # Save TDR result
        if ($debugMode) {
            $safePort = $port -replace '[/\\]', '_'
            $tdrResult | Out-File "debug_tdr_$safePort.txt"
        }

        # Parse TDR results
        $isOpen = $true
        $pairLengths = @()
        foreach ($tdrLine in ($tdrResult -split "`n")) {
            if ($tdrLine -match "Pair\s+[A-D].*Open\s+(\d+)\s+m") {
                $pairLengths += [int]$matches[1]
            }
            elseif ($tdrLine -match "Pair\s+[A-D].*(Short|Terminated|Impedance)") {
                $isOpen = $false
                break
            }
        }

        # Check for patch cable (all pairs open, length > 2m)
        $passthroughLength = 2
        if ($isOpen -and $pairLengths.Count -eq 4 -and ($pairLengths | ForEach-Object { $_ -gt $passthroughLength } | Select-Object -Unique).Count -eq 1) {
            Write-Host "✓ $port has patch cable (all pairs open, length > $passthroughLength m: $($pairLengths -join ', '))" -ForegroundColor Green
            $portsWithPatchCables += $port
        }
        else {
            Write-Host "✓ $port is passthrough or shorter (length <= $passthroughLength m or not all pairs open: $($pairLengths -join ', '))" -ForegroundColor Cyan
            $portsPassthroughOrShorter += $port
        }
    }
}

# Generate Summary
Write-Host "`n==============================================" -ForegroundColor Cyan
Write-Host "Switch: $SwitchIP" -ForegroundColor Cyan
Write-Host "Candidate Ports for Cleanup (Patch Cables Detected):" -ForegroundColor Cyan
$portsWithPatchCables | ForEach-Object { Write-Host $_ }
Write-Host "Total Ports with Patch Cables: $($portsWithPatchCables.Count)" -ForegroundColor Cyan
Write-Host "`nPorts Passthrough or Shorter (No Patch Cable or Short Cable):" -ForegroundColor Cyan
$portsPassthroughOrShorter | ForEach-Object { Write-Host $_ }
Write-Host "Total Ports Passthrough or Shorter: $($portsPassthroughOrShorter.Count)" -ForegroundColor Cyan
Write-Host "Completed: $(Get-Date -Format 'MM/dd/yyyy HH:mm:ss')" -ForegroundColor Cyan
Write-Host "==============================================" -ForegroundColor Cyan

# Log results to file
$logFile = "SwitchCleanup_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
$logContent = @"
Switch: $SwitchIP
Uptime: $uptime
Inactivity Threshold: $InactivityThresholdDays days
Candidate Ports for Cleanup (Patch Cables Detected):
$($portsWithPatchCables -join "`n")
Total Ports with Patch Cables: $($portsWithPatchCables.Count)

Ports Passthrough or Shorter (No Patch Cable or Short Cable):
$($portsPassthroughOrShorter -join "`n")
Total Ports Passthrough or Shorter: $($portsPassthroughOrShorter.Count)

Completed: $(Get-Date -Format 'MM/dd/yyyy HH:mm:ss')
"@
$logContent | Out-File $logFile -Append
Write-Host "Results logged to $logFile" -ForegroundColor Green

# Cleanup
Remove-SSHSession -SessionId $session.SessionId
Write-Host "SSH Session Closed." -ForegroundColor Green
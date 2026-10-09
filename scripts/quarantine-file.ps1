
$QuarantineDir = 'C:\Wazuh-Quarantine'
$LogFile = Join-Path $QuarantineDir 'quarantine.log'

if (-not (Test-Path -LiteralPath $QuarantineDir)) {
    New-Item -ItemType Directory -Path $QuarantineDir -Force | Out-Null
}

function Write-Log([string]$Level, [string]$Message) {
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    Add-Content -LiteralPath $LogFile -Value "$ts - ${Level}: $Message"
}

try {
    $raw = [Console]::In.ReadToEnd()
    Write-Log 'INFO' 'Active Response command received'

    $alert = $raw | ConvertFrom-Json
    $file = $alert.parameters.alert.data.virustotal.source.file

    if ([string]::IsNullOrWhiteSpace([string]$file)) {
        Write-Log 'ERROR' 'No file path in alert'
        exit 1
    }

    Write-Log 'INFO' "Detected file: $file"

    if (-not (Test-Path -LiteralPath $file -PathType Leaf)) {
        Write-Log 'WARNING' "File not found: $file"
        exit 0
    }

    $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $leaf = Split-Path -Path $file -Leaf
    $dest = Join-Path $QuarantineDir "${stamp}_$leaf"

    if (Test-Path -LiteralPath $dest) {
        $dest = Join-Path $QuarantineDir "${stamp}_$([guid]::NewGuid().ToString('N'))_$leaf"
    }

    Move-Item -LiteralPath $file -Destination $dest -ErrorAction Stop
    Write-Log 'SUCCESS' "Quarantined $file -> $dest"
}
catch {
    Write-Log 'ERROR' $_.Exception.Message
    exit 1
}
param(
    [string]$ApiUrl = "http://localhost:8000",
    [string]$Username = "admin",
    [string]$Password = "Admin123!",
    [ValidateSet("asset_discovery", "vulnerability_scan", "web_scan")]
    [string]$ScanType = "vulnerability_scan",
    [int]$TimeoutSeconds = 60
)

$ErrorActionPreference = "Stop"

function Invoke-Api {
    param(
        [Parameter(Mandatory)] [string]$Method,
        [Parameter(Mandatory)] [string]$Path,
        [object]$Body = $null
    )

    $parameters = @{
        Method = $Method
        Uri = "$ApiUrl$Path"
        Headers = $script:Headers
    }
    if ($null -ne $Body) {
        $parameters.ContentType = "application/json"
        $parameters.Body = $Body | ConvertTo-Json -Depth 8
    }
    Invoke-RestMethod @parameters
}

Write-Host "Checking API..." -ForegroundColor Cyan
$health = Invoke-RestMethod -Method Get -Uri "$ApiUrl/health"
Write-Host "API status: $($health.status)" -ForegroundColor Green

$login = Invoke-RestMethod `
    -Method Post `
    -Uri "$ApiUrl/auth/login" `
    -ContentType "application/json" `
    -Body (@{ username = $Username; password = $Password } | ConvertTo-Json)

$script:Headers = @{ Authorization = "Bearer $($login.access_token)" }

# This target is a label for the simulation. Mock mode never contacts it.
$targetName = "DEMO Mock Loopback"
$targets = Invoke-Api -Method Get -Path "/targets"
$target = @($targets) | Where-Object { $_.name -eq $targetName } | Select-Object -First 1

if ($null -eq $target) {
    Write-Host "Creating loopback-labelled demo target..." -ForegroundColor Cyan
    $target = Invoke-Api -Method Post -Path "/targets" -Body @{
        name = $targetName
        host = "127.0.0.1"
        target_type = "IP"
        description = "Safe simulated assessment target; mock mode makes no network connection"
    }
}

Write-Host "Authorizing target $($target.id) for this local demonstration..." -ForegroundColor Cyan
$target = Invoke-Api -Method Post -Path "/targets/$($target.id)/authorize" -Body @{
    authorization_reference = "DEMO-SIMULATION-$(Get-Date -Format yyyyMMdd)"
    authorization_start = (Get-Date).ToUniversalTime().AddMinutes(-5).ToString("o")
    authorization_end = (Get-Date).ToUniversalTime().AddHours(2).ToString("o")
}

$assetsBeforeResponse = Invoke-Api -Method Get -Path "/assets"
$assetsBefore = @(@($assetsBeforeResponse) | Where-Object { [int]$_.target_id -eq [int]$target.id }).Count

Write-Host "Starting MOCK $ScanType assessment (no real probing or exploitation)..." -ForegroundColor Cyan
$scan = Invoke-Api -Method Post -Path "/scans" -Body @{
    target_id = [int]$target.id
    scan_type = $ScanType
    tool = "mock"
    mode = "mock"
}

$deadline = (Get-Date).AddSeconds($TimeoutSeconds)
do {
    Start-Sleep -Seconds 1
    $scan = Invoke-Api -Method Get -Path "/scans/$($scan.id)"
    Write-Host "Scan #$($scan.id): $($scan.status)"
    if ($scan.status -in @("completed", "failed", "cancelled")) { break }
} while ((Get-Date) -lt $deadline)

if ($scan.status -ne "completed") {
    throw "Demo scan did not complete successfully. Final status: $($scan.status)"
}

$scanId = [int]$scan.id
$targetId = [int]$target.id
$allAssets = Invoke-Api -Method Get -Path "/assets"
$assets = @(@($allAssets) | Where-Object { [int]$_.target_id -eq $targetId })
$assetsGenerated = $assets.Count - $assetsBefore
$report = Invoke-Api -Method Get -Path "/reports/$scanId`?format=json"
$findings = @($report.findings)

$outputDir = Join-Path $PSScriptRoot "..\output\demo"
New-Item -ItemType Directory -Force -Path $outputDir | Out-Null
$jsonPath = Join-Path $outputDir "demo-scan-$($scan.id).json"
$pdfPath = Join-Path $outputDir "demo-scan-$($scan.id).pdf"

Invoke-WebRequest `
    -Uri "$ApiUrl/reports/$($scan.id)?format=json" `
    -Headers $script:Headers `
    -OutFile $jsonPath
Invoke-WebRequest `
    -Uri "$ApiUrl/reports/$($scan.id)?format=pdf" `
    -Headers $script:Headers `
    -OutFile $pdfPath

Write-Host ""
Write-Host "SAFE DEMO COMPLETED" -ForegroundColor Green
Write-Host "Target: $($target.name) ($($target.host))"
Write-Host "Authorization: $($target.authorization_status)"
Write-Host "Scan ID: $($scan.id)"
Write-Host "Mode: MOCK - no target was contacted"
Write-Host "Assets generated: $assetsGenerated"
Write-Host "Synthetic findings generated: $($findings.Count)"
Write-Host "Risk assessments generated: $($findings.Count)"

if ($findings.Count -gt 0) {
    Write-Host ""
    Write-Host "Prioritized results:" -ForegroundColor Cyan
    $findings |
        Sort-Object final_risk -Descending |
        Select-Object cve, priority, rule_score, ml_score, final_risk, confidence |
        Format-Table -AutoSize
}

Write-Host "JSON report: $([System.IO.Path]::GetFullPath($jsonPath))"
Write-Host "PDF report:  $([System.IO.Path]::GetFullPath($pdfPath))"

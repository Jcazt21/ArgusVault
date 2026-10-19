<#
.SYNOPSIS
    Authenticode signing script for Argus Vault Windows executables.

.DESCRIPTION
    Signs target\release\argus-app.exe (or specified executable) using Microsoft signtool.exe
    with SHA-256 digest algorithm, RFC 3161 timestamping, and dual-layer verification.

.PARAMETER BinaryPath
    Path to the binary to sign. Default: target\release\argus-app.exe

.PARAMETER CertPath
    Path to the .pfx certificate file (if signing with file).

.PARAMETER Password
    Password for the .pfx certificate (optional, prompted securely if omitted).

.PARAMETER Thumbprint
    Certificate SHA-1 thumbprint if using Windows Certificate Store (CurrentUser\My).

.PARAMETER TimestampServer
    RFC 3161 timestamp server URL. Default: http://timestamp.digicert.com

.EXAMPLE
    .\scripts\sign.ps1 -CertPath "cert.pfx" -Password "Secret123"
    .\scripts\sign.ps1 -Thumbprint "abcdef1234567890abcdef1234567890abcdef12"
#>

[CmdletBinding()]
param(
    [string]$BinaryPath = "target\release\argus-app.exe",
    [string]$CertPath = "",
    [string]$Password = "",
    [string]$Thumbprint = "",
    [string]$TimestampServer = "http://timestamp.digicert.com"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Write-Host "=== Argus Vault Authenticode Signing ===" -ForegroundColor Cyan

# 1. Resolve executable path
$resolvedBinary = Resolve-Path -Path $BinaryPath -ErrorAction SilentlyContinue
if (-not $resolvedBinary -or -not (Test-Path $resolvedBinary)) {
    Write-Error "Target binary not found at: $BinaryPath. Compile in release mode first: cargo build --release --locked"
    exit 1
}

Write-Host "[+] Target executable: $resolvedBinary" -ForegroundColor Green

# 2. Locate signtool.exe
$signtool = (Get-Command "signtool.exe" -ErrorAction SilentlyContinue)?.Source
if (-not $signtool) {
    # Check standard Windows SDK locations
    $sdkPaths = @(
        "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\signtool.exe",
        "${env:ProgramFiles}\Windows Kits\10\bin\*\x64\signtool.exe"
    )
    $found = Get-Item $sdkPaths -ErrorAction SilentlyContinue | Sort-Object FullName -Descending | Select-Object -First 1
    if ($found) {
        $signtool = $found.FullName
    }
}

if (-not $signtool) {
    Write-Error "signtool.exe not found in PATH or Windows Kits directory. Please install Windows SDK."
    exit 1
}

Write-Host "[+] Using signtool: $signtool" -ForegroundColor Green

# 3. Build sign arguments
$signArgs = @("sign", "/fd", "SHA256", "/tr", $TimestampServer, "/td", "SHA256", "/v")

if ($Thumbprint) {
    Write-Host "[+] Using Certificate Store thumbprint: $Thumbprint" -ForegroundColor Green
    $signArgs += @("/sha1", $Thumbprint, "/s", "MY")
} elseif ($CertPath) {
    $resolvedCert = Resolve-Path -Path $CertPath -ErrorAction SilentlyContinue
    if (-not $resolvedCert) {
        Write-Error "Certificate file not found: $CertPath"
        exit 1
    }
    Write-Host "[+] Using Certificate file: $resolvedCert" -ForegroundColor Green
    $signArgs += @("/f", $resolvedCert)
    if ($Password) {
        $signArgs += @("/p", $Password)
    }
} else {
    Write-Host "[!] Neither -CertPath nor -Thumbprint provided." -ForegroundColor Yellow
    Write-Host "    Attempting auto-selection from Windows Certificate Store..." -ForegroundColor Yellow
    $signArgs += @("/a")
}

$signArgs += $resolvedBinary.Path

# 4. Sign binary
Write-Host "[*] Executing signing command..." -ForegroundColor Cyan
& $signtool $signArgs
if ($LASTEXITCODE -ne 0) {
    Write-Error "Failed to sign binary (exit code $LASTEXITCODE)."
    exit $LASTEXITCODE
}

# 5. Verify signature
Write-Host "[*] Verifying signature with Windows Authenticode policy..." -ForegroundColor Cyan
& $signtool verify /pa /v $resolvedBinary.Path
if ($LASTEXITCODE -ne 0) {
    Write-Error "Signature verification failed (exit code $LASTEXITCODE)."
    exit $LASTEXITCODE
}

Write-Host "[OK] Argus Vault binary successfully signed and verified with Authenticode!" -ForegroundColor Green

# ANVIL Setup Script for Windows
# Usage (PowerShell):  .\setup.ps1
# Tip: If scripts are blocked, run:
#   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

param(
    [switch]$SkipRustInstall,
    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ----------------------------
# Output helpers (ASCII only)
# ----------------------------
function Write-Title {
    param([Parameter(Mandatory)][string]$Message)

    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host $Message -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host ""
}

function Write-Status {
    param([Parameter(Mandatory)][string]$Message)
    Write-Host "[+] " -ForegroundColor Green -NoNewline
    Write-Host $Message
}

function Write-Warn {
    param([Parameter(Mandatory)][string]$Message)
    Write-Host "[!] " -ForegroundColor Yellow -NoNewline
    Write-Host $Message
}

function Write-Fail {
    param([Parameter(Mandatory)][string]$Message)
    Write-Host "[-] " -ForegroundColor Red -NoNewline
    Write-Host $Message
}

# ----------------------------
# Checks
# ----------------------------
function Test-Administrator {
    $currentUser = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-RustInstalled {
    try {
        $rustVersion = & rustc --version 2>$null
        if ($rustVersion) {
            Write-Status "Rust is installed: $rustVersion"
            return $true
        }
    } catch { }
    return $false
}

# ----------------------------
# Rust install (rustup)
# ----------------------------
function Install-Rust {
    Write-Status "Downloading Rust installer (rustup-init.exe)..."

    $rustupUrl  = "https://win.rustup.rs/x86_64"
    $rustupPath = Join-Path $env:TEMP "rustup-init.exe"

    try {
        # Ensure TLS 1.2 on older Windows/PS versions
        try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch { }

        Invoke-WebRequest -Uri $rustupUrl -OutFile $rustupPath

        Write-Status "Running Rust installer..."
        Start-Process -FilePath $rustupPath -ArgumentList "-y" -Wait -NoNewWindow

        # Refresh PATH for this session
        $machinePath = [System.Environment]::GetEnvironmentVariable("Path", "Machine")
        $userPath    = [System.Environment]::GetEnvironmentVariable("Path", "User")

        if ([string]::IsNullOrWhiteSpace($machinePath)) { $machinePath = "" }
        if ([string]::IsNullOrWhiteSpace($userPath))    { $userPath    = "" }

        if ($machinePath -and $userPath) {
            $env:Path = "$machinePath;$userPath"
        } elseif ($machinePath) {
            $env:Path = $machinePath
        } else {
            $env:Path = $userPath
        }

        # Add cargo to current session just in case
        $cargoPath = Join-Path $env:USERPROFILE ".cargo\bin"
        if ($env:Path -notlike "*$cargoPath*") {
            $env:Path += ";$cargoPath"
        }

        Write-Status "Rust installed successfully"
        return $true
    } catch {
        Write-Fail "Failed to install Rust: $($_.Exception.Message)"
        return $false
    } finally {
        if (Test-Path $rustupPath) {
            Remove-Item $rustupPath -Force -ErrorAction SilentlyContinue
        }
    }
}

# ----------------------------
# Build / Install
# ----------------------------
function Build-Anvil {
    Write-Status "Building in release mode..."
    try {
        & cargo build --release
        if ($LASTEXITCODE -eq 0) {
            Write-Status "Build completed successfully"
            return $true
        }
        Write-Fail "Build failed with exit code $LASTEXITCODE"
        return $false
    } catch {
        Write-Fail "Build failed: $($_.Exception.Message)"
        return $false
    }
}

function Install-Anvil {
    Write-Status "Installing..."
    try {
        & cargo install --path .
        if ($LASTEXITCODE -eq 0) {
            Write-Status "Installed successfully"
            return $true
        }
        Write-Fail "Installation failed with exit code $LASTEXITCODE"
        return $false
    } catch {
        Write-Fail "Installation failed: $($_.Exception.Message)"
        return $false
    }
}

function Add-CargoToPath {
    $cargoPath = Join-Path $env:USERPROFILE ".cargo\bin"
    $currentPath = [Environment]::GetEnvironmentVariable("Path", "User")

    if ([string]::IsNullOrWhiteSpace($currentPath)) { $currentPath = "" }

    if ($currentPath -notlike "*$cargoPath*") {
        Write-Status "Adding Cargo bin to user PATH..."
        $newPath = if ($currentPath) { "$currentPath;$cargoPath" } else { $cargoPath }

        [Environment]::SetEnvironmentVariable("Path", $newPath, "User")

        # Update current session too
        if ($env:Path -notlike "*$cargoPath*") {
            $env:Path += ";$cargoPath"
        }

        Write-Status "Added $cargoPath to PATH"
    } else {
        Write-Status "Cargo bin already in PATH"
    }
}

function Test-AnvilInstalled {
    try {
        $anvilVersion = & anvil --version 2>$null
        return [bool]$anvilVersion
    } catch {
        return $false
    }
}

# ----------------------------
# Main
# ----------------------------
function Main {
    Write-Title "ANVIL Setup Script (Windows)"

    if (-not (Test-Administrator)) {
        Write-Warn "Not running as Administrator. If installation fails, re-run PowerShell as Administrator."
    }

    Write-Host "Starting installation..." -ForegroundColor White
    Write-Host ""

    if (-not (Test-RustInstalled)) {
        if ($SkipRustInstall) {
            Write-Fail "Rust is not installed and -SkipRustInstall was set."
            exit 1
        }

        Write-Warn "Rust not found. Installing..."
        if (-not (Install-Rust)) {
            Write-Fail "Rust install failed. Install Rust manually and re-run."
            exit 1
        }

        if (-not (Test-RustInstalled)) {
            Write-Warn "Rust installed but not available in this session."
            Write-Warn "Close and re-open PowerShell, then run the script again."
            exit 0
        }
    }

    if (-not (Build-Anvil)) {
        Write-Fail "Build failed."
        exit 1
    }

    if (-not (Install-Anvil)) {
        Write-Fail "Installation failed."
        exit 1
    }

    Add-CargoToPath

    Write-Host ""
    Write-Host "------------------------------------------------------------" -ForegroundColor Cyan

    if (Test-AnvilInstalled) {
        $version = (& anvil --version 2>$null | Select-Object -First 1)
        Write-Status "Installed successfully!"
        Write-Host "Version: $version" -ForegroundColor White
    } else {
        Write-Warn "Installed, but 'anvil' isn't found in PATH yet."
        Write-Warn "Close and re-open PowerShell and try: anvil --version"
    }

    Write-Host "------------------------------------------------------------" -ForegroundColor Cyan
}

Main

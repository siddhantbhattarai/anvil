# ANVIL Setup Script for Windows
# Run this script in PowerShell as Administrator
# Usage: .\setup.ps1

param(
    [switch]$SkipRustInstall,
    [switch]$Force
)

$ErrorActionPreference = "Stop"

# Colors and formatting
function Write-Title {
    param([string]$Message)
    Write-Host ""
    Write-Host "╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║                    ANVIL Setup Script                          ║" -ForegroundColor Cyan
    Write-Host "║        Enterprise-grade Security Testing Framework             ║" -ForegroundColor Cyan
    Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
}

function Write-Status {
    param([string]$Message)
    Write-Host "[+] " -ForegroundColor Green -NoNewline
    Write-Host $Message
}

function Write-Warning {
    param([string]$Message)
    Write-Host "[!] " -ForegroundColor Yellow -NoNewline
    Write-Host $Message
}

function Write-Error {
    param([string]$Message)
    Write-Host "[-] " -ForegroundColor Red -NoNewline
    Write-Host $Message
}

# Check if running as Administrator
function Test-Administrator {
    $currentUser = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Check if Rust is installed
function Test-RustInstalled {
    try {
        $rustVersion = & rustc --version 2>$null
        if ($rustVersion) {
            Write-Status "Rust is installed: $rustVersion"
            return $true
        }
    } catch {
        return $false
    }
    return $false
}

# Install Rust using rustup
function Install-Rust {
    Write-Status "Downloading Rust installer..."
    
    $rustupUrl = "https://win.rustup.rs/x86_64"
    $rustupPath = "$env:TEMP\rustup-init.exe"
    
    try {
        Invoke-WebRequest -Uri $rustupUrl -OutFile $rustupPath -UseBasicParsing
        Write-Status "Running Rust installer..."
        
        # Run rustup-init with default options
        Start-Process -FilePath $rustupPath -ArgumentList "-y" -Wait -NoNewWindow
        
        # Refresh environment
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
        
        # Add cargo to current session
        $cargoPath = "$env:USERPROFILE\.cargo\bin"
        if ($env:Path -notlike "*$cargoPath*") {
            $env:Path += ";$cargoPath"
        }
        
        Write-Status "Rust installed successfully"
        return $true
    } catch {
        Write-Error "Failed to install Rust: $_"
        return $false
    } finally {
        if (Test-Path $rustupPath) {
            Remove-Item $rustupPath -Force
        }
    }
}

# Build ANVIL
function Build-Anvil {
    Write-Status "Building ANVIL in release mode..."
    
    try {
        & cargo build --release
        if ($LASTEXITCODE -eq 0) {
            Write-Status "Build completed successfully"
            return $true
        } else {
            Write-Error "Build failed with exit code $LASTEXITCODE"
            return $false
        }
    } catch {
        Write-Error "Build failed: $_"
        return $false
    }
}

# Install ANVIL
function Install-Anvil {
    Write-Status "Installing ANVIL..."
    
    try {
        & cargo install --path .
        if ($LASTEXITCODE -eq 0) {
            Write-Status "ANVIL installed successfully"
            return $true
        } else {
            Write-Error "Installation failed with exit code $LASTEXITCODE"
            return $false
        }
    } catch {
        Write-Error "Installation failed: $_"
        return $false
    }
}

# Add Cargo bin to PATH
function Add-CargoToPath {
    $cargoPath = "$env:USERPROFILE\.cargo\bin"
    
    # Get current user PATH
    $currentPath = [Environment]::GetEnvironmentVariable("Path", "User")
    
    if ($currentPath -notlike "*$cargoPath*") {
        Write-Status "Adding Cargo bin to PATH..."
        
        $newPath = "$currentPath;$cargoPath"
        [Environment]::SetEnvironmentVariable("Path", $newPath, "User")
        
        # Update current session
        $env:Path += ";$cargoPath"
        
        Write-Status "Added $cargoPath to PATH"
    } else {
        Write-Status "Cargo bin already in PATH"
    }
}

# Verify installation
function Test-AnvilInstalled {
    try {
        $anvilVersion = & anvil --version 2>$null
        if ($anvilVersion) {
            return $true
        }
    } catch {
        return $false
    }
    return $false
}

# Main installation
function Main {
    Write-Title
    
    Write-Host "Starting ANVIL installation for Windows..." -ForegroundColor White
    Write-Host ""
    
    # Check Rust
    if (-not (Test-RustInstalled)) {
        if ($SkipRustInstall) {
            Write-Error "Rust is not installed. Please install Rust first."
            Write-Host "  Download from: https://rustup.rs/"
            exit 1
        }
        
        Write-Warning "Rust not found. Installing..."
        if (-not (Install-Rust)) {
            Write-Error "Failed to install Rust. Please install manually from https://rustup.rs/"
            exit 1
        }
        
        # Verify Rust after install
        if (-not (Test-RustInstalled)) {
            Write-Warning "Rust installed but not in current session."
            Write-Warning "Please restart PowerShell and run this script again."
            exit 0
        }
    }
    
    # Build
    if (-not (Build-Anvil)) {
        Write-Error "Build failed. Please check the error messages above."
        exit 1
    }
    
    # Install
    if (-not (Install-Anvil)) {
        Write-Error "Installation failed. Please check the error messages above."
        exit 1
    }
    
    # Setup PATH
    Add-CargoToPath
    
    # Verify
    Write-Host ""
    Write-Host "════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    
    if (Test-AnvilInstalled) {
        $version = & anvil --version 2>$null | Select-Object -First 1
        Write-Status "ANVIL installed successfully!"
        Write-Host ""
        Write-Host "  Version: $version" -ForegroundColor White
        Write-Host ""
        Write-Host "  Quick start:" -ForegroundColor White
        Write-Host "    anvil --help" -ForegroundColor Gray
        Write-Host "    anvil -t 'http://target.com/page?id=1' -p id --sqli --dbs" -ForegroundColor Gray
        Write-Host ""
    } else {
        Write-Warning "ANVIL installed but not in current PATH"
        Write-Warning "Please restart PowerShell to use 'anvil' command"
    }
    
    Write-Host "════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
}

# Run main
Main

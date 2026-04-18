param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("x64", "x86")]
    [string]$Arch = "x64",

    [Parameter(Mandatory=$false)]
    [ValidateSet("Debug", "Release")]
    [string]$BuildType = "Debug",

    [Parameter(Mandatory=$false)]
    [switch]$Clean,

    [Parameter(Mandatory=$false)]
    [string]$Bind = "0.0.0.0",

    [Parameter(Mandatory=$false)]
    [string]$Port = "5678"
)

$ErrorActionPreference = "Stop"
$DllName = "dbgx-mcp.dll"
$BuildDir = "build"

Write-Host "--- WinDbg MCP Extension: Build & Deploy ---" -ForegroundColor Cyan

# 1. Initialize Visual Studio Environment
function Import-VsEnvironment {
    param([string]$Architecture)

    Write-Host "Searching for Visual Studio (2017, 2019, or 2022)..."
    $VsWherePath = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    if (-not (Test-Path $VsWherePath)) {
        # Fallback to path search
        $VsWherePath = Get-Command "vswhere.exe" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source
        if (-not $VsWherePath) {
            throw "vswhere.exe not found. Is Visual Studio installed?"
        }
    }

    # Find the latest installation starting from version 15.0 (VS 2017)
    $VsInstallPath = & $VsWherePath -latest -version "[15.0,)" -products * -property installationPath
    if (-not $VsInstallPath) {
        throw "Visual Studio 2017 or newer (or Build Tools) not found by vswhere."
    }

    $VcVarsBatch = Join-Path $VsInstallPath "VC\Auxiliary\Build\vcvarsall.bat"
    if (-not (Test-Path $VcVarsBatch)) {
        throw "vcvarsall.bat not found at $VcVarsBatch"
    }

    Write-Host "Initializing $Architecture environment from: $VcVarsBatch"

    # Run the batch file and capture the resulting environment variables
    $TempFile = [System.IO.Path]::GetTempFileName()
    $BatchCmd = "`"$VcVarsBatch`" $Architecture && set > `"$TempFile`""
    cmd.exe /c $BatchCmd | Out-Null

    Get-Content $TempFile | ForEach-Object {
        if ($_ -match "^(.*?)=(.*)$") {
            $Name = $Matches[1]
            $Value = $Matches[2]
            # Only import variables that are typically needed for building
            if ($Name -match "^(PATH|INCLUDE|LIB|LIBPATH|VCINSTALLDIR|WindowsSdk.*)$") {
                Set-Item "env:$Name" $Value
            }
        }
    }
    Remove-Item $TempFile
    Write-Host "Environment initialized." -ForegroundColor Gray
}

# Only import if compiler is not already in path OR if it's the wrong architecture
$CompilerPath = Get-Command "cl.exe" -ErrorAction SilentlyContinue
$NeedsInit = $true

if ($null -ne $CompilerPath) {
    # Check if the existing cl.exe is the right architecture
    # x64 cl.exe usually has "HostX64\x64" or "HostX86\x64" in the path
    # x86 cl.exe usually has "HostX86\x86" or "HostX64\x86" in the path
    if ($Arch -eq "x64" -and $CompilerPath.Source -like "*\x64\cl.exe") {
        $NeedsInit = $false
    } elseif ($Arch -eq "x86" -and $CompilerPath.Source -like "*\x86\cl.exe") {
        $NeedsInit = $false
    }
}

if ($NeedsInit) {
    Import-VsEnvironment -Architecture $Arch
} else {
    Write-Host "Correct compiler 'cl.exe' already in path ($($CompilerPath.Source)), skipping VS initialization." -ForegroundColor Gray
}

# 2. Clean Step & Generator Check
if (Test-Path $BuildDir) {
    $CacheFile = Join-Path $BuildDir "CMakeCache.txt"
    if (Test-Path $CacheFile) {
        $ExistingGenerator = Get-Content $CacheFile | Select-String "CMAKE_GENERATOR:INTERNAL="
        if ($null -ne $ExistingGenerator -and $ExistingGenerator.Line -notlike "*Ninja*") {
            Write-Host "Detected different generator in existing build directory. Cleaning..." -ForegroundColor Yellow
            $Clean = $true
        }
    }
}

if ($Clean -and (Test-Path $BuildDir)) {
    Write-Host "Cleaning build directory..."
    Remove-Item -Recurse -Force $BuildDir
}

if (-not (Test-Path $BuildDir)) {
    New-Item -ItemType Directory -Path $BuildDir | Out-Null
}

# 3. Build Step
Push-Location $BuildDir
try {
    Write-Host "Configuring CMake ($Arch, $BuildType)..."
    # Note: Using Ninja generator. Ensure Ninja is in your path.
    # Using quotes for the define to avoid PowerShell expansion issues with special characters if any
    cmake -G "Ninja" "-DCMAKE_BUILD_TYPE=$BuildType" ..

    Write-Host "Building project..."
    # For Ninja, --config is mostly ignored but we pass it anyway for consistency
    cmake --build . --config $BuildType
} catch {
    Write-Error "Build failed. If you recently switched Visual Studio versions or generators, try running with -Clean."
    Write-Error "Error details: $_"
    Pop-Location
    return
}
Pop-Location

# 4. Locate the DLL
$PossiblePaths = @(
    (Join-Path $BuildDir "$BuildType\$DllName")
    (Join-Path $BuildDir $DllName)
)

$DllPath = $null
foreach ($Path in $PossiblePaths) {
    if (Test-Path $Path) {
        $DllPath = Resolve-Path $Path
        break
    }
}

if ($null -eq $DllPath) {
    Write-Error "Could not find $DllName after build."
    return
}

# 5. Detect Architecture (Safety check to match target folder)
$Stream = [System.IO.File]::OpenRead($DllPath)
$Reader = New-Object System.IO.BinaryReader($Stream)
$Stream.Position = 0x3C
$PeOffset = $Reader.ReadUInt32()
$Stream.Position = $PeOffset + 4
$Machine = $Reader.ReadUInt16()
$Reader.Close()
$Stream.Close()

if ($Machine -eq 0x8664) {
    $TargetSubDir = "dbg\EngineExtensions"
} elseif ($Machine -eq 0x014c) {
    $TargetSubDir = "dbg\EngineExtensions32"
} else {
    Write-Error "Unsupported machine type: 0x$($Machine.ToString("X4"))"
    return
}

# 6. Deploy
$TargetDir = Join-Path $env:LOCALAPPDATA $TargetSubDir
if (-not (Test-Path $TargetDir)) {
    New-Item -ItemType Directory -Path $TargetDir -Force | Out-Null
}

$DestPath = Join-Path $TargetDir $DllName

try {
    Copy-Item $DllPath -Destination $DestPath -Force
    Write-Host "Successfully built and deployed DLL to: $DestPath" -ForegroundColor Green
} catch {
    Write-Error "Failed to copy DLL. Ensure WinDbg is not using it."
    return
}

# 7. Usage Instructions
Write-Host "`n--- Ready to use! ---" -ForegroundColor Cyan
Write-Host "1. Set the bind address in your current shell:"
Write-Host "   `$env:WINDBG_MCP_BIND = `"$Bind`"" -ForegroundColor Yellow
Write-Host "   `$env:WINDBG_MCP_PORT = `"$Port`"" -ForegroundColor Yellow
Write-Host "2. Start WinDbg (launch from THIS shell to inherit the BIND environment variable)."
Write-Host "3. Load the extension: .load dbgx-mcp" -ForegroundColor Yellow

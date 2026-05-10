param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("x64", "x86", "all")]
    [string]$Arch = "all",

    [Parameter(Mandatory=$false)]
    [ValidateSet("Debug", "Release")]
    [string]$BuildType = "Debug",

    [Parameter(Mandatory=$false)]
    [switch]$Clean,

    [Parameter(Mandatory=$false)]
    [string]$Bind = "0.0.0.0",

    [Parameter(Mandatory=$false)]
    [string]$Port = "5678",

    [Parameter(Mandatory=$false)]
    [switch]$Package
)

$ErrorActionPreference = "Stop"
$DllName = "dbgx-mcp.dll"
$BaseBuildDir = "build"

Write-Host "--- WinDbg MCP Extension: Build & Deploy ---" -ForegroundColor Cyan

# 1. Get Visual Studio Environment Setup Command
function Get-VsEnvironmentCmd
{
    param([string]$Architecture)

    Write-Host "Searching for Visual Studio (2017, 2019, or 2022)..."
    $VsWherePath = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    if (-not (Test-Path $VsWherePath))
    {
        $VsWherePath = Get-Command "vswhere.exe" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source
        if (-not $VsWherePath)
        {
            throw "vswhere.exe not found. Is Visual Studio installed?"
        }
    }

    $VsInstallPath = & $VsWherePath -latest -version "[15.0,)" -products * -property installationPath
    if (-not $VsInstallPath)
    {
        throw "Visual Studio 2017 or newer (or Build Tools) not found by vswhere."
    }

    $VcVarsBatch = Join-Path $VsInstallPath "VC\Auxiliary\Build\vcvarsall.bat"
    if (-not (Test-Path $VcVarsBatch))
    {
        throw "vcvarsall.bat not found at $VcVarsBatch"
    }

    return "`"$VcVarsBatch`" $Architecture"
}

# Determine architectures to build
$BuiltArtifacts = @()
$ArchsToBuild = @()
if ($Arch -eq "all")
{
    $ArchsToBuild = @("x64", "x86")
} else
{
    $ArchsToBuild = @($Arch)
}

foreach ($CurrentArch in $ArchsToBuild)
{
    Write-Host "`n>>> Processing Architecture: $CurrentArch <<<" -ForegroundColor Cyan

    # 2. Import environment variables specifically for current loop target
    $CompilerPath = Get-Command "cl.exe" -ErrorAction SilentlyContinue
    $NeedsInit = $true

    if ($null -ne $CompilerPath -and $ArchsToBuild.Count -eq 1)
    {
        if ($CurrentArch -eq "x64" -and $CompilerPath.Source -like "*\x64\cl.exe")
        {
            $NeedsInit = $false
        } elseif ($CurrentArch -eq "x86" -and $CompilerPath.Source -like "*\x86\cl.exe")
        {
            $NeedsInit = $false
        }
    }

    $EnvCmd = ""
    if ($NeedsInit -or $ArchsToBuild.Count -gt 1)
    {
        $EnvCmd = Get-VsEnvironmentCmd -Architecture $CurrentArch
    } else
    {
        Write-Host "Correct compiler 'cl.exe' already in path ($($CompilerPath.Source)), skipping VS initialization." -ForegroundColor Gray
    }

    # Establish isolated architecture-specific build sub-folder
    $BuildDir = Join-Path $BaseBuildDir $CurrentArch

    # 3. Clean Step & Generator Check
    if (Test-Path $BuildDir)
    {
        $CacheFile = Join-Path $BuildDir "CMakeCache.txt"
        if (Test-Path $CacheFile)
        {
            $ExistingGenerator = Get-Content $CacheFile | Select-String "CMAKE_GENERATOR:INTERNAL="
            if ($null -ne $ExistingGenerator -and $ExistingGenerator.Line -notlike "*Ninja*")
            {
                Write-Host "Detected different generator in existing build directory. Cleaning..." -ForegroundColor Yellow
                $Clean = $true
            }
        }
    }

    if ($Clean -and (Test-Path $BuildDir))
    {
        Write-Host "Cleaning build directory ($BuildDir)..."
        Remove-Item -Recurse -Force $BuildDir
    }

    if (-not (Test-Path $BuildDir))
    {
        New-Item -ItemType Directory -Path $BuildDir | Out-Null
    }

    # 4. Build Step
    Push-Location $BuildDir
    try
    {
        Write-Host "Configuring CMake for $CurrentArch ($BuildType)..."
        $sysProc = "AMD64"
        if ($CurrentArch -eq "x86")
        { $sysProc = "X86"
        }

        $ConfigCmd = "cmake -G `"Ninja`" `"-DCMAKE_BUILD_TYPE=$BuildType`" `"-DCMAKE_SYSTEM_PROCESSOR=$sysProc`" ..\.."
        $BuildCmd = "cmake --build . --config $BuildType"

        Write-Host "Building project..."
        $BuildTimer = [System.Diagnostics.Stopwatch]::StartNew()

        if ($EnvCmd)
        {
            # Execute in a sub-process so we don't mess up the current session environment
            $FullCmd = "$EnvCmd >nul && $ConfigCmd && $BuildCmd"

            # Temporarily truncate PATH to core Windows directories only to bypass the 8192 character cmd.exe limit
            $OldPath = $env:PATH
            try
            {
                $env:PATH = "C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem;C:\Windows\System32\WindowsPowerShell\v1.0\"
                cmd.exe /c $FullCmd
                $CmdExitCode = $LASTEXITCODE
            } finally
            {
                $env:PATH = $OldPath
            }
            if ($CmdExitCode -ne 0)
            { throw "Build failed with exit code $CmdExitCode"
            }
        } else
        {
            Invoke-Expression $ConfigCmd
            if ($LASTEXITCODE -ne 0)
            { throw "CMake config failed with exit code $LASTEXITCODE"
            }
            Invoke-Expression $BuildCmd
            if ($LASTEXITCODE -ne 0)
            { throw "CMake build failed with exit code $LASTEXITCODE"
            }
        }

        $BuildTimer.Stop()
        $Duration = [Math]::Round($BuildTimer.Elapsed.TotalSeconds, 2)
        Write-Host "Compile duration: $Duration seconds" -ForegroundColor Green
    } catch
    {
        Write-Error "Build failed for architecture $CurrentArch."
        Write-Error "Error details: $_"
        Pop-Location
        continue
    }
    Pop-Location

    # 5. Locate the DLL
    $PossiblePaths = @(
        (Join-Path $BuildDir "$BuildType\$DllName")
        (Join-Path $BuildDir $DllName)
    )

    $DllPath = $null
    foreach ($Path in $PossiblePaths)
    {
        if (Test-Path $Path)
        {
            $DllPath = Resolve-Path $Path
            break
        }
    }

    if ($null -eq $DllPath)
    {
        Write-Error "Could not find $DllName after build for $CurrentArch."
        continue
    }

    $PdbName = "dbgx-mcp.pdb"
    $PossiblePdbPaths = @(
        (Join-Path $BuildDir "$BuildType\$PdbName")
        (Join-Path $BuildDir $PdbName)
    )
    $PdbPath = $null
    foreach ($Path in $PossiblePdbPaths)
    {
        if (Test-Path $Path)
        {
            $PdbPath = Resolve-Path $Path
            break
        }
    }

    if ($Package)
    {
        $BuiltArtifacts += [PSCustomObject]@{
            Arch = $CurrentArch
            Dll  = $DllPath
            Pdb  = $PdbPath
        }
    }

    # 6. Detect Architecture from machine parameters (safety verification)
    $Stream = [System.IO.File]::OpenRead($DllPath)
    $Reader = New-Object System.IO.BinaryReader($Stream)
    $Stream.Position = 0x3C
    $PeOffset = $Reader.ReadUInt32()
    $Stream.Position = $PeOffset + 4
    $Machine = $Reader.ReadUInt16()
    $Reader.Close()
    $Stream.Close()

    if ($Machine -eq 0x8664)
    {
        $TargetSubDir = "dbg\EngineExtensions"
    } elseif ($Machine -eq 0x014c)
    {
        $TargetSubDir = "dbg\EngineExtensions32"
    } else
    {
        Write-Error "Unsupported machine type found: 0x$($Machine.ToString("X4"))"
        continue
    }

    # 7. Deploy (skipped in CI/CD packaging modes)
    if (-not $Package)
    {
        $TargetDir = Join-Path $env:LOCALAPPDATA $TargetSubDir
        if (-not (Test-Path $TargetDir))
        {
            New-Item -ItemType Directory -Path $TargetDir -Force | Out-Null
        }

        $DestPath = Join-Path $TargetDir $DllName

        try
        {
            Copy-Item $DllPath -Destination $DestPath -Force
            Write-Host "Successfully built and deployed $CurrentArch DLL to: $DestPath" -ForegroundColor Green
        } catch
        {
            Write-Error "Failed to copy DLL for $CurrentArch. Ensure WinDbg is not locking or using it."
            continue
        }
    } else
    {
        Write-Host "Skipping local deployment for $CurrentArch (packaging active)." -ForegroundColor Gray
    }
}

# 8. Create Package of Build Artifacts
if ($Package -and $BuiltArtifacts.Count -gt 0)
{
    Write-Host "`n--- Packaging Build Artifacts ---" -ForegroundColor Cyan
    $DistFolder = Join-Path $PSScriptRoot "dist"

    if (Test-Path $DistFolder)
    {
        Remove-Item -Recurse -Force $DistFolder
    }
    New-Item -ItemType Directory -Path $DistFolder | Out-Null

    foreach ($Artifact in $BuiltArtifacts)
    {
        $ArchFolder = Join-Path $DistFolder $Artifact.Arch
        New-Item -ItemType Directory -Path $ArchFolder -Force | Out-Null

        Copy-Item $Artifact.Dll -Destination $ArchFolder -Force
        if ($null -ne $Artifact.Pdb -and (Test-Path $Artifact.Pdb))
        {
            Copy-Item $Artifact.Pdb -Destination $ArchFolder -Force
        }
        Write-Host "Collected artifacts for $($Artifact.Arch) to: $ArchFolder" -ForegroundColor Gray
    }

    $ZipPath = Join-Path $PSScriptRoot "dist.zip"
    if (Test-Path $ZipPath)
    {
        Remove-Item -Force $ZipPath
    }

    Write-Host "Creating archive dist.zip..." -ForegroundColor Gray
    Compress-Archive -Path "$DistFolder\*" -DestinationPath $ZipPath -Force
    Write-Host "Successfully packaged all build artifacts to: $ZipPath" -ForegroundColor Green
}

# 9. Final usage layout instructions
Write-Host "`n--- Ready to use! ---" -ForegroundColor Cyan
Write-Host "1. Set the bind address in your current shell:"
Write-Host "   `$env:WINDBG_MCP_BIND = `"$Bind`"" -ForegroundColor Yellow
Write-Host "   `$env:WINDBG_MCP_PORT = `"$Port`"" -ForegroundColor Yellow
Write-Host "2. Start WinDbg (launch from THIS shell to inherit the BIND environment variable)."
Write-Host "3. Load the extension: .load dbgx-mcp" -ForegroundColor Yellow

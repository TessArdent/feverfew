# Builds Feverfew.exe and packages it as dist\setup.exe.
# Needs the .NET SDK (8 or later) and Inno Setup 6.
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot

[xml]$project = Get-Content 'src\Feverfew\Feverfew.csproj'
$version = ($project.Project.PropertyGroup | ForEach-Object { $_.Version } | Where-Object { $_ }) | Select-Object -First 1

dotnet build 'src\Feverfew\Feverfew.csproj' -c Release --nologo
if ($LASTEXITCODE -ne 0) { throw 'dotnet build failed' }

$iscc = @(
    "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe",
    "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
    "$env:ProgramFiles\Inno Setup 6\ISCC.exe"
) | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $iscc) { throw 'Inno Setup 6 not found. Install it with: winget install JRSoftware.InnoSetup' }

& $iscc /Qp "/DAppVersion=$version" 'installer\setup.iss'
if ($LASTEXITCODE -ne 0) { throw 'Inno Setup failed' }

$hash = (Get-FileHash 'dist\setup.exe' -Algorithm SHA256).Hash
Write-Host "dist\setup.exe  version $version  SHA256 $hash"

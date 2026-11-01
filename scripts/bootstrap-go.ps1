$ErrorActionPreference='Stop'
$root=(Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$toolRoot=Join-Path $root '.tooling'
$goExe=Join-Path $toolRoot 'go\bin\go.exe'
if (Test-Path -LiteralPath $goExe) { & $goExe version; exit $LASTEXITCODE }
New-Item -ItemType Directory -Force -Path $toolRoot | Out-Null
$zip=Join-Path $toolRoot 'go1.26.10.windows-amd64.zip'
Invoke-WebRequest -Uri 'https://go.dev/dl/go1.26.10.windows-amd64.zip' -OutFile $zip
$expected='7ecd2d7260e82c59bcbd7f1077a07cee2dea607295b858df67195a1e4e09629b'
$actual=(Get-FileHash -Algorithm SHA256 -LiteralPath $zip).Hash.ToLowerInvariant()
if ($actual -ne $expected) { throw "Go archive checksum mismatch: $actual" }
Expand-Archive -LiteralPath $zip -DestinationPath $toolRoot -Force
& $goExe version

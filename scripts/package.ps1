param([string]$Name = '')
$ErrorActionPreference = 'Stop'
$repoPath = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
Push-Location -LiteralPath $repoPath
try {
    $metadata = (& cargo metadata --format-version 1 --locked --no-deps) | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0) { throw 'Package metadata failed' }
    $version = ($metadata.packages | Where-Object { $_.name -eq 'unbolt' }).version
    if ([string]::IsNullOrEmpty($Name)) { $Name = 'Unbolt-' + $version + '-windows-x64' }
    if ($Name -notmatch '^Unbolt-[A-Za-z0-9.-]+$') { throw 'Invalid package name' }
    & cargo build --release --locked --bin unbolt --bin unbolt-cli --bin unbolt-helper
    if ($LASTEXITCODE -ne 0) { throw 'Release build failed' }
    $packagePath = Join-Path $repoPath ('dist\' + $Name)
    if (Test-Path -LiteralPath $packagePath) { throw 'Choose a new package name; output already exists' }
    [IO.Directory]::CreateDirectory($packagePath) | Out-Null
    foreach ($pair in @(@('unbolt.exe', 'Unbolt.exe'), @('unbolt-cli.exe', 'UnboltCLI.exe'), @('unbolt-helper.exe', 'UnboltHelper.exe'))) {
        Copy-Item -LiteralPath (Join-Path $repoPath ('target\release\' + $pair[0])) -Destination (Join-Path $packagePath $pair[1])
    }
    foreach ($file in @('README.md', 'LICENSE', 'CHANGELOG.md')) {
        Copy-Item -LiteralPath (Join-Path $repoPath $file) -Destination $packagePath
    }
    Copy-Item -LiteralPath (Join-Path $repoPath 'assets') -Destination (Join-Path $packagePath 'assets') -Recurse
    $docsPath = Join-Path $packagePath 'docs'
    [IO.Directory]::CreateDirectory($docsPath) | Out-Null
    Get-ChildItem -LiteralPath (Join-Path $repoPath 'docs') -Filter '*.md' -File | Copy-Item -Destination $docsPath
    $metadata = (& cargo metadata --format-version 1 --locked) | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0) { throw 'Dependency metadata failed' }
    $noticesPath = Join-Path $packagePath 'ThirdParty'
    [IO.Directory]::CreateDirectory($noticesPath) | Out-Null
    $notices = foreach ($dependency in $metadata.packages | Where-Object { $_.name -ne 'unbolt' }) {
        $dependencyPath = Join-Path $noticesPath ($dependency.name + '-' + $dependency.version)
        [IO.Directory]::CreateDirectory($dependencyPath) | Out-Null
        $sourcePath = Split-Path -Parent $dependency.manifest_path
        Get-ChildItem -LiteralPath $sourcePath -File | Where-Object { $_.Name -match '^(LICENSE|COPYING|NOTICE)' } | Copy-Item -Destination $dependencyPath
        [pscustomobject]@{ name = $dependency.name; version = $dependency.version; license = $dependency.license; repository = $dependency.repository }
    }
    $notices | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $noticesPath 'dependencies.json') -Encoding utf8
    $files = foreach ($file in Get-ChildItem -LiteralPath $packagePath -Recurse -File) {
        [pscustomobject]@{ path = $file.FullName.Substring($packagePath.Length + 1); bytes = $file.Length; sha256 = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash }
    }
    [pscustomobject]@{ name = $Name; version = $version; platform = 'windows-x64'; builtAtUtc = [DateTime]::UtcNow.ToString('O'); sourceCommit = (& git rev-parse HEAD); sourceChanges = @(& git status --porcelain); testFixturesIncluded = $false; files = @($files) } |
        ConvertTo-Json -Depth 7 | Set-Content -LiteralPath (Join-Path $packagePath 'BUILD.json') -Encoding utf8
    $archivePath = Join-Path $repoPath ('dist\' + $Name + '.zip')
    if (Test-Path -LiteralPath $archivePath) { throw 'Archive already exists' }
    Compress-Archive -LiteralPath $packagePath -DestinationPath $archivePath
    Write-Output $packagePath
    Write-Output $archivePath
} finally {
    Pop-Location
}

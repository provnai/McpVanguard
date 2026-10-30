#requires -Version 5.1
[CmdletBinding()]
param(
    [string]$PythonExe,
    [string]$NodeExe,
    [string]$NpmCli
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Invoke-IsolatedCommand {
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [string[]]$ArgumentList = @(),
        [hashtable]$EnvironmentOverrides = @{}
    )

    $allowedNames = @('PATH', 'SYSTEMROOT', 'WINDIR', 'TEMP', 'TMP', 'COMSPEC', 'PATHEXT',
        'USERPROFILE', 'HOMEDRIVE', 'HOMEPATH', 'APPDATA', 'LOCALAPPDATA', 'PROGRAMDATA',
        'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'NO_PROXY')
    $savedEnvironment = @{}
    $overrideNames = @($EnvironmentOverrides.Keys | ForEach-Object { ([string]$_).ToUpperInvariant() })
    foreach ($item in Get-ChildItem Env:) {
        if ($allowedNames -notcontains $item.Name.ToUpperInvariant() -or
            $overrideNames -contains $item.Name.ToUpperInvariant()) {
            $savedEnvironment[$item.Name] = $item.Value
            Remove-Item -LiteralPath "Env:$($item.Name)"
        }
    }
    try {
        foreach ($name in $EnvironmentOverrides.Keys) {
            Set-Item -LiteralPath "Env:$name" -Value ([string]$EnvironmentOverrides[$name])
        }
        # Windows PowerShell 5.1 wraps native stderr as ErrorRecord objects.
        # Capture those diagnostics, then decide success from the native exit code.
        $savedErrorAction = $ErrorActionPreference
        try {
            $ErrorActionPreference = 'Continue'
            $global:LASTEXITCODE = $null
            $commandOutput = & $FilePath @ArgumentList 2>&1
            $commandExitCode = $global:LASTEXITCODE
        }
        finally {
            $ErrorActionPreference = $savedErrorAction
        }
        if ($null -eq $commandExitCode) {
            throw "Could not start native command: $FilePath"
        }
        return [pscustomobject]@{ Output = @($commandOutput); ExitCode = $commandExitCode }
    }
    finally {
        foreach ($entry in $savedEnvironment.GetEnumerator()) {
            Set-Item -LiteralPath "Env:$($entry.Key)" -Value $entry.Value
        }
        foreach ($name in $EnvironmentOverrides.Keys) {
            if (-not $savedEnvironment.ContainsKey([string]$name)) {
                Remove-Item -LiteralPath "Env:$name" -ErrorAction SilentlyContinue
            }
        }
    }
}

$scriptsRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$kitRoot = Join-Path $scriptsRoot 'filesystem-evaluation'
$runner = Join-Path $scriptsRoot 'filesystem_walkthrough.py'
$relay = Join-Path $scriptsRoot 'filesystem_relay.py'
$probe = Join-Path $scriptsRoot 'filesystem_probe.py'
$pythonLock = Join-Path $kitRoot 'requirements.lock'
$npmManifest = Join-Path $kitRoot 'package.json'
$npmLock = Join-Path $kitRoot 'package-lock.json'
$requirementsInput = Join-Path $kitRoot 'requirements.in'
$powershellRunner = Join-Path $scriptsRoot 'run_filesystem_walkthrough.ps1'
$testFile = Join-Path (Split-Path -Parent $scriptsRoot) 'tests\test_filesystem_walkthrough.py'
$guide = Join-Path (Split-Path -Parent $scriptsRoot) 'docs\FILESYSTEM_WALKTHROUGH.md'

foreach ($required in @($runner, $relay, $probe, $pythonLock, $npmManifest, $npmLock, $requirementsInput, $powershellRunner, $testFile, $guide)) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
        throw "Evaluation kit file is missing: $required"
    }
}

if (-not $PythonExe) {
    $PythonExe = (Get-Command python.exe -ErrorAction Stop).Source
}
if (-not $NodeExe) {
    $NodeExe = (Get-Command node.exe -ErrorAction Stop).Source
}
if (-not (Test-Path -LiteralPath $PythonExe -PathType Leaf)) {
    throw "Python executable was not found: $PythonExe"
}
if (-not (Test-Path -LiteralPath $NodeExe -PathType Leaf)) {
    throw "Node executable was not found: $NodeExe"
}

$pythonCheck = Invoke-IsolatedCommand -FilePath $PythonExe -ArgumentList @('--version')
$pythonVersion = ($pythonCheck.Output -join "`n").Trim()
if ($pythonCheck.ExitCode -ne 0 -or $pythonVersion -ne 'Python 3.12.14') {
    throw "Use CPython 3.12.14; found '$pythonVersion'"
}
$nodeCheck = Invoke-IsolatedCommand -FilePath $NodeExe -ArgumentList @('--version')
$nodeVersion = ($nodeCheck.Output -join "`n").Trim()
if ($nodeCheck.ExitCode -ne 0 -or $nodeVersion -ne 'v24.22.1') {
    throw "Use Node v24.22.1; found '$nodeVersion'"
}

$npmCandidates = @()
if ($NpmCli) {
    $npmCandidates += $NpmCli
}
else {
    $bundledNpmCli = Join-Path (Split-Path -Parent $NodeExe) 'node_modules\npm\bin\npm-cli.js'
    $npmCandidates += $bundledNpmCli
    $npmLauncher = Get-Command npm.ps1 -ErrorAction SilentlyContinue
    if ($npmLauncher) {
        $npmCandidates += Join-Path (Split-Path -Parent $npmLauncher.Source) 'node_modules\npm\bin\npm-cli.js'
    }
}

$npmCli = $null
$npmPackageJson = $null
$npmVersion = $null
$npmAttempts = @()
foreach ($candidate in ($npmCandidates | Select-Object -Unique)) {
    if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
        $npmAttempts += "$candidate (not found)"
        continue
    }
    $resolvedCandidate = (Resolve-Path -LiteralPath $candidate).Path
    $candidatePackageJson = Join-Path (Split-Path -Parent (Split-Path -Parent $resolvedCandidate)) 'package.json'
    if (-not (Test-Path -LiteralPath $candidatePackageJson -PathType Leaf)) {
        $npmAttempts += "$candidate (adjacent npm package.json not found)"
        continue
    }
    try {
        $candidateMetadata = Get-Content -LiteralPath $candidatePackageJson -Raw | ConvertFrom-Json
        $candidateName = $candidateMetadata.name
        $candidateVersion = $candidateMetadata.version
    }
    catch {
        $npmAttempts += "$candidate (invalid adjacent package.json)"
        continue
    }
    if ($candidateName -eq 'npm' -and $candidateVersion -eq '10.9.4') {
        $npmCli = $resolvedCandidate
        $npmPackageJson = $candidatePackageJson
        $npmVersion = $candidateVersion
        break
    }
    $npmAttempts += "$candidate (package metadata identifies ${candidateName}@${candidateVersion})"
}
if (-not $npmCli) {
    $attemptSummary = $npmAttempts -join '; '
    throw "This walkthrough requires npm 10.9.4. Pass -NpmCli with its npm-cli.js path. Checked: $attemptSummary"
}

$originalPath = $env:PATH
$originalTemp = $env:TEMP
$originalTmp = $env:TMP
$gitCommand = Get-Command git.exe -ErrorAction SilentlyContinue
$gitPathEntries = @()
if ($gitCommand) {
    $gitDirectory = Split-Path -Parent $gitCommand.Source
    $gitPathEntries += $gitDirectory
    $gitRuntime = Join-Path (Split-Path -Parent $gitDirectory) 'mingw64\bin'
    if (Test-Path -LiteralPath $gitRuntime -PathType Container) { $gitPathEntries += $gitRuntime }
}
$tempRoot = (Resolve-Path -LiteralPath $env:TEMP).Path.TrimEnd('\')
$evaluationRoot = Join-Path $tempRoot ('mcpvanguard-evaluation-' + [guid]::NewGuid().ToString())
if ((Split-Path -Parent $evaluationRoot).TrimEnd('\') -ine $tempRoot) {
    throw "Refusing to create evaluation files outside the temp directory: $evaluationRoot"
}
$dependencyPathProbe = Join-Path $evaluationRoot 'venv\Lib\site-packages\cryptography\hazmat\bindings\_rust.pyd'
if ($dependencyPathProbe.Length -gt 240) {
    throw "The generated dependency path is too long for reliable Windows loading ($($dependencyPathProbe.Length) characters). Set TEMP and TMP to a shorter local directory and retry."
}

$env:PATH = (@((Split-Path -Parent $PythonExe), (Split-Path -Parent $NodeExe),
    (Join-Path $env:SystemRoot 'System32')) + $gitPathEntries) -join [IO.Path]::PathSeparator
$createdEvaluationRoot = $false
try {
    New-Item -ItemType Directory -Path $evaluationRoot | Out-Null
    $createdEvaluationRoot = $true
    $env:TEMP = $evaluationRoot
    $env:TMP = $evaluationRoot
    $venv = Join-Path $evaluationRoot 'venv'
    $venvResult = Invoke-IsolatedCommand -FilePath $PythonExe -ArgumentList @('-m', 'venv', $venv)
    if ($venvResult.ExitCode -ne 0) {
        $venvResult.Output | ForEach-Object { Write-Host $_ }
        throw 'Could not create the disposable Python environment'
    }

    $venvPython = Join-Path $venv 'Scripts\python.exe'
    $pipResult = Invoke-IsolatedCommand -FilePath $venvPython -ArgumentList @(
        '-m', 'pip', 'install', '--disable-pip-version-check', '--no-cache-dir',
        '--require-hashes', '--index-url', 'https://pypi.org/simple', '-r', $pythonLock) `
        -EnvironmentOverrides @{ PIP_CONFIG_FILE = 'nul' }
    if ($pipResult.ExitCode -ne 0) {
        $pipResult.Output | ForEach-Object { Write-Host $_ }
        throw 'Hash-locked Python dependency installation failed'
    }

    Copy-Item -LiteralPath $npmManifest -Destination (Join-Path $evaluationRoot 'package.json')
    Copy-Item -LiteralPath $npmLock -Destination (Join-Path $evaluationRoot 'package-lock.json')
    $npmCache = Join-Path $evaluationRoot 'npm-cache'
    $emptyNpmUserConfig = Join-Path $evaluationRoot 'empty-user.npmrc'
    $emptyNpmGlobalConfig = Join-Path $evaluationRoot 'empty-global.npmrc'
    New-Item -ItemType File -Path $emptyNpmUserConfig | Out-Null
    New-Item -ItemType File -Path $emptyNpmGlobalConfig | Out-Null
    Push-Location $evaluationRoot
    try {
        $npmCheck = Invoke-IsolatedCommand -FilePath $NodeExe -ArgumentList @($npmCli, '--version')
        $reportedNpmVersion = ($npmCheck.Output -join "`n").Trim()
        if ($npmCheck.ExitCode -ne 0 -or $reportedNpmVersion -ne $npmVersion) {
            throw "npm CLI runtime mismatch: package metadata says $npmVersion but CLI reported '$reportedNpmVersion'"
        }
        $npmResult = Invoke-IsolatedCommand -FilePath $NodeExe -ArgumentList @(
            $npmCli, 'ci', '--ignore-scripts', '--no-audit', '--no-fund',
            '--registry', 'https://registry.npmjs.org/', '--userconfig', $emptyNpmUserConfig,
            '--globalconfig', $emptyNpmGlobalConfig, '--cache', $npmCache)
        if ($npmResult.ExitCode -ne 0) {
            $npmResult.Output | ForEach-Object { Write-Host $_ }
            throw 'Locked upstream npm dependency installation failed'
        }
    }
    finally {
        Pop-Location
    }

    $entry = Join-Path $evaluationRoot 'node_modules\@modelcontextprotocol\server-filesystem\dist\index.js'
    $evaluationResult = Invoke-IsolatedCommand -FilePath $venvPython -ArgumentList @(
        $runner, '--server-entry', $entry, '--python-lock', $pythonLock, '--npm-lock', $npmLock)
    if ($evaluationResult.ExitCode -ne 0) {
        $evaluationResult.Output | ForEach-Object { Write-Host $_ }
        throw 'The filesystem walkthrough failed'
    }
    $json = $evaluationResult.Output -join "`n"
    $report = $json | ConvertFrom-Json
    if (-not $report.passed -or $report.environment.python -ne '3.12.14' -or
        $report.environment.python_implementation -ne 'CPython' -or
        [string]::IsNullOrWhiteSpace([string]$report.environment.pip) -or
        $report.environment.node -ne 'v24.22.1' -or $report.upstream.version -ne '2.1.0' -or
        $report.mcpvanguard.version -ne '2.2.2' -or
        $report.dependency_locks.python.package_count -lt 1 -or
        $report.dependency_locks.npm.locked_package_count -lt 1 -or
        @($report.runner.kit_file_sha256.PSObject.Properties).Count -ne 10 -or
        $report.runner.kit_file_sha256.'scripts/filesystem_probe.py' -notmatch '^[0-9a-f]{64}$') {
        throw 'The walkthrough returned an incomplete or mismatched report'
    }
    foreach ($property in $report.runner.kit_file_sha256.PSObject.Properties) {
        if ($property.Value -notmatch '^[0-9a-f]{64}$') {
            throw "The report has no valid SHA-256 for $($property.Name)"
        }
    }
    $expectedKit = @{
        'scripts/filesystem_walkthrough.py' = $runner
        'scripts/filesystem_relay.py' = $relay
        'scripts/filesystem_probe.py' = $probe
        'scripts/run_filesystem_walkthrough.ps1' = $powershellRunner
        'scripts/filesystem-evaluation/requirements.in' = $requirementsInput
        'scripts/filesystem-evaluation/requirements.lock' = $pythonLock
        'scripts/filesystem-evaluation/package.json' = $npmManifest
        'scripts/filesystem-evaluation/package-lock.json' = $npmLock
        'tests/test_filesystem_walkthrough.py' = $testFile
        'docs/FILESYSTEM_WALKTHROUGH.md' = $guide
    }
    foreach ($name in $expectedKit.Keys) {
        $expectedHash = (Get-FileHash -LiteralPath $expectedKit[$name] -Algorithm SHA256).Hash.ToLowerInvariant()
        $reportedHash = $report.runner.kit_file_sha256.PSObject.Properties[$name]
        if ($null -eq $reportedHash -or $reportedHash.Value -ne $expectedHash) {
            throw "Evaluation kit hash mismatch: $name"
        }
    }
    foreach ($mode in @('broad', 'native', 'guarded')) {
        $case = $report.cases.$mode
        $expectedIds = if ($mode -eq 'guarded') { @(2, 4) } else { @(2, 3, 4, 5) }
        if ($case.upstream_probe_ready -ne $true -or @($case.upstream_response_missing_ids).Count -ne 0) {
            throw "Probe readiness or missing-response check failed: $mode"
        }
        foreach ($field in @('relay_received_call_ids', 'upstream_ingress_call_ids',
                              'upstream_forwarded_call_ids', 'upstream_response_call_ids')) {
            if ((@($case.$field) -join ',') -ne ($expectedIds -join ',')) {
                throw "Probe IDs mismatch in ${mode}: $field"
            }
        }
    }
    if ($report.cases.guarded.protected_fixture_sha256_before -notmatch '^[0-9a-f]{64}$' -or
        $report.cases.guarded.protected_fixture_sha256_before -ne $report.cases.guarded.protected_fixture_sha256_after) {
        throw 'Protected fixture hash changed or is missing'
    }
    $report.environment | Add-Member -NotePropertyName npm -NotePropertyValue $npmVersion -Force
    $report.environment | Add-Member -NotePropertyName powershell `
        -NotePropertyValue $PSVersionTable.PSVersion.ToString() -Force
    $report.environment | Add-Member -NotePropertyName powershell_edition `
        -NotePropertyValue $PSVersionTable.PSEdition -Force
    $report.runner | Add-Member -NotePropertyName npm_cli_sha256 `
        -NotePropertyValue (Get-FileHash -LiteralPath $npmCli -Algorithm SHA256).Hash.ToLowerInvariant() -Force
    $report.runner | Add-Member -NotePropertyName npm_package_json_sha256 `
        -NotePropertyValue (Get-FileHash -LiteralPath $npmPackageJson -Algorithm SHA256).Hash.ToLowerInvariant() -Force
    Write-Output ($report | ConvertTo-Json -Depth 100)
}
finally {
    try {
        if ($createdEvaluationRoot -and (Test-Path -LiteralPath $evaluationRoot)) {
            $resolvedEvaluation = (Resolve-Path -LiteralPath $evaluationRoot).Path
            $leaf = Split-Path -Leaf $resolvedEvaluation
            $resolvedParent = (Split-Path -Parent $resolvedEvaluation).TrimEnd('\')
            if ($resolvedParent -ine $tempRoot -or $leaf -notmatch '^mcpvanguard-evaluation-[0-9a-f-]{36}$') {
                throw "Refusing cleanup outside the exact generated temp directory: $resolvedEvaluation"
            }
            $item = Get-Item -LiteralPath $resolvedEvaluation -Force
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Refusing to recursively remove a reparse point: $resolvedEvaluation"
            }
            Remove-Item -LiteralPath $resolvedEvaluation -Recurse -Force
        }
    }
    finally {
        $env:PATH = $originalPath
        $env:TEMP = $originalTemp
        $env:TMP = $originalTmp
    }
}

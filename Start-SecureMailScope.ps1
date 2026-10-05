param([int]$Port=8000, [switch]$LabTrust)
$ErrorActionPreference = 'Stop'
$project = $PSScriptRoot
$pythonPath = Join-Path $project '.venv\Scripts\python.exe'
$ready = Join-Path $project '.venv\.securemailscope-ready'
if (-not (Test-Path -LiteralPath $pythonPath)) {
    Write-Host 'First run: creating the local Python environment.'
    & python -m venv (Join-Path $project '.venv')
    if ($LASTEXITCODE -ne 0) { throw 'Python 3.14 is recommended (the tested version).' }
}
if (-not (Test-Path -LiteralPath $ready)) {
    Write-Host 'Installing tested dependencies. Failed installs can be retried.'
    & $pythonPath -m pip install -r (Join-Path $project 'backend\requirements-tested.txt')
    if ($LASTEXITCODE -ne 0) { throw 'Dependency installation failed; verify Internet access and retry.' }
    Set-Content -LiteralPath $ready -Value 'Dependencies installed successfully.'
}
$previousTrustStore = $env:SMS_TRUST_STORE
Push-Location (Join-Path $project 'backend')
try {
    if ($LabTrust) {
        $env:SMS_TRUST_STORE = Join-Path $project 'sample-captures\lab-root-ca.pem'
        Write-Host 'Trusting the included synthetic lab CA for this server only.'
    }
    Write-Host "Open http://127.0.0.1:$Port - Ctrl+C stops the server."
    & $pythonPath -m uvicorn app.main:app --host 127.0.0.1 --port $Port
} finally {
    $env:SMS_TRUST_STORE = $previousTrustStore
    Pop-Location
}

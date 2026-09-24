# Verifies the whole Voss tree before a merge. Must exit 0 to merge.
# Usage:  powershell -ExecutionPolicy Bypass -File .\verify.ps1

$ErrorActionPreference = "Stop"

Write-Host "== compile =="
python -m compileall -q voss tests
if ($LASTEXITCODE -ne 0) { Write-Error "compileall failed"; exit 1 }

Write-Host "== full suite =="
python -m unittest discover -s tests -v
if ($LASTEXITCODE -ne 0) { Write-Error "unittest failed"; exit 1 }

Write-Host ""
Write-Host "VERIFY OK"
exit 0
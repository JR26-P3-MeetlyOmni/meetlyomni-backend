# Test Git hooks functionality script
Write-Host "Testing Git hooks..." -ForegroundColor Cyan

# Check if pre-commit hook exists
if (Test-Path .git/hooks/pre-commit) {
    Write-Host "pre-commit hook file exists" -ForegroundColor Green
    
    # Display hook content
    Write-Host "`nHook content:" -ForegroundColor Yellow
    Get-Content .git/hooks/pre-commit | ForEach-Object { Write-Host "  $_" -ForegroundColor White }
    
    # Test dotnet commands availability
    Write-Host "`nTesting dotnet command availability..." -ForegroundColor Cyan
    
    try {
        $formatResult = dotnet format MeetlyOmni.sln --dry-run --verbosity quiet 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Host "dotnet format: Available" -ForegroundColor Green
        } else {
            Write-Host "dotnet format: Has formatting issues that need to be fixed" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "dotnet format: Failed - $_" -ForegroundColor Red
    }
    
    try {
        $buildResult = dotnet build MeetlyOmni.sln --no-restore --verbosity quiet 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Host "dotnet build: Success" -ForegroundColor Green
        } else {
            Write-Host "dotnet build: Has warnings or errors" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "dotnet build: Failed - $_" -ForegroundColor Red
    }
    
    try {
        $testResult = dotnet test MeetlyOmni.sln --no-build --verbosity quiet 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Host "dotnet test: Success" -ForegroundColor Green
        } else {
            Write-Host "dotnet test: Has failing tests" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "dotnet test: Failed - $_" -ForegroundColor Red
    }
    
    Write-Host "`nHook testing completed! You can now commit code normally." -ForegroundColor Green
} else {
    Write-Host "pre-commit hook file does not exist" -ForegroundColor Red
    Write-Host "Please run: .\setup-git-hooks.ps1" -ForegroundColor Yellow
} 
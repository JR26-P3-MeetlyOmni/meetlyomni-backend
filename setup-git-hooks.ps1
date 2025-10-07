# Git hooks setup script
Write-Host "Setting up Git hooks..." -ForegroundColor Cyan

# Check if we're in a Git repository
if (-not (Test-Path .git)) {
    Write-Host "Error: Not in a Git repository" -ForegroundColor Red
    exit 1
}

Write-Host "Setting up Git hooks..."

# Ensure .git/hooks directory exists
if (-not (Test-Path .git/hooks)) {
    try {
        New-Item -ItemType Directory -Path .git/hooks -Force | Out-Null
        Write-Host "Created .git/hooks directory" -ForegroundColor Green
    } catch {
        Write-Host "Failed to create .git/hooks directory: $_" -ForegroundColor Red
        exit 1
    }
}

# Create pre-commit hook content
$preCommitContent = @'
#!/bin/sh
echo "Running dotnet format..."
dotnet format MeetlyOmni.sln || exit 1

echo "Building solution..."
dotnet build MeetlyOmni.sln --no-restore || exit 1

echo "Running tests..."
dotnet test MeetlyOmni.sln --no-build || exit 1
'@

# Write pre-commit hook
try {
    $preCommitContent | Out-File -FilePath ".git/hooks/pre-commit" -Encoding ASCII
    Write-Host "Git hooks setup completed!" -ForegroundColor Green
    Write-Host "Pre-commit hook will now automatically run:" -ForegroundColor Yellow
    Write-Host "  - Code formatting (dotnet format)" -ForegroundColor White
    Write-Host "  - Build validation (dotnet build)" -ForegroundColor White
    Write-Host "  - Unit testing (dotnet test)" -ForegroundColor White
} catch {
    Write-Host "Failed to create hooks directory: $_" -ForegroundColor Red
    exit 1
} 
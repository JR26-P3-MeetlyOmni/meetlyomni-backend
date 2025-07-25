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

# 新增 pre-push hook 内容
$prePushContent = @'
#!/usr/bin/env pwsh
$ErrorActionPreference = "Stop"
$projectPath = "MeetlyOmni/MeetlyOmni.Tests"
$coverageDir = "coverage"
$minCoverage = 80

# 1. 运行当前分支测试并生成覆盖率
dotnet test $projectPath --collect:"XPlat Code Coverage" --results-directory $coverageDir | Out-Null
if (-not (Get-Command reportgenerator -ErrorAction SilentlyContinue)) {
  Write-Host "请先全局安装 reportgenerator: dotnet tool install -g dotnet-reportgenerator-globaltool"
  exit 1
}
reportgenerator -reports:"$coverageDir\*\coverage.cobertura.xml" -targetdir:$coverageDir -reporttypes:TextSummary | Out-File "$coverageDir\summary.txt"
$newCoverage = 0
if (Test-Path "$coverageDir\summary.txt") {
  $line = Select-String "Line coverage" "$coverageDir\summary.txt" | Select-Object -First 1
  if ($line) {
    $newCoverage = [float]($line.ToString().Split()[2].TrimEnd('%'))
  }
}

# 2. 获取主分支最新覆盖率
git fetch origin main
$baseDir = "$coverageDir/base"
if (Test-Path $baseDir) { Remove-Item $baseDir -Recurse -Force }
git worktree add $baseDir origin/main
try {
  dotnet test "$baseDir/../$projectPath" --collect:"XPlat Code Coverage" --results-directory $baseDir | Out-Null
  reportgenerator -reports:"$baseDir\*\coverage.cobertura.xml" -targetdir:$baseDir -reporttypes:TextSummary | Out-File "$baseDir\summary.txt"
  $baseCoverage = 0
  if (Test-Path "$baseDir\summary.txt") {
    $baseLine = Select-String "Line coverage" "$baseDir\summary.txt" | Select-Object -First 1
    if ($baseLine) {
      $baseCoverage = [float]($baseLine.ToString().Split()[2].TrimEnd('%'))
    }
  }
} finally {
  git worktree remove $baseDir --force
}

# 3. 检查覆盖率
if ($newCoverage -lt $minCoverage) {
  Write-Host "❌ 覆盖率 $newCoverage% 低于最低要求 $minCoverage%"
  Write-Host "详细报告：$coverageDir\index.htm"
  exit 1
}
if ($newCoverage -lt $baseCoverage) {
  Write-Host "❌ 覆盖率回退：主分支 $baseCoverage% → 当前 $newCoverage%"
  Write-Host "详细报告：$coverageDir\index.htm"
  exit 1
}
Write-Host "✅ 覆盖率检查通过：主分支 $baseCoverage% → 当前 $newCoverage%"
'@

$prePushPath = ".git/hooks/pre-push"
$prePushContent | Out-File -FilePath $prePushPath -Encoding ASCII
Write-Host "pre-push hook installed!" -ForegroundColor Green 
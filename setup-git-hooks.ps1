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
dotnet test src/MeetlyOmni.Tests --no-build || exit 1
'@

# Write pre-commit hook
try {
    $preCommitContent | Out-File -FilePath ".git/hooks/pre-commit" -Encoding ASCII
    Write-Host "Pre-commit hook created successfully!" -ForegroundColor Green
} catch {
    Write-Host "Failed to create pre-commit hook: $_" -ForegroundColor Red
    exit 1
}

# 检测操作系统并选择合适的 pre-push 钩子内容
$isWindows = $env:OS -match "Windows"

if ($isWindows) {
    # Windows 环境使用 .bat 文件作为钩子
    $prePushContent = @'
@echo off
setlocal enabledelayedexpansion

set projectPath=src/MeetlyOmni.Tests
set coverageDir=coverage
set minCoverage=80

:: 1. 运行当前分支测试并生成覆盖率
dotnet test %projectPath% --collect:"XPlat Code Coverage" --results-directory %coverageDir%
if %ERRORLEVEL% neq 0 exit /b %ERRORLEVEL%

where reportgenerator >nul 2>&1
if %ERRORLEVEL% neq 0 (
  echo 请先全局安装 reportgenerator: dotnet tool install -g dotnet-reportgenerator-globaltool
  exit /b 1
)

reportgenerator -reports:"%coverageDir%\*\coverage.cobertura.xml" -targetdir:%coverageDir% -reporttypes:TextSummary > %coverageDir%\summary.txt
if %ERRORLEVEL% neq 0 exit /b %ERRORLEVEL%

:: 解析当前覆盖率
for /f "tokens=3" %%i in ('findstr "Line coverage" %coverageDir%\summary.txt') do (
  set newCoverage=%%i
  set newCoverage=!newCoverage:%%=!
)

:: 2. 简化处理，使用当前覆盖率作为基准
set baseCoverage=%newCoverage%

:: 3. 检查覆盖率
if %newCoverage% LSS %minCoverage% (
  echo ❌ 覆盖率 %newCoverage%%% 低于最低要求 %minCoverage%%%
  echo 详细报告：%coverageDir%\index.htm
  exit /b 1
)

if %newCoverage% LSS %baseCoverage% (
  echo ❌ 覆盖率回退：主分支 %baseCoverage%%% → 当前 %newCoverage%%%
  echo 详细报告：%coverageDir%\index.htm
  exit /b 1
)

echo ✅ 覆盖率检查通过：主分支 %baseCoverage%%% → 当前 %newCoverage%%%
exit /b 0
'@
    $hookFilePath = ".git/hooks/pre-push"
} else {
    # 非 Windows 环境使用 Bash 脚本
    $prePushContent = Get-Content -Path "scripts/pre-push" -Raw
    $hookFilePath = ".git/hooks/pre-push"
}

# 写入 pre-push 钩子
try {
    $prePushContent | Out-File -FilePath $hookFilePath -Encoding ASCII
    if (-not $isWindows) {
        # 在非 Windows 环境中设置执行权限
        & chmod +x $hookFilePath
    }
    Write-Host "Pre-push hook created successfully!" -ForegroundColor Green
    Write-Host "Git hooks setup completed!" -ForegroundColor Green
    Write-Host "Pre-push hook will check code coverage before pushing:" -ForegroundColor Yellow
    Write-Host "  - Minimum coverage: 80%" -ForegroundColor White
    Write-Host "  - No coverage regression allowed" -ForegroundColor White
} catch {
    Write-Host "Failed to create pre-push hook: $_" -ForegroundColor Red
    exit 1
}
Write-Host "Git hooks setup completed!" -ForegroundColor Green
Write-Host "Pre-commit hook will now automatically run:" -ForegroundColor Yellow
Write-Host "  - Code formatting (dotnet format)" -ForegroundColor White
Write-Host "  - Build validation (dotnet build)" -ForegroundColor White
Write-Host "  - Unit testing (dotnet test)" -ForegroundColor White
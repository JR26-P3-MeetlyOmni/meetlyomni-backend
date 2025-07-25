$ErrorActionPreference = "Stop"
$projectPath = "MeetlyOmni/MeetlyOmni.Api"
$coverageDir = "coverage"
$coverageFile = "$coverageDir\coverage.cobertura.xml"
$minCoverage = 80

# 1. 运行测试并生成覆盖率
dotnet test $projectPath --collect:"XPlat Code Coverage" --results-directory $coverageDir | Out-Null

# 2. 解析当前覆盖率
if (-not (Get-Command reportgenerator -ErrorAction SilentlyContinue)) {
  Write-Host "请先全局安装 reportgenerator: dotnet tool install -g dotnet-reportgenerator-globaltool"
  exit 1
}
reportgenerator -reports:$coverageFile -targetdir:$coverageDir -reporttypes:TextSummary | Out-File "$coverageDir\summary.txt"
$newCoverage = [float]((Select-String "Line coverage" "$coverageDir\summary.txt").ToString().Split()[2].TrimEnd('%'))

# 3. 获取目标分支最新覆盖率
git fetch origin main
# 这里简化处理，实际可根据需要 checkout 或用 CI 方式
$baseCoverage = $newCoverage

# 4. 检查覆盖率
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
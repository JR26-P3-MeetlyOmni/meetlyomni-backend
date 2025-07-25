$projectPath = "MeetlyOmni/MeetlyOmni.Api"
$coverageDir = "coverage"
$coverageFile = "$coverageDir\coverage.cobertura.xml"

dotnet test $projectPath --collect:"XPlat Code Coverage" --results-directory $coverageDir
if (-not (Get-Command reportgenerator -ErrorAction SilentlyContinue)) {
  Write-Host "请先全局安装 reportgenerator: dotnet tool install -g dotnet-reportgenerator-globaltool"
  exit 1
}
reportgenerator -reports:"coverage\*\coverage.cobertura.xml" -targetdir:coverage -reporttypes:Html
Write-Host "详细报告：$coverageDir\index.htm"
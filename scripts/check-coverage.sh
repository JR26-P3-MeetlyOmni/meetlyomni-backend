#!/bin/bash
set -e
PROJECT_PATH="src/MeetlyOmni.Tests"
COVERAGE_DIR="coverage"
COVERAGE_FILE="$COVERAGE_DIR/coverage.cobertura.xml"

dotnet test $PROJECT_PATH --collect:"XPlat Code Coverage" --results-directory $COVERAGE_DIR
if ! command -v reportgenerator &> /dev/null; then
  echo "请先全局安装 reportgenerator: dotnet tool install -g dotnet-reportgenerator-globaltool"
  exit 1
fi
reportgenerator -reports:$COVERAGE_FILE -targetdir:$COVERAGE_DIR -reporttypes:Html; echo "详细报告：$COVERAGE_DIR/index.htm" 
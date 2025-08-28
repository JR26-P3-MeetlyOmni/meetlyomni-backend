pipeline {
  agent any
  stages {
    stage('verify') {
      steps {
        sh 'echo Jenkinsfile detected on $(uname -m) && dotnet --info | head -n 5 || true'
      }
    }
  }
}
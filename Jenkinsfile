pipeline {
  agent any

  options {
    timestamps()
    ansiColor('xterm')
  }

  environment {
    AWS_REGION      = 'us-east-1'                 // TODO: 替换你的区域
    AWS_ACCOUNT_ID  = '951546173303'              // TODO: 替换你的账号ID
    ECR_REPO        = 'meetlyomni-api'            // TODO: 确保ECR中已创建
    APP_NAME        = 'meetlyomni-api'
    IMAGE_TAG       = "${env.BRANCH_NAME}-${env.BUILD_NUMBER}"
    ECR_URI         = "${env.AWS_ACCOUNT_ID}.dkr.ecr.${env.AWS_REGION}.amazonaws.com/${env.ECR_REPO}"
    PUBLISH_DIR     = 'publish'
  }

  stages {
    stage('Checkout') {
      steps {
        checkout scm
        sh 'git --version'
      }
    }

    stage('Dotnet Restore') {
      steps {
        sh 'dotnet restore'
      }
    }

    stage('Build') {
      steps {
        sh 'dotnet build -c Release --no-restore'
      }
    }

    stage('Test') {
      steps {
        sh 'dotnet test --configuration Release --no-build --verbosity normal'
      }
    }

    stage('Publish') {
      when { not { changeRequest() } } // 仅分支构建执行发布、打包与部署, 试试
      steps {
        sh 'rm -rf ${PUBLISH_DIR}'
        sh 'dotnet publish src/MeetlyOmni.Api/MeetlyOmni.Api.csproj -c Release -o ${PUBLISH_DIR} /p:UseAppHost=false'
        sh 'ls -lah ${PUBLISH_DIR} | head -n 20'
      }
    }

    stage('Docker Build & Login') {
      when { not { changeRequest() } }
      steps {
        sh '''
          aws --version
          aws ecr get-login-password --region ${AWS_REGION} \
            | docker login --username AWS --password-stdin ${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com
          docker build -f src/MeetlyOmni.Api/Dockerfile.runtime -t ${ECR_REPO}:${IMAGE_TAG} .
          docker tag ${ECR_REPO}:${IMAGE_TAG} ${ECR_URI}:${IMAGE_TAG}
          docker tag ${ECR_REPO}:${IMAGE_TAG} ${ECR_URI}:${BRANCH_NAME}-latest
        '''
      }
    }

    stage('Docker Push') {
      when { not { changeRequest() } }
      steps {
        sh '''
          docker push ${ECR_URI}:${IMAGE_TAG}
          docker push ${ECR_URI}:${BRANCH_NAME}-latest
        '''
      }
    }

    stage('Deploy to ECS') {
      when { not { changeRequest() } }
      steps {
        script {
          // 分支到环境映射
          String envName = (env.BRANCH_NAME == 'dev') ? 'Staging' : ((env.BRANCH_NAME == 'devops/scarlett') ? 'Production' : '')
          if (!envName) {
            echo "Branch ${env.BRANCH_NAME} not mapped to an environment. Skipping deploy."
            return
          }

          String cluster = "meetlyomni-${envName}-cluster"
          String service = "meetlyomni-${envName}-service"

          sh """
            aws ecs update-service \
              --cluster ${cluster} \
              --service ${service} \
              --force-new-deployment \
              --region ${AWS_REGION}
          """
        }
      }
    }
  }

  post {
    success {
      echo "Build OK. Image: ${ECR_URI}:${IMAGE_TAG}"
    }
    failure {
      echo "Build FAILED for ${env.BRANCH_NAME}"
    }
    always {
      sh 'docker image ls | head -n 20 || true'
    }
  }
}
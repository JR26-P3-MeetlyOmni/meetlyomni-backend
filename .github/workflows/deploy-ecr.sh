#!/bin/bash
set -e

# -------- 配置部分 --------
AWS_REGION="ap-southeast-2"       
REPO_NAME="meetlyomni-backend"    
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
IMAGE_TAG="latest"

# -------- 创建 ECR 仓库 (如果已存在会报错，可忽略) --------
echo ">>> Creating ECR repo: $REPO_NAME ..."
aws ecr create-repository \
  --repository-name $REPO_NAME \
  --region $AWS_REGION || echo "Repo already exists, skip."

# -------- 登录 ECR --------
echo ">>> Logging in to ECR ..."
aws ecr get-login-password --region $AWS_REGION \
  | docker login --username AWS --password-stdin ${ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com

# -------- 使用 buildx 构建镜像 --------
echo ">>> Building docker image ..."
docker buildx build \
  --platform linux/amd64 \
  -t ${ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/${REPO_NAME}:${IMAGE_TAG} \
  ./src/MeetlyOmni.Api

# -------- 推送镜像到 ECR --------
echo ">>> Pushing image to ECR ..."
docker push ${ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/${REPO_NAME}:${IMAGE_TAG}

echo ">>> Done! Image pushed to:"
echo "${ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/${REPO_NAME}:${IMAGE_TAG}"
#!/bin/bash
set -e


AWS_REGION="ap-southeast-2"       
REPO_NAME="meetlyomni-backend"    
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
IMAGE_TAG="latest"


echo ">>> Creating ECR repo: $REPO_NAME ..."
aws ecr create-repository \
  --repository-name $REPO_NAME \
  --region $AWS_REGION || echo "Repo already exists, skip."


echo ">>> Logging in to ECR ..."
aws ecr get-login-password --region $AWS_REGION \
  | docker login --username AWS --password-stdin ${ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com


echo ">>> Building docker image ..."
docker buildx build \
  --platform linux/amd64 \
  -t ${ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/${REPO_NAME}:${IMAGE_TAG} \
  ./src/MeetlyOmni.Api


echo ">>> Pushing image to ECR ..."
docker push ${ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/${REPO_NAME}:${IMAGE_TAG}

echo ">>> Done! Image pushed to:"
echo "${ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/${REPO_NAME}:${IMAGE_TAG}"
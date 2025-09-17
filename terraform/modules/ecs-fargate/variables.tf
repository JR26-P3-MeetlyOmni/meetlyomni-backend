variable "ecs_cluster_id" {
  description = "ECS Cluster ID"
  type = string 
}

variable "security_group_alb_id" {
  description = "ALB Security Group ID from VPC module"
  type = string
}

variable "project" {
  description = "Project name"
  type = string
  default = "meetlyomni"
}

variable "environment" {
  description = "Application environment"
  type = string
  default = "uat"
}

variable "region" {
  description = "AWS region"
  type = string
  default = "ap-southeast-2" 
  
}

variable "vpc_id" {
  description = "VPC ID where ECS Fargate service will be deployed"
  type = string   
}

variable "private_subnet_ids" {
  description = "List of private subnet IDs"
  type = list(string) 
}

variable "public_subnet_ids" {
  description = "List of public subnet IDs from VPC module"
  type = list(string) 
}

variable "ecs_security_group_id" {
    description = "ECS Security Group ID"
    type = string
}

variable "container_image" {
    description = "Container image for the ECS task"
    type = string   
    default = "351889159066.dkr.ecr.ap-southeast-2.amazonaws.com/meetly-omni-backend-dev:latest"
}

variable "ecs_task_execution_role_arn" {
    description = "ECS Task Definition ARN"
    type = string   
    default = "arn:aws:iam::351889159066:role/meetly-omni-backend-ecs-task-execution"
  
}

variable "connection_string" {
    description = "Database connection string"
    type = string   
    default = "arn:aws:ssm:ap-southeast-2:351889159066:parameter/ConnectionStrings__MeetlyOmniDb"
}
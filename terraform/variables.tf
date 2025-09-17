variable "module" {
    description = "Module name"
    type = string
    default = "meetlyomni" 
}

variable "container_image" {
  description = "Container image for the ECS task"
  type = string   
  default = "351889159066.dkr.ecr.ap-southeast-2.amazonaws.com/meetly-omni-backend-dev:latest"
}

variable "ecs_task_execution_role_arn" {
  description = "ECS Task Execution Role ARN"
  type = string   
  default = "arn:aws:iam::351889159066:role/meetly-omni-backend-ecs-task-execution"
}

variable "connection_string" {
  description = "Database connection string"
  type = string   
  default = "arn:aws:ssm:ap-southeast-2:351889159066:parameter/ConnectionStrings__MeetlyOmniDb"
}

variable "vpc_cidr_block" {
  type        = string
  default     = "10.0.0.0/16"
  description = "CIDR block range for vpc"
}

variable "region" {
  description = "AWS region"
  type = string
  default = "ap-southeast-2"         
}

variable "project" {
  description = "Project name"
  type = string
  default = "meetlyomni" 
}

variable "platform" {
  description = "Platform name"
  type = string
  default = "uat"
}

variable "environment" {
  description = "Applicaiton environment"
  type = string
  default = "uat"
}

variable "aws_availability_zones" {
  description = "List of AWS availability zones"
  type = list(string)
  default = ["ap-southeast-2a", "ap-southeast-2b"] 
}

variable "max_capacity" {
  description = "The maximum capacity for the ECS service."
  type        = number  
  default     = 3   
  
}

variable "min_capacity" {
  description = "The minimum capacity for the ECS service."
  type        = number  
  default     = 1   
  
}


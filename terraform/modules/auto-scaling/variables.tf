variable "ecs_service_name" {
  description = "ECS Service Name"
  type        = string 
  default     = "meetlyomni-uat-fargate-service"
}

variable "ecs_cluster_name" {
  description = "ECS Cluster Name"
  type        = string
  default     = "meetlyomni-ecs-cluster-uat"
}

variable "project" {
  description = "Project name"
  type        = string
  default     = "meetlyomni"
  
}

variable "environment" {
  description = "Application environment"
  type        = string
  default     = "uat"
  
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

variable "region" {
  description = "AWS region for deployment"
  type        = string
  default     = "ap-southeast-2"
}

variable "db_name" {
  description = "Database name for RDS"
  type        = string
  default     = "meetlyomni"
}

variable "db_username" {
  description = "Master username for RDS"
  type        = string
  default     = "postgres"
}

variable "db_password" {
  description = "Master password for RDS"
  type        = string
  sensitive   = true
}

variable "db_instance_class" {
  description = "RDS instance type"
  type        = string
  default     = "db.t3.micro"
}

variable "db_allocated_storage" {
  description = "RDS storage size in GB"
  type        = number
  default     = 20
}
variable "name" {
  description = "Base name for all resources"
  type        = string
  default     = "meetlyomni"

}

variable "health_check_path" {
  description = "ALB health check path"
  type        = string
  default     = "/health"

}
variable "ecr_image_uri" {
  description = "ECR image URI for the backend application"
  type        = string
  default     = "034362033405.dkr.ecr.ap-southeast-2.amazonaws.com/meetlyomni-backend:latest"
}
variable "db_engine_version" {
  description = "PostgreSQL engine version for RDS"
  type        = string
  default     = "15.5"
}

variable "multi_az" {
  description = "Whether to enable Multi-AZ deployment for RDS"
  type        = bool
  default     = false
}

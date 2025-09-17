variable "vpc_cidr_block" {
  type        = string
  default     = "10.0.0.0/16"
  description = "CIDR block range for vpc"
}

variable "environment" {
  description = "Applicaiton environment"
  type = string
  default = "uat"
}

variable "vpc_tag_name" {
  description = "Tag name for the VPC"
  type = string
  default = "meetlyomni-vpc"  
  
}

variable "number_of_private_subnets" {
  description = "Number of private subnets to create"
  type = number
  default = 2   
}

variable "security_group_alb_name" { 
  description = "Security group name for ALB"
  type = string
  default = "meetlyomni-alb-uat-sg"
}

variable "region" {
  description = "AWS region"
  type = string
  default = "ap-southeast-2" 
  
}

variable "aws_availability_zones" {
  description = "List of AWS availability zones"
  type = list(string)
  default = ["ap-southeast-2a", "ap-southeast-2b"]
}
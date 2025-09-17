variable "ecs_cluster_name" {
  description = "ECS Cluster Name"
  type = string
  default = "meetlyomni-uat-cluster"
  
}

variable "cluster_tag_name" {
  description = "Tag name for the ECS Cluster"
  type = string
  default = "meetlyomni-ecs-cluster"
}
resource "aws_ecs_cluster" "meetlyomni-ecs-cluster" {
  name = var.ecs_cluster_name 

  tags = {
    Name = var.cluster_tag_name
  }

  setting {
    name  = "containerInsights"
    value = "enabled"
  }
}

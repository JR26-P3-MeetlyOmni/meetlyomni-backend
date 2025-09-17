module "vpc" {
  source = "./modules/vpc"
  vpc_cidr_block = var.vpc_cidr_block
  environment = var.environment
  vpc_tag_name = "${var.project}-${var.platform}-vpc"
  number_of_private_subnets = 2
  security_group_alb_name = "${var.project}-${var.platform}-alb-sg"
  aws_availability_zones = var.aws_availability_zones
  region = var.region
}

# ECS cluster
module "ecs_cluster" {
  source = "./modules/ecs-cluster"
  ecs_cluster_name = "${var.project}-ecs-cluster-${var.environment}"
  cluster_tag_name = "${var.project}-ecs-cluster-${var.environment}"
}

# ECS task definition and service on Fargate
module "ecs_fargate" {
  source = "./modules/ecs-fargate"
  ecs_cluster_id = module.ecs_cluster.id
  vpc_id = module.vpc.vpc_id
  private_subnet_ids = module.vpc.private_subnet_ids
  public_subnet_ids = module.vpc.public_subnet_ids
  ecs_security_group_id = module.vpc.ecs_tasks_sg_id
  container_image = var.container_image
  ecs_task_execution_role_arn = var.ecs_task_execution_role_arn
  
  connection_string = var.connection_string
  project = var.project
  environment = var.environment
  security_group_alb_id = module.vpc.security_group_alb_id
}

# Auto Scaling for ECS service
module "auto_scaling" {
  source = "./modules/auto-scaling"
  max_capacity = var.max_capacity
  min_capacity = var.min_capacity
  ecs_service_name = module.ecs_fargate.ecs_service_name
  project = var.project
  environment = var.environment
} 

#module "aws_route53" {
#  source = "./modules/route53"
#  hosted_zone_id = "Z071432363GBS33VG2WE"
#  alb_dns_name = module.ecs_fargate.alb_dns_name
#  alb_zone_id = module.ecs_fargate.alb_zone_id
#  
#}

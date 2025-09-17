resource "aws_ecs_service" "meetlyomni-fargate-service" {
  name            = "${var.project}-${var.environment}-fargate-service"
  cluster         = var.ecs_cluster_id
  task_definition = aws_ecs_task_definition.meetlyomni-fargate-task.arn
  desired_count   = 2
  launch_type     = "FARGATE"

  network_configuration {
    subnets         = var.private_subnet_ids
    security_groups = [var.ecs_security_group_id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.meetlyomni-target-group.arn
    container_name   = "meetlyomni-container"
    container_port   = 8080
  }

  depends_on = [aws_ecs_task_definition.meetlyomni-fargate-task]

  tags = {
    Name = "${var.project}-${var.environment}-fargate-service"
   }


}

resource "aws_cloudwatch_log_group" "meetlyomni-log-group" {
  name              = "/ecs/${var.project}-${var.environment}"
  retention_in_days = 7
}

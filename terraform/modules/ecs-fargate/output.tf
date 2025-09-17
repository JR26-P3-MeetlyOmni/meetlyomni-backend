output "ecs_task_arn" {
    value = aws_ecs_task_definition.meetlyomni-fargate-task.arn
}

output "ecs_service_name" {
    value = aws_ecs_service.meetlyomni-fargate-service.name
}

output "alb_zone_id" {
    value = aws_lb.meetlyomni-alb.zone_id
}

output "alb_dns_record" {
    value = aws_lb.meetlyomni-alb.dns_name
}

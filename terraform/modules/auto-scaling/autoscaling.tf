resource "aws_appautoscaling_target" "meetlyomni-autoscaling-target" {
  max_capacity       = var.max_capacity
  min_capacity       = var.min_capacity
  resource_id        = "service/${var.ecs_cluster_name}/${var.ecs_service_name}"
  scalable_dimension = "ecs:service:DesiredCount"
  service_namespace  = "ecs"
  
}

resource "aws_appautoscaling_policy" "meetlyomni-cpu-autoscaling-policy" {
  
  name               = "meetlyomni-cpu-autoscaling-policy"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.meetlyomni-autoscaling-target.resource_id
  scalable_dimension = aws_appautoscaling_target.meetlyomni-autoscaling-target.scalable_dimension
  service_namespace  = aws_appautoscaling_target.meetlyomni-autoscaling-target.service_namespace

  target_tracking_scaling_policy_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageCPUUtilization"
    }
    target_value       = 30.0
    scale_in_cooldown  = 300
    scale_out_cooldown = 300
  }

}

resource "aws_appautoscaling_policy" "meetlyomni-memory-autoscaling-policy" {
  
  name               = "meetlyomni-memory-autoscaling-policy"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.meetlyomni-autoscaling-target.resource_id
  scalable_dimension = aws_appautoscaling_target.meetlyomni-autoscaling-target.scalable_dimension
  service_namespace  = aws_appautoscaling_target.meetlyomni-autoscaling-target.service_namespace

  target_tracking_scaling_policy_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageMemoryUtilization"
    }
    target_value       = 30.0
    scale_in_cooldown  = 300
    scale_out_cooldown = 300
  }

}

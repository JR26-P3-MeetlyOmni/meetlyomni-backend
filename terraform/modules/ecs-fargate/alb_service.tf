resource "aws_lb" "meetlyomni-alb" {
  name               = "${var.project}-${var.environment}-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [var.security_group_alb_id]
  subnets            = var.public_subnet_ids

  enable_deletion_protection = false

  tags = {
    Name = "${var.project}-${var.environment}-alb"
  }
  
}

output "public_subnets" {
  value = ["subnet-12345678", "subnet-87654321"]
}


output "alb_arn" {
  value = aws_lb.meetlyomni-alb.arn
}

output "alb_dns_name" {
  value = aws_lb.meetlyomni-alb.dns_name
}

resource "aws_lb_target_group" "meetlyomni-target-group" {
  name        = "${var.project}-${var.environment}-target-group"
  port        = 8080
  protocol    = "HTTP"
  vpc_id      = var.vpc_id
  target_type = "ip"

  health_check {
    path                = "/health"
    interval            = 30
    timeout             = 5
    healthy_threshold   = 5
    unhealthy_threshold = 2
    matcher             = "200-399"
  }

  lifecycle {
    prevent_destroy = true
  }

  tags = {
    Name = "${var.project}-${var.environment}-target-group"
  }
  
}

resource "aws_lb_listener" "meetlyomni-listener" {
  load_balancer_arn = aws_lb.meetlyomni-alb.arn
  port              = "8080"
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.meetlyomni-target-group.arn
  }
}

resource "aws_lb_listener" "meetlyomni-listener-https" {
  load_balancer_arn = aws_lb.meetlyomni-alb.arn
  port              = "443"
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-2016-08" 
  certificate_arn   = "arn:aws:acm:ap-southeast-2:351889159066:certificate/d0529416-31fc-4cc6-b304-78c4bb5d40d6"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.meetlyomni-target-group.arn
  }
}

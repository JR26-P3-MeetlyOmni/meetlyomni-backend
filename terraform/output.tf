output "alb_dns_name" {
  value       = aws_lb.this.dns_name
  description = "Access your API via http://<alb_dns_name>"
}


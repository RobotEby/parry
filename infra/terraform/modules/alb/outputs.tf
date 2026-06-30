output "alb_dns_name" {
  description = "ALB DNS name."
  value       = aws_lb.this.dns_name
}

output "alb_arn" {
  description = "ALB ARN."
  value       = aws_lb.this.arn
}

output "load_balancer_arn_suffix" {
  description = "ALB ARN suffix used by CloudWatch metrics."
  value       = aws_lb.this.arn_suffix
}

output "target_group_arn" {
  description = "Target group ARN."
  value       = aws_lb_target_group.this.arn
}

output "target_group_arn_suffix" {
  description = "Target group ARN suffix used by CloudWatch metrics."
  value       = aws_lb_target_group.this.arn_suffix
}

output "listener_arns" {
  description = "Listener ARNs."
  value       = compact(concat([aws_lb_listener.http.arn], aws_lb_listener.https[*].arn))
}

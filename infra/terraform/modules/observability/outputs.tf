output "log_group_name" {
  description = "ECS CloudWatch log group name."
  value       = aws_cloudwatch_log_group.ecs.name
}

output "log_group_arn" {
  description = "ECS CloudWatch log group ARN."
  value       = aws_cloudwatch_log_group.ecs.arn
}

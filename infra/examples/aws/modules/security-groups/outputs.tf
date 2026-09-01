output "alb_security_group_id" {
  description = "ALB security group id."
  value       = aws_security_group.alb.id
}

output "ecs_security_group_id" {
  description = "ECS security group id."
  value       = aws_security_group.ecs.id
}

output "redis_security_group_id" {
  description = "Redis security group id."
  value       = aws_security_group.redis.id
}

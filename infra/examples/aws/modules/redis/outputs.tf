output "primary_endpoint_address" {
  description = "Redis primary endpoint address."
  value       = aws_elasticache_replication_group.this.primary_endpoint_address
}

output "reader_endpoint_address" {
  description = "Redis reader endpoint address."
  value       = aws_elasticache_replication_group.this.reader_endpoint_address
}

output "replication_group_id" {
  description = "Redis replication group id."
  value       = aws_elasticache_replication_group.this.id
}

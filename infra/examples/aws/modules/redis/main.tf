locals {
  auth_enabled = var.auth_token != null && var.auth_token != ""
}

resource "aws_elasticache_subnet_group" "this" {
  name       = "${var.name_prefix}-redis-subnets"
  subnet_ids = var.private_subnet_ids

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-redis-subnets"
  })
}

resource "aws_elasticache_replication_group" "this" {
  replication_group_id = substr("${var.name_prefix}-redis", 0, 40)
  description          = "Redis store for Parry distributed application-layer controls"

  engine               = "redis"
  engine_version       = "7.1"
  node_type            = var.node_type
  port                 = 6379
  num_cache_clusters   = var.num_cache_clusters
  parameter_group_name = "default.redis7"

  subnet_group_name  = aws_elasticache_subnet_group.this.name
  security_group_ids = [var.redis_security_group_id]

  at_rest_encryption_enabled = true
  transit_encryption_enabled = true
  auth_token                 = local.auth_enabled ? var.auth_token : null

  automatic_failover_enabled = var.num_cache_clusters > 1
  multi_az_enabled           = var.num_cache_clusters > 1
  snapshot_retention_limit   = var.snapshot_retention_limit

  apply_immediately = true

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-redis"
  })
}

locals {
  name_prefix = "${var.project_name}-${var.environment}"

  common_tags = merge(var.tags, {
    Project     = var.project_name
    Environment = var.environment
    ManagedBy   = "terraform"
    Component   = "parry"
  })
}

module "network" {
  source = "./modules/network"

  name_prefix = local.name_prefix
  vpc_cidr    = "10.42.0.0/16"
  public_subnet_cidrs = [
    "10.42.0.0/24",
    "10.42.1.0/24"
  ]
  private_subnet_cidrs = [
    "10.42.10.0/24",
    "10.42.11.0/24"
  ]
  enable_nat_gateway = var.enable_nat_gateway
  tags               = local.common_tags
}

module "security_groups" {
  source = "./modules/security-groups"

  name_prefix  = local.name_prefix
  vpc_id       = module.network.vpc_id
  vpc_cidr     = module.network.vpc_cidr
  app_port     = var.app_port
  enable_https = var.enable_https
  tags         = local.common_tags
}

module "ecr" {
  source = "./modules/ecr"

  name_prefix = local.name_prefix
  tags        = local.common_tags
}

module "observability" {
  source = "./modules/observability"

  name_prefix        = local.name_prefix
  log_retention_days = 14
  enable_alarms      = false
  sns_topic_arn      = ""
  tags               = local.common_tags
}

module "alb" {
  source = "./modules/alb"

  name_prefix           = local.name_prefix
  vpc_id                = module.network.vpc_id
  public_subnet_ids     = module.network.public_subnet_ids
  alb_security_group_id = module.security_groups.alb_security_group_id
  app_port              = var.app_port
  enable_https          = var.enable_https
  acm_certificate_arn   = var.acm_certificate_arn
  health_check_path     = "/health"
  tags                  = local.common_tags
}

module "redis" {
  source = "./modules/redis"

  name_prefix              = local.name_prefix
  private_subnet_ids       = module.network.private_subnet_ids
  redis_security_group_id  = module.security_groups.redis_security_group_id
  node_type                = var.redis_node_type
  num_cache_clusters       = var.redis_num_cache_clusters
  auth_token               = var.redis_auth_token
  snapshot_retention_limit = 1
  tags                     = local.common_tags
}

module "ecs" {
  source = "./modules/ecs"

  name_prefix                  = local.name_prefix
  aws_region                   = var.aws_region
  container_image              = var.container_image
  app_port                     = var.app_port
  desired_count                = var.desired_count
  cpu                          = var.cpu
  memory                       = var.memory
  private_subnet_ids           = module.network.private_subnet_ids
  ecs_security_group_id        = module.security_groups.ecs_security_group_id
  target_group_arn             = module.alb.target_group_arn
  cloudwatch_log_group_name    = module.observability.log_group_name
  redis_endpoint               = module.redis.primary_endpoint_address
  parry_admin_token_secret_arn = var.parry_admin_token_secret_arn
  redis_auth_token_secret_arn  = var.redis_auth_token_secret_arn
  tags                         = local.common_tags

  depends_on = [module.alb]
}

module "waf" {
  source = "./modules/waf"
  count  = var.enable_cloudfront ? 1 : 0

  providers = {
    aws = aws.us_east_1
  }

  name_prefix       = local.name_prefix
  enable_count_mode = var.enable_waf_count_mode
  rate_limit        = var.waf_rate_limit
  tags              = local.common_tags
}

module "cloudfront" {
  source = "./modules/cloudfront"
  count  = var.enable_cloudfront ? 1 : 0

  providers = {
    aws = aws.us_east_1
  }

  name_prefix            = local.name_prefix
  origin_domain_name     = module.alb.alb_dns_name
  web_acl_arn            = var.enable_cloudfront ? module.waf[0].web_acl_arn : ""
  domain_name            = var.domain_name
  acm_certificate_arn    = var.acm_certificate_arn
  origin_protocol_policy = var.enable_https ? "https-only" : "http-only"
  tags                   = local.common_tags
}

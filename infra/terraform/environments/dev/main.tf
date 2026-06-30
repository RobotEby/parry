module "parry" {
  source = "../.."

  providers = {
    aws           = aws
    aws.us_east_1 = aws.us_east_1
  }

  project_name                 = var.project_name
  environment                  = var.environment
  aws_region                   = var.aws_region
  container_image              = var.container_image
  app_port                     = var.app_port
  desired_count                = var.desired_count
  cpu                          = var.cpu
  memory                       = var.memory
  enable_nat_gateway           = var.enable_nat_gateway
  enable_vpc_endpoints         = var.enable_vpc_endpoints
  enable_cloudfront            = var.enable_cloudfront
  enable_https                 = var.enable_https
  acm_certificate_arn          = var.acm_certificate_arn
  domain_name                  = var.domain_name
  redis_node_type              = var.redis_node_type
  redis_num_cache_clusters     = var.redis_num_cache_clusters
  redis_auth_token_secret_arn  = var.redis_auth_token_secret_arn
  redis_auth_token             = var.redis_auth_token
  parry_admin_token_secret_arn = var.parry_admin_token_secret_arn
  enable_waf_count_mode        = var.enable_waf_count_mode
  waf_rate_limit               = var.waf_rate_limit
  allowed_admin_cidr           = var.allowed_admin_cidr
  tags                         = var.tags
}

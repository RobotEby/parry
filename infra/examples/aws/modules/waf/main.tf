locals {
  managed_rule_groups = [
    "AWSManagedRulesCommonRuleSet",
    "AWSManagedRulesKnownBadInputsRuleSet",
    "AWSManagedRulesSQLiRuleSet",
    "AWSManagedRulesAmazonIpReputationList"
  ]
}

resource "aws_wafv2_web_acl" "this" {
  name        = "${var.name_prefix}-cloudfront-waf"
  description = "CloudFront WAF for Parry demo API edge protection"
  scope       = "CLOUDFRONT"

  default_action {
    allow {}
  }

  dynamic "rule" {
    for_each = local.managed_rule_groups
    content {
      name     = rule.value
      priority = index(local.managed_rule_groups, rule.value) + 1

      override_action {
        dynamic "count" {
          for_each = var.enable_count_mode ? [1] : []
          content {}
        }

        dynamic "none" {
          for_each = var.enable_count_mode ? [] : [1]
          content {}
        }
      }

      statement {
        managed_rule_group_statement {
          name        = rule.value
          vendor_name = "AWS"
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "${var.name_prefix}-${rule.value}"
        sampled_requests_enabled   = true
      }
    }
  }

  rule {
    name     = "GlobalRateLimit"
    priority = 100

    action {
      dynamic "count" {
        for_each = var.enable_count_mode ? [1] : []
        content {}
      }

      dynamic "block" {
        for_each = var.enable_count_mode ? [] : [1]
        content {}
      }
    }

    statement {
      rate_based_statement {
        aggregate_key_type = "IP"
        limit              = var.rate_limit
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.name_prefix}-global-rate-limit"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "AuthPathRateLimit"
    priority = 101

    action {
      dynamic "count" {
        for_each = var.enable_count_mode ? [1] : []
        content {}
      }

      dynamic "block" {
        for_each = var.enable_count_mode ? [] : [1]
        content {}
      }
    }

    statement {
      rate_based_statement {
        aggregate_key_type = "IP"
        limit              = var.auth_rate_limit

        scope_down_statement {
          or_statement {
            statement {
              byte_match_statement {
                positional_constraint = "EXACTLY"
                search_string         = "/login"

                field_to_match {
                  uri_path {}
                }

                text_transformation {
                  priority = 0
                  type     = "NONE"
                }
              }
            }

            statement {
              byte_match_statement {
                positional_constraint = "EXACTLY"
                search_string         = "/signin"

                field_to_match {
                  uri_path {}
                }

                text_transformation {
                  priority = 0
                  type     = "NONE"
                }
              }
            }

            statement {
              byte_match_statement {
                positional_constraint = "STARTS_WITH"
                search_string         = "/auth/"

                field_to_match {
                  uri_path {}
                }

                text_transformation {
                  priority = 0
                  type     = "NONE"
                }
              }
            }

            statement {
              byte_match_statement {
                positional_constraint = "STARTS_WITH"
                search_string         = "/api/auth/"

                field_to_match {
                  uri_path {}
                }

                text_transformation {
                  priority = 0
                  type     = "NONE"
                }
              }
            }

            statement {
              byte_match_statement {
                positional_constraint = "EXACTLY"
                search_string         = "/forgot-password"

                field_to_match {
                  uri_path {}
                }

                text_transformation {
                  priority = 0
                  type     = "NONE"
                }
              }
            }

            statement {
              byte_match_statement {
                positional_constraint = "EXACTLY"
                search_string         = "/reset-password"

                field_to_match {
                  uri_path {}
                }

                text_transformation {
                  priority = 0
                  type     = "NONE"
                }
              }
            }
          }
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.name_prefix}-auth-path-rate-limit"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${var.name_prefix}-cloudfront-waf"
    sampled_requests_enabled   = true
  }

  tags = var.tags
}

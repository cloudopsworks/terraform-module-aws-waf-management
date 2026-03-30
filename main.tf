##
# (c) 2021-2026
#     Cloud Ops Works LLC - https://cloudops.works/
#     Find us on:
#       GitHub: https://github.com/cloudopsworks
#       WebSite: https://cloudops.works
#     Distributed Under Apache v2.0 License
#

##
# WAFv2 IP Sets
# One resource per entry in settings.ip_sets.
# Use ref:<name> in ip_set_reference.arn rules to link these resources dynamically.
##
resource "aws_wafv2_ip_set" "this" {
  for_each = { for s in local.ip_sets : s.name => s }

  name               = format("%s-%s", local.waf_name, each.value.name)
  scope              = local.waf_scope
  description        = try(each.value.description, null)
  ip_address_version = each.value.ip_address_version
  addresses          = try(each.value.addresses, [])

  tags = local.all_tags
}

##
# WAFv2 Regex Pattern Sets
# One resource per entry in settings.regex_pattern_sets.
# Use ref:<name> in regex_pattern_set_reference.arn rules to link these resources dynamically.
##
resource "aws_wafv2_regex_pattern_set" "this" {
  for_each = { for s in local.regex_pattern_sets : s.name => s }

  name        = format("%s-%s", local.waf_name, each.value.name)
  scope       = local.waf_scope
  description = try(each.value.description, null)

  dynamic "regular_expression" {
    for_each = try(each.value.patterns, [])
    content {
      regex_string = regular_expression.value
    }
  }

  tags = local.all_tags
}

##
# WAFv2 API Keys (mobile SDK token domain integration)
# One resource per entry in settings.api_keys.
##
resource "aws_wafv2_api_key" "this" {
  for_each = { for k in local.api_keys : k.name => k }

  scope         = local.waf_scope
  token_domains = each.value.token_domains
}

##
# Custom WAFv2 Rule Groups
# One resource per entry in settings.rule_groups.
# Rules within each group support ref:<name> in ip_set_reference and
# regex_pattern_set_reference ARNs to reference module-managed resources.
##
resource "aws_wafv2_rule_group" "this" {
  for_each = { for rg in local.custom_rule_groups : rg.name => rg }

  name        = format("%s-%s", local.waf_name, each.value.name)
  scope       = local.waf_scope
  capacity    = each.value.capacity
  description = try(each.value.description, null)

  dynamic "rule" {
    for_each = try(each.value.rules, [])

    content {
      name     = rule.value.name
      priority = rule.value.priority

      action {
        dynamic "allow" {
          for_each = try(rule.value.action, "block") == "allow" ? [1] : []
          content {}
        }
        dynamic "block" {
          for_each = try(rule.value.action, "block") == "block" ? [1] : []
          content {}
        }
        dynamic "count" {
          for_each = try(rule.value.action, "block") == "count" ? [1] : []
          content {}
        }
        dynamic "captcha" {
          for_each = try(rule.value.action, "block") == "captcha" ? [1] : []
          content {}
        }
      }

      statement {
        ##
        # IP Set Reference Statement
        # Use arn for a literal ARN, or ref for a module-managed ip set name.
        ##
        dynamic "ip_set_reference_statement" {
          for_each = try(rule.value.ip_set_reference, null) != null ? [rule.value.ip_set_reference] : []
          content {
            arn = try(ip_set_reference_statement.value.ref, null) != null ? aws_wafv2_ip_set.this[ip_set_reference_statement.value.ref].arn : ip_set_reference_statement.value.arn
          }
        }

        ##
        # Geo Match Statement
        ##
        dynamic "geo_match_statement" {
          for_each = try(rule.value.geo_match, null) != null ? [rule.value.geo_match] : []
          content {
            country_codes = geo_match_statement.value.country_codes
          }
        }

        ##
        # Rate-Based Statement
        ##
        dynamic "rate_based_statement" {
          for_each = try(rule.value.rate_based, null) != null ? [rule.value.rate_based] : []
          content {
            limit                 = rate_based_statement.value.limit
            aggregate_key_type    = try(rate_based_statement.value.aggregate_key_type, "IP")
            evaluation_window_sec = try(rate_based_statement.value.evaluation_window_sec, 300)
          }
        }

        ##
        # Byte Match Statement
        ##
        dynamic "byte_match_statement" {
          for_each = try(rule.value.byte_match, null) != null ? [rule.value.byte_match] : []
          content {
            search_string         = byte_match_statement.value.search_string
            positional_constraint = byte_match_statement.value.positional_constraint

            field_to_match {
              dynamic "uri_path" {
                for_each = try(byte_match_statement.value.field_to_match.type, "") == "URI_PATH" ? [1] : []
                content {}
              }
              dynamic "query_string" {
                for_each = try(byte_match_statement.value.field_to_match.type, "") == "QUERY_STRING" ? [1] : []
                content {}
              }
              dynamic "method" {
                for_each = try(byte_match_statement.value.field_to_match.type, "") == "METHOD" ? [1] : []
                content {}
              }
              dynamic "all_query_arguments" {
                for_each = try(byte_match_statement.value.field_to_match.type, "") == "ALL_QUERY_ARGUMENTS" ? [1] : []
                content {}
              }
              dynamic "body" {
                for_each = try(byte_match_statement.value.field_to_match.type, "") == "BODY" ? [1] : []
                content {
                  oversize_handling = try(byte_match_statement.value.field_to_match.oversize_handling, "NO_MATCH")
                }
              }
              dynamic "single_header" {
                for_each = try(byte_match_statement.value.field_to_match.type, "") == "SINGLE_HEADER" ? [1] : []
                content {
                  name = lower(byte_match_statement.value.field_to_match.name)
                }
              }
              dynamic "single_query_argument" {
                for_each = try(byte_match_statement.value.field_to_match.type, "") == "SINGLE_QUERY_ARGUMENT" ? [1] : []
                content {
                  name = lower(byte_match_statement.value.field_to_match.name)
                }
              }
            }

            dynamic "text_transformation" {
              for_each = try(byte_match_statement.value.text_transformations, [{ priority = 0, type = "NONE" }])
              content {
                priority = text_transformation.value.priority
                type     = text_transformation.value.type
              }
            }
          }
        }

        ##
        # Size Constraint Statement
        ##
        dynamic "size_constraint_statement" {
          for_each = try(rule.value.size_constraint, null) != null ? [rule.value.size_constraint] : []
          content {
            comparison_operator = size_constraint_statement.value.comparison_operator
            size                = size_constraint_statement.value.size

            field_to_match {
              dynamic "uri_path" {
                for_each = try(size_constraint_statement.value.field_to_match.type, "") == "URI_PATH" ? [1] : []
                content {}
              }
              dynamic "query_string" {
                for_each = try(size_constraint_statement.value.field_to_match.type, "") == "QUERY_STRING" ? [1] : []
                content {}
              }
              dynamic "method" {
                for_each = try(size_constraint_statement.value.field_to_match.type, "") == "METHOD" ? [1] : []
                content {}
              }
              dynamic "all_query_arguments" {
                for_each = try(size_constraint_statement.value.field_to_match.type, "") == "ALL_QUERY_ARGUMENTS" ? [1] : []
                content {}
              }
              dynamic "body" {
                for_each = try(size_constraint_statement.value.field_to_match.type, "") == "BODY" ? [1] : []
                content {
                  oversize_handling = try(size_constraint_statement.value.field_to_match.oversize_handling, "NO_MATCH")
                }
              }
              dynamic "single_header" {
                for_each = try(size_constraint_statement.value.field_to_match.type, "") == "SINGLE_HEADER" ? [1] : []
                content {
                  name = lower(size_constraint_statement.value.field_to_match.name)
                }
              }
              dynamic "single_query_argument" {
                for_each = try(size_constraint_statement.value.field_to_match.type, "") == "SINGLE_QUERY_ARGUMENT" ? [1] : []
                content {
                  name = lower(size_constraint_statement.value.field_to_match.name)
                }
              }
            }

            dynamic "text_transformation" {
              for_each = try(size_constraint_statement.value.text_transformations, [{ priority = 0, type = "NONE" }])
              content {
                priority = text_transformation.value.priority
                type     = text_transformation.value.type
              }
            }
          }
        }

        ##
        # Regex Pattern Set Reference Statement
        # Use arn for a literal ARN, or ref for a module-managed regex pattern set name.
        ##
        dynamic "regex_pattern_set_reference_statement" {
          for_each = try(rule.value.regex_pattern_set_reference, null) != null ? [rule.value.regex_pattern_set_reference] : []
          content {
            arn = try(regex_pattern_set_reference_statement.value.ref, null) != null ? aws_wafv2_regex_pattern_set.this[regex_pattern_set_reference_statement.value.ref].arn : regex_pattern_set_reference_statement.value.arn

            field_to_match {
              dynamic "uri_path" {
                for_each = try(regex_pattern_set_reference_statement.value.field_to_match.type, "") == "URI_PATH" ? [1] : []
                content {}
              }
              dynamic "query_string" {
                for_each = try(regex_pattern_set_reference_statement.value.field_to_match.type, "") == "QUERY_STRING" ? [1] : []
                content {}
              }
              dynamic "method" {
                for_each = try(regex_pattern_set_reference_statement.value.field_to_match.type, "") == "METHOD" ? [1] : []
                content {}
              }
              dynamic "all_query_arguments" {
                for_each = try(regex_pattern_set_reference_statement.value.field_to_match.type, "") == "ALL_QUERY_ARGUMENTS" ? [1] : []
                content {}
              }
              dynamic "body" {
                for_each = try(regex_pattern_set_reference_statement.value.field_to_match.type, "") == "BODY" ? [1] : []
                content {
                  oversize_handling = try(regex_pattern_set_reference_statement.value.field_to_match.oversize_handling, "NO_MATCH")
                }
              }
              dynamic "single_header" {
                for_each = try(regex_pattern_set_reference_statement.value.field_to_match.type, "") == "SINGLE_HEADER" ? [1] : []
                content {
                  name = lower(regex_pattern_set_reference_statement.value.field_to_match.name)
                }
              }
              dynamic "single_query_argument" {
                for_each = try(regex_pattern_set_reference_statement.value.field_to_match.type, "") == "SINGLE_QUERY_ARGUMENT" ? [1] : []
                content {
                  name = lower(regex_pattern_set_reference_statement.value.field_to_match.name)
                }
              }
            }

            dynamic "text_transformation" {
              for_each = try(regex_pattern_set_reference_statement.value.text_transformations, [{ priority = 0, type = "NONE" }])
              content {
                priority = text_transformation.value.priority
                type     = text_transformation.value.type
              }
            }
          }
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = try(rule.value.visibility_config.cloudwatch_metrics_enabled, true)
        metric_name                = try(rule.value.visibility_config.metric_name, rule.value.name)
        sampled_requests_enabled   = try(rule.value.visibility_config.sampled_requests_enabled, true)
      }
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = try(each.value.visibility_config.cloudwatch_metrics_enabled, true)
    metric_name                = try(each.value.visibility_config.metric_name, format("%s-%s", local.waf_name, each.value.name))
    sampled_requests_enabled   = try(each.value.visibility_config.sampled_requests_enabled, true)
  }

  tags = local.all_tags
}

##
# WAFv2 Web ACL
# Rules are evaluated in priority order. All rules reference rule groups — either
# AWS managed groups, external ARNs (with optional ref: for module-managed groups),
# or custom groups created by this module.
#
# IMPORTANT: lifecycle.ignore_changes = [rule] is set so that rule changes made
# outside Terraform (e.g. by AWS Firewall Manager or the console) are not reverted
# on the next plan/apply. Rules are applied on initial creation only.
##
resource "aws_wafv2_web_acl" "this" {
  name        = local.waf_name
  scope       = local.waf_scope
  description = try(var.settings.description, format("WAF ACL managed by Terraform for %s", local.system_name))

  default_action {
    dynamic "allow" {
      for_each = local.default_action == "allow" ? [1] : []
      content {}
    }
    dynamic "block" {
      for_each = local.default_action == "block" ? [1] : []
      content {}
    }
  }

  ##
  # AWS Managed Rule Groups
  ##
  dynamic "rule" {
    for_each = { for r in local.managed_rules : r.name => r }

    content {
      name     = rule.value.name
      priority = rule.value.priority

      override_action {
        dynamic "none" {
          for_each = try(rule.value.override_action, "none") == "none" ? [1] : []
          content {}
        }
        dynamic "count" {
          for_each = try(rule.value.override_action, "none") == "count" ? [1] : []
          content {}
        }
      }

      statement {
        managed_rule_group_statement {
          name        = rule.value.name
          vendor_name = try(rule.value.vendor_name, "AWS")
          version     = try(rule.value.version, null)

          dynamic "rule_action_override" {
            for_each = try(rule.value.excluded_rules, [])
            content {
              name = rule_action_override.value
              action_to_use {
                count {}
              }
            }
          }

          dynamic "managed_rule_group_configs" {
            for_each = try(rule.value.managed_rule_group_configs, [])
            content {
              dynamic "aws_managed_rules_bot_control_rule_set" {
                for_each = try(managed_rule_group_configs.value.bot_control, null) != null ? [managed_rule_group_configs.value.bot_control] : []
                content {
                  inspection_level = aws_managed_rules_bot_control_rule_set.value.inspection_level
                }
              }

              dynamic "aws_managed_rules_atp_rule_set" {
                for_each = try(managed_rule_group_configs.value.atp, null) != null ? [managed_rule_group_configs.value.atp] : []
                content {
                  login_path = aws_managed_rules_atp_rule_set.value.login_path
                }
              }
            }
          }
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = try(rule.value.visibility_config.cloudwatch_metrics_enabled, true)
        metric_name                = try(rule.value.visibility_config.metric_name, rule.value.name)
        sampled_requests_enabled   = try(rule.value.visibility_config.sampled_requests_enabled, true)
      }
    }
  }

  ##
  # External and Module-Managed Rule Group References
  # Use arn for a literal ARN, or ref for a module-managed rule group name
  # from settings.rule_groups.
  ##
  dynamic "rule" {
    for_each = { for r in local.rule_group_references : r.name => r }

    content {
      name     = rule.value.name
      priority = rule.value.priority

      override_action {
        dynamic "none" {
          for_each = try(rule.value.override_action, "none") == "none" ? [1] : []
          content {}
        }
        dynamic "count" {
          for_each = try(rule.value.override_action, "none") == "count" ? [1] : []
          content {}
        }
      }

      statement {
        rule_group_reference_statement {
          arn = try(rule.value.ref, null) != null ? aws_wafv2_rule_group.this[rule.value.ref].arn : rule.value.arn

          dynamic "rule_action_override" {
            for_each = try(rule.value.excluded_rules, [])
            content {
              name = rule_action_override.value
              action_to_use {
                count {}
              }
            }
          }
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = try(rule.value.visibility_config.cloudwatch_metrics_enabled, true)
        metric_name                = try(rule.value.visibility_config.metric_name, rule.value.name)
        sampled_requests_enabled   = try(rule.value.visibility_config.sampled_requests_enabled, true)
      }
    }
  }

  ##
  # Custom Rule Groups (created by this module)
  ##
  dynamic "rule" {
    for_each = { for rg in local.custom_rule_groups : rg.name => rg }

    content {
      name     = rule.value.name
      priority = rule.value.priority

      override_action {
        dynamic "none" {
          for_each = try(rule.value.override_action, "none") == "none" ? [1] : []
          content {}
        }
        dynamic "count" {
          for_each = try(rule.value.override_action, "none") == "count" ? [1] : []
          content {}
        }
      }

      statement {
        rule_group_reference_statement {
          arn = aws_wafv2_rule_group.this[rule.value.name].arn
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = try(rule.value.visibility_config.cloudwatch_metrics_enabled, true)
        metric_name                = try(rule.value.visibility_config.metric_name, rule.value.name)
        sampled_requests_enabled   = try(rule.value.visibility_config.sampled_requests_enabled, true)
      }
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = try(var.settings.visibility_config.cloudwatch_metrics_enabled, true)
    metric_name                = try(var.settings.visibility_config.metric_name, local.waf_name)
    sampled_requests_enabled   = try(var.settings.visibility_config.sampled_requests_enabled, true)
  }

  tags = local.all_tags

  lifecycle {
    ignore_changes = [rule]
  }
}

##
# WAFv2 Web ACL Associations
# Associates the Web ACL with protected AWS resources:
# ALB, API Gateway stage, AppSync GraphQL API, Cognito User Pool,
# App Runner service, or Verified Access instance.
##
resource "aws_wafv2_web_acl_association" "this" {
  for_each = { for a in local.web_acl_associations : a.resource_arn => a }

  resource_arn = each.value.resource_arn
  web_acl_arn  = aws_wafv2_web_acl.this.arn
}

##
# WAFv2 Web ACL Logging Configuration (optional)
##
resource "aws_wafv2_web_acl_logging_configuration" "this" {
  count = local.logging_enabled ? 1 : 0

  resource_arn            = aws_wafv2_web_acl.this.arn
  log_destination_configs = local.logging_destinations

  dynamic "redacted_fields" {
    for_each = try(var.settings.logging.redacted_fields, [])
    content {
      dynamic "uri_path" {
        for_each = try(redacted_fields.value.type, "") == "URI_PATH" ? [1] : []
        content {}
      }
      dynamic "query_string" {
        for_each = try(redacted_fields.value.type, "") == "QUERY_STRING" ? [1] : []
        content {}
      }
      dynamic "method" {
        for_each = try(redacted_fields.value.type, "") == "METHOD" ? [1] : []
        content {}
      }
      dynamic "single_header" {
        for_each = try(redacted_fields.value.type, "") == "SINGLE_HEADER" ? [1] : []
        content {
          name = lower(redacted_fields.value.name)
        }
      }
    }
  }

  dynamic "logging_filter" {
    for_each = try(var.settings.logging.filter, null) != null ? [var.settings.logging.filter] : []
    content {
      default_behavior = logging_filter.value.default_behavior

      dynamic "filter" {
        for_each = try(logging_filter.value.filters, [])
        content {
          behavior    = filter.value.behavior
          requirement = filter.value.requirement

          dynamic "condition" {
            for_each = try(filter.value.conditions, [])
            content {
              dynamic "action_condition" {
                for_each = try(condition.value.action_condition, null) != null ? [condition.value.action_condition] : []
                content {
                  action = action_condition.value
                }
              }
              dynamic "label_name_condition" {
                for_each = try(condition.value.label_name_condition, null) != null ? [condition.value.label_name_condition] : []
                content {
                  label_name = label_name_condition.value
                }
              }
            }
          }
        }
      }
    }
  }
}

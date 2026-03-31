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
# Rules are managed as separate aws_wafv2_web_acl_rule resources below.
# lifecycle.ignore_changes = [rule] ensures that rules added outside Terraform
# (e.g. by AWS Firewall Manager or the console) are not reverted on plan/apply.
##
resource "aws_wafv2_web_acl" "this" {
  name          = local.waf_name
  scope         = local.waf_scope
  description   = try(var.settings.description, format("WAF ACL managed by Terraform for %s", local.system_name))
  token_domains = try(var.settings.token_domains, null)

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

  dynamic "captcha_config" {
    for_each = try(var.settings.captcha_config, null) != null ? [var.settings.captcha_config] : []
    content {
      immunity_time_property {
        immunity_time = captcha_config.value.immunity_time
      }
    }
  }

  dynamic "challenge_config" {
    for_each = try(var.settings.challenge_config, null) != null ? [var.settings.challenge_config] : []
    content {
      immunity_time_property {
        immunity_time = challenge_config.value.immunity_time
      }
    }
  }

  dynamic "association_config" {
    for_each = try(var.settings.association_config, null) != null ? [var.settings.association_config] : []
    content {
      dynamic "request_body" {
        for_each = try(association_config.value.request_body, [])
        content {
          dynamic "api_gateway" {
            for_each = try(request_body.value.api_gateway, null) != null ? [request_body.value.api_gateway] : []
            content {
              default_size_inspection_limit = api_gateway.value.default_size_inspection_limit
            }
          }
          dynamic "app_runner_service" {
            for_each = try(request_body.value.app_runner_service, null) != null ? [request_body.value.app_runner_service] : []
            content {
              default_size_inspection_limit = app_runner_service.value.default_size_inspection_limit
            }
          }
          dynamic "cloudfront" {
            for_each = try(request_body.value.cloudfront, null) != null ? [request_body.value.cloudfront] : []
            content {
              default_size_inspection_limit = cloudfront.value.default_size_inspection_limit
            }
          }
          dynamic "cognito_user_pool" {
            for_each = try(request_body.value.cognito_user_pool, null) != null ? [request_body.value.cognito_user_pool] : []
            content {
              default_size_inspection_limit = cognito_user_pool.value.default_size_inspection_limit
            }
          }
          dynamic "verified_access_instance" {
            for_each = try(request_body.value.verified_access_instance, null) != null ? [request_body.value.verified_access_instance] : []
            content {
              default_size_inspection_limit = verified_access_instance.value.default_size_inspection_limit
            }
          }
        }
      }
    }
  }

  dynamic "custom_response_body" {
    for_each = { for b in try(var.settings.custom_response_bodies, []) : b.key => b }
    content {
      key          = custom_response_body.value.key
      content      = custom_response_body.value.content
      content_type = custom_response_body.value.content_type
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
# WAFv2 Web ACL Rules — AWS Managed Rule Groups
##
resource "aws_wafv2_web_acl_rule" "managed" {
  for_each = { for r in local.managed_rules : r.name => r }

  name        = format("%s-%s", try(each.value.vendor_name, "AWS"), each.value.name)
  priority    = each.value.priority
  web_acl_arn = aws_wafv2_web_acl.this.arn

  override_action {
    dynamic "none" {
      for_each = try(each.value.override_action, "none") == "none" ? [1] : []
      content {}
    }
    dynamic "count" {
      for_each = try(each.value.override_action, "none") == "count" ? [1] : []
      content {}
    }
  }

  statement {
    managed_rule_group_statement {
      name        = each.value.name
      vendor_name = try(each.value.vendor_name, "AWS")
      version     = try(each.value.version, null)

      dynamic "rule_action_override" {
        for_each = try(each.value.rule_action_overrides, [])
        content {
          name = rule_action_override.value.name
          action_to_use {
            dynamic "allow" {
              for_each = try(rule_action_override.value.action, "count") == "allow" ? [1] : []
              content {}
            }
            dynamic "block" {
              for_each = try(rule_action_override.value.action, "count") == "block" ? [1] : []
              content {}
            }
            dynamic "count" {
              for_each = try(rule_action_override.value.action, "count") == "count" ? [1] : []
              content {}
            }
            dynamic "captcha" {
              for_each = try(rule_action_override.value.action, "count") == "captcha" ? [1] : []
              content {}
            }
            dynamic "challenge" {
              for_each = try(rule_action_override.value.action, "count") == "challenge" ? [1] : []
              content {}
            }
          }
        }
      }

      dynamic "managed_rule_group_configs" {
        for_each = try(each.value.managed_rule_group_configs, [])
        content {
          dynamic "aws_managed_rules_bot_control_rule_set" {
            for_each = try(managed_rule_group_configs.value.bot_control, null) != null ? [managed_rule_group_configs.value.bot_control] : []
            content {
              inspection_level        = aws_managed_rules_bot_control_rule_set.value.inspection_level
              enable_machine_learning = try(aws_managed_rules_bot_control_rule_set.value.enable_machine_learning, true)
            }
          }

          dynamic "aws_managed_rules_atp_rule_set" {
            for_each = try(managed_rule_group_configs.value.atp, null) != null ? [managed_rule_group_configs.value.atp] : []
            content {
              login_path = aws_managed_rules_atp_rule_set.value.login_path

              dynamic "request_inspection" {
                for_each = try(aws_managed_rules_atp_rule_set.value.request_inspection, null) != null ? [aws_managed_rules_atp_rule_set.value.request_inspection] : []
                content {
                  password_field { identifier = request_inspection.value.password_field }
                  payload_type = request_inspection.value.payload_type
                  username_field { identifier = request_inspection.value.username_field }
                }
              }

              dynamic "response_inspection" {
                for_each = try(aws_managed_rules_atp_rule_set.value.response_inspection, null) != null ? [aws_managed_rules_atp_rule_set.value.response_inspection] : []
                content {
                  dynamic "body_contains" {
                    for_each = try(response_inspection.value.body_contains, null) != null ? [response_inspection.value.body_contains] : []
                    content {
                      failure_strings = body_contains.value.failure_strings
                      success_strings = body_contains.value.success_strings
                    }
                  }
                  dynamic "header" {
                    for_each = try(response_inspection.value.header, null) != null ? [response_inspection.value.header] : []
                    content {
                      failure_values = header.value.failure_values
                      name           = header.value.name
                      success_values = header.value.success_values
                    }
                  }
                  dynamic "json" {
                    for_each = try(response_inspection.value.json, null) != null ? [response_inspection.value.json] : []
                    content {
                      failure_values = json.value.failure_values
                      identifier     = json.value.identifier
                      success_values = json.value.success_values
                    }
                  }
                  dynamic "status_code" {
                    for_each = try(response_inspection.value.status_code, null) != null ? [response_inspection.value.status_code] : []
                    content {
                      failure_codes = status_code.value.failure_codes
                      success_codes = status_code.value.success_codes
                    }
                  }
                }
              }
            }
          }

          dynamic "aws_managed_rules_acfp_rule_set" {
            for_each = try(managed_rule_group_configs.value.acfp, null) != null ? [managed_rule_group_configs.value.acfp] : []
            content {
              creation_path          = aws_managed_rules_acfp_rule_set.value.creation_path
              registration_page_path = aws_managed_rules_acfp_rule_set.value.registration_page_path

              dynamic "request_inspection" {
                for_each = try(aws_managed_rules_acfp_rule_set.value.request_inspection, null) != null ? [aws_managed_rules_acfp_rule_set.value.request_inspection] : []
                content {
                  payload_type = request_inspection.value.payload_type

                  dynamic "address_fields" {
                    for_each = try(request_inspection.value.address_fields, [])
                    content {
                      identifiers = address_fields.value.identifiers
                    }
                  }
                  dynamic "email_field" {
                    for_each = try(request_inspection.value.email_field, null) != null ? [request_inspection.value.email_field] : []
                    content {
                      identifier = email_field.value.identifier
                    }
                  }
                  dynamic "password_field" {
                    for_each = try(request_inspection.value.password_field, null) != null ? [request_inspection.value.password_field] : []
                    content {
                      identifier = password_field.value.identifier
                    }
                  }
                  dynamic "phone_number_fields" {
                    for_each = try(request_inspection.value.phone_number_fields, [])
                    content {
                      identifiers = phone_number_fields.value.identifiers
                    }
                  }
                  dynamic "username_field" {
                    for_each = try(request_inspection.value.username_field, null) != null ? [request_inspection.value.username_field] : []
                    content {
                      identifier = username_field.value.identifier
                    }
                  }
                }
              }

              dynamic "response_inspection" {
                for_each = try(aws_managed_rules_acfp_rule_set.value.response_inspection, null) != null ? [aws_managed_rules_acfp_rule_set.value.response_inspection] : []
                content {
                  dynamic "body_contains" {
                    for_each = try(response_inspection.value.body_contains, null) != null ? [response_inspection.value.body_contains] : []
                    content {
                      failure_strings = body_contains.value.failure_strings
                      success_strings = body_contains.value.success_strings
                    }
                  }
                  dynamic "header" {
                    for_each = try(response_inspection.value.header, null) != null ? [response_inspection.value.header] : []
                    content {
                      failure_values = header.value.failure_values
                      name           = header.value.name
                      success_values = header.value.success_values
                    }
                  }
                  dynamic "json" {
                    for_each = try(response_inspection.value.json, null) != null ? [response_inspection.value.json] : []
                    content {
                      failure_values = json.value.failure_values
                      identifier     = json.value.identifier
                      success_values = json.value.success_values
                    }
                  }
                  dynamic "status_code" {
                    for_each = try(response_inspection.value.status_code, null) != null ? [response_inspection.value.status_code] : []
                    content {
                      failure_codes = status_code.value.failure_codes
                      success_codes = status_code.value.success_codes
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }

  dynamic "captcha_config" {
    for_each = try(each.value.captcha_config, null) != null ? [each.value.captcha_config] : []
    content {
      immunity_time_property {
        immunity_time = captcha_config.value.immunity_time
      }
    }
  }

  dynamic "challenge_config" {
    for_each = try(each.value.challenge_config, null) != null ? [each.value.challenge_config] : []
    content {
      immunity_time_property {
        immunity_time = challenge_config.value.immunity_time
      }
    }
  }

  dynamic "rule_label" {
    for_each = try(each.value.rule_labels, [])
    content {
      name = rule_label.value
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = try(each.value.visibility_config.cloudwatch_metrics_enabled, true)
    metric_name                = try(each.value.visibility_config.metric_name, each.value.name)
    sampled_requests_enabled   = try(each.value.visibility_config.sampled_requests_enabled, true)
  }
}

##
# WAFv2 Web ACL Rules — External and Module-Managed Rule Group References
# Use arn for a literal ARN, or ref for a module-managed rule group name
# from settings.rule_groups.
##
resource "aws_wafv2_web_acl_rule" "rule_group_references" {
  for_each = { for r in local.rule_group_references : r.name => r }

  name        = each.value.name
  priority    = each.value.priority
  web_acl_arn = aws_wafv2_web_acl.this.arn

  override_action {
    dynamic "none" {
      for_each = try(each.value.override_action, "none") == "none" ? [1] : []
      content {}
    }
    dynamic "count" {
      for_each = try(each.value.override_action, "none") == "count" ? [1] : []
      content {}
    }
  }

  statement {
    rule_group_reference_statement {
      arn = try(each.value.ref, null) != null ? aws_wafv2_rule_group.this[each.value.ref].arn : each.value.arn

      dynamic "rule_action_override" {
        for_each = try(each.value.rule_action_overrides, [])
        content {
          name = rule_action_override.value.name
          action_to_use {
            dynamic "allow" {
              for_each = try(rule_action_override.value.action, "count") == "allow" ? [1] : []
              content {}
            }
            dynamic "block" {
              for_each = try(rule_action_override.value.action, "count") == "block" ? [1] : []
              content {}
            }
            dynamic "count" {
              for_each = try(rule_action_override.value.action, "count") == "count" ? [1] : []
              content {}
            }
            dynamic "captcha" {
              for_each = try(rule_action_override.value.action, "count") == "captcha" ? [1] : []
              content {}
            }
            dynamic "challenge" {
              for_each = try(rule_action_override.value.action, "count") == "challenge" ? [1] : []
              content {}
            }
          }
        }
      }
    }
  }

  dynamic "captcha_config" {
    for_each = try(each.value.captcha_config, null) != null ? [each.value.captcha_config] : []
    content {
      immunity_time_property {
        immunity_time = captcha_config.value.immunity_time
      }
    }
  }

  dynamic "challenge_config" {
    for_each = try(each.value.challenge_config, null) != null ? [each.value.challenge_config] : []
    content {
      immunity_time_property {
        immunity_time = challenge_config.value.immunity_time
      }
    }
  }

  dynamic "rule_label" {
    for_each = try(each.value.rule_labels, [])
    content {
      name = rule_label.value
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = try(each.value.visibility_config.cloudwatch_metrics_enabled, true)
    metric_name                = try(each.value.visibility_config.metric_name, each.value.name)
    sampled_requests_enabled   = try(each.value.visibility_config.sampled_requests_enabled, true)
  }
}

##
# WAFv2 Web ACL Rules — Custom Rule Groups (created by this module)
##
resource "aws_wafv2_web_acl_rule" "custom_rule_groups" {
  for_each = { for rg in local.custom_rule_groups : rg.name => rg }

  name        = each.value.name
  priority    = each.value.priority
  web_acl_arn = aws_wafv2_web_acl.this.arn

  override_action {
    dynamic "none" {
      for_each = try(each.value.override_action, "none") == "none" ? [1] : []
      content {}
    }
    dynamic "count" {
      for_each = try(each.value.override_action, "none") == "count" ? [1] : []
      content {}
    }
  }

  statement {
    rule_group_reference_statement {
      arn = aws_wafv2_rule_group.this[each.value.name].arn
    }
  }

  dynamic "captcha_config" {
    for_each = try(each.value.captcha_config, null) != null ? [each.value.captcha_config] : []
    content {
      immunity_time_property {
        immunity_time = captcha_config.value.immunity_time
      }
    }
  }

  dynamic "challenge_config" {
    for_each = try(each.value.challenge_config, null) != null ? [each.value.challenge_config] : []
    content {
      immunity_time_property {
        immunity_time = challenge_config.value.immunity_time
      }
    }
  }

  dynamic "rule_label" {
    for_each = try(each.value.rule_labels, [])
    content {
      name = rule_label.value
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = try(each.value.visibility_config.cloudwatch_metrics_enabled, true)
    metric_name                = try(each.value.visibility_config.metric_name, each.value.name)
    sampled_requests_enabled   = try(each.value.visibility_config.sampled_requests_enabled, true)
  }
}

##
# WAFv2 Web ACL Rules — Custom Inline Rules
# Statement type is dynamically detected from the rule config key.
# Unlike rule-group rules, these use action (not override_action).
# Supported statements:
#   Leaf:     ip_set_reference, geo_match, label_match, asn_match, rate_based,
#             byte_match, size_constraint, sqli_match, xss_match,
#             regex_match, regex_pattern_set_reference
#   Compound: not_statement, and_statement, or_statement
#             (each compound wraps any leaf statement one level deep)
##
resource "aws_wafv2_web_acl_rule" "custom" {
  for_each = { for r in local.custom_rules : r.name => r }

  name        = each.value.name
  priority    = each.value.priority
  web_acl_arn = aws_wafv2_web_acl.this.arn

  action {
    dynamic "allow" {
      for_each = try(each.value.action, "block") == "allow" ? [1] : []
      content {}
    }
    dynamic "block" {
      for_each = try(each.value.action, "block") == "block" ? [1] : []
      content {}
    }
    dynamic "count" {
      for_each = try(each.value.action, "block") == "count" ? [1] : []
      content {}
    }
    dynamic "captcha" {
      for_each = try(each.value.action, "block") == "captcha" ? [1] : []
      content {}
    }
    dynamic "challenge" {
      for_each = try(each.value.action, "block") == "challenge" ? [1] : []
      content {}
    }
  }

  statement {
    ##
    # IP Set Reference Statement
    ##
    dynamic "ip_set_reference_statement" {
      for_each = try(each.value.ip_set_reference, null) != null ? [each.value.ip_set_reference] : []
      content {
        arn = try(ip_set_reference_statement.value.ref, null) != null ? aws_wafv2_ip_set.this[ip_set_reference_statement.value.ref].arn : ip_set_reference_statement.value.arn

        dynamic "ip_set_forwarded_ip_config" {
          for_each = try(ip_set_reference_statement.value.forwarded_ip_config, null) != null ? [ip_set_reference_statement.value.forwarded_ip_config] : []
          content {
            fallback_behavior = ip_set_forwarded_ip_config.value.fallback_behavior
            header_name       = ip_set_forwarded_ip_config.value.header_name
            position          = ip_set_forwarded_ip_config.value.position
          }
        }
      }
    }

    ##
    # Geo Match Statement
    ##
    dynamic "geo_match_statement" {
      for_each = try(each.value.geo_match, null) != null ? [each.value.geo_match] : []
      content {
        country_codes = geo_match_statement.value.country_codes

        dynamic "forwarded_ip_config" {
          for_each = try(geo_match_statement.value.forwarded_ip_config, null) != null ? [geo_match_statement.value.forwarded_ip_config] : []
          content {
            fallback_behavior = forwarded_ip_config.value.fallback_behavior
            header_name       = forwarded_ip_config.value.header_name
          }
        }
      }
    }

    ##
    # Label Match Statement
    ##
    dynamic "label_match_statement" {
      for_each = try(each.value.label_match, null) != null ? [each.value.label_match] : []
      content {
        scope = label_match_statement.value.scope
        key   = label_match_statement.value.key
      }
    }

    ##
    # ASN Match Statement
    ##
    dynamic "asn_match_statement" {
      for_each = try(each.value.asn_match, null) != null ? [each.value.asn_match] : []
      content {
        asn_list = asn_match_statement.value.asn_list

        dynamic "forwarded_ip_config" {
          for_each = try(asn_match_statement.value.forwarded_ip_config, null) != null ? [asn_match_statement.value.forwarded_ip_config] : []
          content {
            fallback_behavior = forwarded_ip_config.value.fallback_behavior
            header_name       = forwarded_ip_config.value.header_name
          }
        }
      }
    }

    ##
    # Rate-Based Statement
    ##
    dynamic "rate_based_statement" {
      for_each = try(each.value.rate_based, null) != null ? [each.value.rate_based] : []
      content {
        limit                 = rate_based_statement.value.limit
        aggregate_key_type    = try(rate_based_statement.value.aggregate_key_type, "IP")
        evaluation_window_sec = try(rate_based_statement.value.evaluation_window_sec, 300)

        dynamic "forwarded_ip_config" {
          for_each = try(rate_based_statement.value.forwarded_ip_config, null) != null ? [rate_based_statement.value.forwarded_ip_config] : []
          content {
            fallback_behavior = forwarded_ip_config.value.fallback_behavior
            header_name       = forwarded_ip_config.value.header_name
          }
        }
      }
    }

    ##
    # Byte Match Statement
    ##
    dynamic "byte_match_statement" {
      for_each = try(each.value.byte_match, null) != null ? [each.value.byte_match] : []
      content {
        search_string         = byte_match_statement.value.search_string
        positional_constraint = byte_match_statement.value.positional_constraint

        field_to_match {
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
          dynamic "cookies" {
            for_each = try(byte_match_statement.value.field_to_match.type, "") == "COOKIES" ? [byte_match_statement.value.field_to_match] : []
            iterator = ftm_cookies
            content {
              match_scope       = try(ftm_cookies.value.match_scope, "ALL")
              oversize_handling = try(ftm_cookies.value.oversize_handling, "NO_MATCH")
              match_pattern {
                dynamic "all" {
                  for_each = try(ftm_cookies.value.included_cookies, null) == null && try(ftm_cookies.value.excluded_cookies, null) == null ? [1] : []
                  content {}
                }
                included_cookies = try(ftm_cookies.value.included_cookies, null)
                excluded_cookies = try(ftm_cookies.value.excluded_cookies, null)
              }
            }
          }
          dynamic "headers" {
            for_each = try(byte_match_statement.value.field_to_match.type, "") == "HEADERS" ? [byte_match_statement.value.field_to_match] : []
            iterator = ftm_headers
            content {
              match_scope       = try(ftm_headers.value.match_scope, "ALL")
              oversize_handling = try(ftm_headers.value.oversize_handling, "NO_MATCH")
              match_pattern {
                dynamic "all" {
                  for_each = try(ftm_headers.value.included_headers, null) == null && try(ftm_headers.value.excluded_headers, null) == null ? [1] : []
                  content {}
                }
                included_headers = try(ftm_headers.value.included_headers, null)
                excluded_headers = try(ftm_headers.value.excluded_headers, null)
              }
            }
          }
          dynamic "json_body" {
            for_each = try(byte_match_statement.value.field_to_match.type, "") == "JSON_BODY" ? [byte_match_statement.value.field_to_match] : []
            iterator = ftm_json
            content {
              match_scope               = try(ftm_json.value.match_scope, "ALL")
              oversize_handling         = try(ftm_json.value.oversize_handling, "NO_MATCH")
              invalid_fallback_behavior = try(ftm_json.value.invalid_fallback_behavior, "NO_MATCH")
              match_pattern {
                dynamic "all" {
                  for_each = try(ftm_json.value.included_paths, null) == null ? [1] : []
                  content {}
                }
                included_paths = try(ftm_json.value.included_paths, null)
              }
            }
          }
          dynamic "method" {
            for_each = try(byte_match_statement.value.field_to_match.type, "") == "METHOD" ? [1] : []
            content {}
          }
          dynamic "query_string" {
            for_each = try(byte_match_statement.value.field_to_match.type, "") == "QUERY_STRING" ? [1] : []
            content {}
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
          dynamic "uri_path" {
            for_each = try(byte_match_statement.value.field_to_match.type, "") == "URI_PATH" ? [1] : []
            content {}
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
      for_each = try(each.value.size_constraint, null) != null ? [each.value.size_constraint] : []
      content {
        comparison_operator = size_constraint_statement.value.comparison_operator
        size                = size_constraint_statement.value.size

        field_to_match {
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
          dynamic "cookies" {
            for_each = try(size_constraint_statement.value.field_to_match.type, "") == "COOKIES" ? [size_constraint_statement.value.field_to_match] : []
            iterator = ftm_cookies
            content {
              match_scope       = try(ftm_cookies.value.match_scope, "ALL")
              oversize_handling = try(ftm_cookies.value.oversize_handling, "NO_MATCH")
              match_pattern {
                dynamic "all" {
                  for_each = try(ftm_cookies.value.included_cookies, null) == null && try(ftm_cookies.value.excluded_cookies, null) == null ? [1] : []
                  content {}
                }
                included_cookies = try(ftm_cookies.value.included_cookies, null)
                excluded_cookies = try(ftm_cookies.value.excluded_cookies, null)
              }
            }
          }
          dynamic "headers" {
            for_each = try(size_constraint_statement.value.field_to_match.type, "") == "HEADERS" ? [size_constraint_statement.value.field_to_match] : []
            iterator = ftm_headers
            content {
              match_scope       = try(ftm_headers.value.match_scope, "ALL")
              oversize_handling = try(ftm_headers.value.oversize_handling, "NO_MATCH")
              match_pattern {
                dynamic "all" {
                  for_each = try(ftm_headers.value.included_headers, null) == null && try(ftm_headers.value.excluded_headers, null) == null ? [1] : []
                  content {}
                }
                included_headers = try(ftm_headers.value.included_headers, null)
                excluded_headers = try(ftm_headers.value.excluded_headers, null)
              }
            }
          }
          dynamic "json_body" {
            for_each = try(size_constraint_statement.value.field_to_match.type, "") == "JSON_BODY" ? [size_constraint_statement.value.field_to_match] : []
            iterator = ftm_json
            content {
              match_scope               = try(ftm_json.value.match_scope, "ALL")
              oversize_handling         = try(ftm_json.value.oversize_handling, "NO_MATCH")
              invalid_fallback_behavior = try(ftm_json.value.invalid_fallback_behavior, "NO_MATCH")
              match_pattern {
                dynamic "all" {
                  for_each = try(ftm_json.value.included_paths, null) == null ? [1] : []
                  content {}
                }
                included_paths = try(ftm_json.value.included_paths, null)
              }
            }
          }
          dynamic "method" {
            for_each = try(size_constraint_statement.value.field_to_match.type, "") == "METHOD" ? [1] : []
            content {}
          }
          dynamic "query_string" {
            for_each = try(size_constraint_statement.value.field_to_match.type, "") == "QUERY_STRING" ? [1] : []
            content {}
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
          dynamic "uri_path" {
            for_each = try(size_constraint_statement.value.field_to_match.type, "") == "URI_PATH" ? [1] : []
            content {}
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
    # SQLi Match Statement
    ##
    dynamic "sqli_match_statement" {
      for_each = try(each.value.sqli_match, null) != null ? [each.value.sqli_match] : []
      content {
        sensitivity_level = try(sqli_match_statement.value.sensitivity_level, "LOW")

        field_to_match {
          dynamic "all_query_arguments" {
            for_each = try(sqli_match_statement.value.field_to_match.type, "") == "ALL_QUERY_ARGUMENTS" ? [1] : []
            content {}
          }
          dynamic "body" {
            for_each = try(sqli_match_statement.value.field_to_match.type, "") == "BODY" ? [1] : []
            content {
              oversize_handling = try(sqli_match_statement.value.field_to_match.oversize_handling, "NO_MATCH")
            }
          }
          dynamic "cookies" {
            for_each = try(sqli_match_statement.value.field_to_match.type, "") == "COOKIES" ? [sqli_match_statement.value.field_to_match] : []
            iterator = ftm_cookies
            content {
              match_scope       = try(ftm_cookies.value.match_scope, "ALL")
              oversize_handling = try(ftm_cookies.value.oversize_handling, "NO_MATCH")
              match_pattern {
                dynamic "all" {
                  for_each = try(ftm_cookies.value.included_cookies, null) == null && try(ftm_cookies.value.excluded_cookies, null) == null ? [1] : []
                  content {}
                }
                included_cookies = try(ftm_cookies.value.included_cookies, null)
                excluded_cookies = try(ftm_cookies.value.excluded_cookies, null)
              }
            }
          }
          dynamic "headers" {
            for_each = try(sqli_match_statement.value.field_to_match.type, "") == "HEADERS" ? [sqli_match_statement.value.field_to_match] : []
            iterator = ftm_headers
            content {
              match_scope       = try(ftm_headers.value.match_scope, "ALL")
              oversize_handling = try(ftm_headers.value.oversize_handling, "NO_MATCH")
              match_pattern {
                dynamic "all" {
                  for_each = try(ftm_headers.value.included_headers, null) == null && try(ftm_headers.value.excluded_headers, null) == null ? [1] : []
                  content {}
                }
                included_headers = try(ftm_headers.value.included_headers, null)
                excluded_headers = try(ftm_headers.value.excluded_headers, null)
              }
            }
          }
          dynamic "json_body" {
            for_each = try(sqli_match_statement.value.field_to_match.type, "") == "JSON_BODY" ? [sqli_match_statement.value.field_to_match] : []
            iterator = ftm_json
            content {
              match_scope               = try(ftm_json.value.match_scope, "ALL")
              oversize_handling         = try(ftm_json.value.oversize_handling, "NO_MATCH")
              invalid_fallback_behavior = try(ftm_json.value.invalid_fallback_behavior, "NO_MATCH")
              match_pattern {
                dynamic "all" {
                  for_each = try(ftm_json.value.included_paths, null) == null ? [1] : []
                  content {}
                }
                included_paths = try(ftm_json.value.included_paths, null)
              }
            }
          }
          dynamic "method" {
            for_each = try(sqli_match_statement.value.field_to_match.type, "") == "METHOD" ? [1] : []
            content {}
          }
          dynamic "query_string" {
            for_each = try(sqli_match_statement.value.field_to_match.type, "") == "QUERY_STRING" ? [1] : []
            content {}
          }
          dynamic "single_header" {
            for_each = try(sqli_match_statement.value.field_to_match.type, "") == "SINGLE_HEADER" ? [1] : []
            content {
              name = lower(sqli_match_statement.value.field_to_match.name)
            }
          }
          dynamic "single_query_argument" {
            for_each = try(sqli_match_statement.value.field_to_match.type, "") == "SINGLE_QUERY_ARGUMENT" ? [1] : []
            content {
              name = lower(sqli_match_statement.value.field_to_match.name)
            }
          }
          dynamic "uri_path" {
            for_each = try(sqli_match_statement.value.field_to_match.type, "") == "URI_PATH" ? [1] : []
            content {}
          }
        }

        dynamic "text_transformation" {
          for_each = try(sqli_match_statement.value.text_transformations, [{ priority = 0, type = "NONE" }])
          content {
            priority = text_transformation.value.priority
            type     = text_transformation.value.type
          }
        }
      }
    }

    ##
    # XSS Match Statement
    ##
    dynamic "xss_match_statement" {
      for_each = try(each.value.xss_match, null) != null ? [each.value.xss_match] : []
      content {
        field_to_match {
          dynamic "all_query_arguments" {
            for_each = try(xss_match_statement.value.field_to_match.type, "") == "ALL_QUERY_ARGUMENTS" ? [1] : []
            content {}
          }
          dynamic "body" {
            for_each = try(xss_match_statement.value.field_to_match.type, "") == "BODY" ? [1] : []
            content {
              oversize_handling = try(xss_match_statement.value.field_to_match.oversize_handling, "NO_MATCH")
            }
          }
          dynamic "cookies" {
            for_each = try(xss_match_statement.value.field_to_match.type, "") == "COOKIES" ? [xss_match_statement.value.field_to_match] : []
            iterator = ftm_cookies
            content {
              match_scope       = try(ftm_cookies.value.match_scope, "ALL")
              oversize_handling = try(ftm_cookies.value.oversize_handling, "NO_MATCH")
              match_pattern {
                dynamic "all" {
                  for_each = try(ftm_cookies.value.included_cookies, null) == null && try(ftm_cookies.value.excluded_cookies, null) == null ? [1] : []
                  content {}
                }
                included_cookies = try(ftm_cookies.value.included_cookies, null)
                excluded_cookies = try(ftm_cookies.value.excluded_cookies, null)
              }
            }
          }
          dynamic "headers" {
            for_each = try(xss_match_statement.value.field_to_match.type, "") == "HEADERS" ? [xss_match_statement.value.field_to_match] : []
            iterator = ftm_headers
            content {
              match_scope       = try(ftm_headers.value.match_scope, "ALL")
              oversize_handling = try(ftm_headers.value.oversize_handling, "NO_MATCH")
              match_pattern {
                dynamic "all" {
                  for_each = try(ftm_headers.value.included_headers, null) == null && try(ftm_headers.value.excluded_headers, null) == null ? [1] : []
                  content {}
                }
                included_headers = try(ftm_headers.value.included_headers, null)
                excluded_headers = try(ftm_headers.value.excluded_headers, null)
              }
            }
          }
          dynamic "json_body" {
            for_each = try(xss_match_statement.value.field_to_match.type, "") == "JSON_BODY" ? [xss_match_statement.value.field_to_match] : []
            iterator = ftm_json
            content {
              match_scope               = try(ftm_json.value.match_scope, "ALL")
              oversize_handling         = try(ftm_json.value.oversize_handling, "NO_MATCH")
              invalid_fallback_behavior = try(ftm_json.value.invalid_fallback_behavior, "NO_MATCH")
              match_pattern {
                dynamic "all" {
                  for_each = try(ftm_json.value.included_paths, null) == null ? [1] : []
                  content {}
                }
                included_paths = try(ftm_json.value.included_paths, null)
              }
            }
          }
          dynamic "method" {
            for_each = try(xss_match_statement.value.field_to_match.type, "") == "METHOD" ? [1] : []
            content {}
          }
          dynamic "query_string" {
            for_each = try(xss_match_statement.value.field_to_match.type, "") == "QUERY_STRING" ? [1] : []
            content {}
          }
          dynamic "single_header" {
            for_each = try(xss_match_statement.value.field_to_match.type, "") == "SINGLE_HEADER" ? [1] : []
            content {
              name = lower(xss_match_statement.value.field_to_match.name)
            }
          }
          dynamic "single_query_argument" {
            for_each = try(xss_match_statement.value.field_to_match.type, "") == "SINGLE_QUERY_ARGUMENT" ? [1] : []
            content {
              name = lower(xss_match_statement.value.field_to_match.name)
            }
          }
          dynamic "uri_path" {
            for_each = try(xss_match_statement.value.field_to_match.type, "") == "URI_PATH" ? [1] : []
            content {}
          }
        }

        dynamic "text_transformation" {
          for_each = try(xss_match_statement.value.text_transformations, [{ priority = 0, type = "NONE" }])
          content {
            priority = text_transformation.value.priority
            type     = text_transformation.value.type
          }
        }
      }
    }

    ##
    # Regex Match Statement
    ##
    dynamic "regex_match_statement" {
      for_each = try(each.value.regex_match, null) != null ? [each.value.regex_match] : []
      content {
        regex_string = regex_match_statement.value.regex_string

        field_to_match {
          dynamic "all_query_arguments" {
            for_each = try(regex_match_statement.value.field_to_match.type, "") == "ALL_QUERY_ARGUMENTS" ? [1] : []
            content {}
          }
          dynamic "body" {
            for_each = try(regex_match_statement.value.field_to_match.type, "") == "BODY" ? [1] : []
            content {
              oversize_handling = try(regex_match_statement.value.field_to_match.oversize_handling, "NO_MATCH")
            }
          }
          dynamic "cookies" {
            for_each = try(regex_match_statement.value.field_to_match.type, "") == "COOKIES" ? [regex_match_statement.value.field_to_match] : []
            iterator = ftm_cookies
            content {
              match_scope       = try(ftm_cookies.value.match_scope, "ALL")
              oversize_handling = try(ftm_cookies.value.oversize_handling, "NO_MATCH")
              match_pattern {
                dynamic "all" {
                  for_each = try(ftm_cookies.value.included_cookies, null) == null && try(ftm_cookies.value.excluded_cookies, null) == null ? [1] : []
                  content {}
                }
                included_cookies = try(ftm_cookies.value.included_cookies, null)
                excluded_cookies = try(ftm_cookies.value.excluded_cookies, null)
              }
            }
          }
          dynamic "headers" {
            for_each = try(regex_match_statement.value.field_to_match.type, "") == "HEADERS" ? [regex_match_statement.value.field_to_match] : []
            iterator = ftm_headers
            content {
              match_scope       = try(ftm_headers.value.match_scope, "ALL")
              oversize_handling = try(ftm_headers.value.oversize_handling, "NO_MATCH")
              match_pattern {
                dynamic "all" {
                  for_each = try(ftm_headers.value.included_headers, null) == null && try(ftm_headers.value.excluded_headers, null) == null ? [1] : []
                  content {}
                }
                included_headers = try(ftm_headers.value.included_headers, null)
                excluded_headers = try(ftm_headers.value.excluded_headers, null)
              }
            }
          }
          dynamic "json_body" {
            for_each = try(regex_match_statement.value.field_to_match.type, "") == "JSON_BODY" ? [regex_match_statement.value.field_to_match] : []
            iterator = ftm_json
            content {
              match_scope               = try(ftm_json.value.match_scope, "ALL")
              oversize_handling         = try(ftm_json.value.oversize_handling, "NO_MATCH")
              invalid_fallback_behavior = try(ftm_json.value.invalid_fallback_behavior, "NO_MATCH")
              match_pattern {
                dynamic "all" {
                  for_each = try(ftm_json.value.included_paths, null) == null ? [1] : []
                  content {}
                }
                included_paths = try(ftm_json.value.included_paths, null)
              }
            }
          }
          dynamic "method" {
            for_each = try(regex_match_statement.value.field_to_match.type, "") == "METHOD" ? [1] : []
            content {}
          }
          dynamic "query_string" {
            for_each = try(regex_match_statement.value.field_to_match.type, "") == "QUERY_STRING" ? [1] : []
            content {}
          }
          dynamic "single_header" {
            for_each = try(regex_match_statement.value.field_to_match.type, "") == "SINGLE_HEADER" ? [1] : []
            content {
              name = lower(regex_match_statement.value.field_to_match.name)
            }
          }
          dynamic "single_query_argument" {
            for_each = try(regex_match_statement.value.field_to_match.type, "") == "SINGLE_QUERY_ARGUMENT" ? [1] : []
            content {
              name = lower(regex_match_statement.value.field_to_match.name)
            }
          }
          dynamic "uri_path" {
            for_each = try(regex_match_statement.value.field_to_match.type, "") == "URI_PATH" ? [1] : []
            content {}
          }
        }

        dynamic "text_transformation" {
          for_each = try(regex_match_statement.value.text_transformations, [{ priority = 0, type = "NONE" }])
          content {
            priority = text_transformation.value.priority
            type     = text_transformation.value.type
          }
        }
      }
    }

    ##
    # Regex Pattern Set Reference Statement
    ##
    dynamic "regex_pattern_set_reference_statement" {
      for_each = try(each.value.regex_pattern_set_reference, null) != null ? [each.value.regex_pattern_set_reference] : []
      content {
        arn = try(regex_pattern_set_reference_statement.value.ref, null) != null ? aws_wafv2_regex_pattern_set.this[regex_pattern_set_reference_statement.value.ref].arn : regex_pattern_set_reference_statement.value.arn

        field_to_match {
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
          dynamic "cookies" {
            for_each = try(regex_pattern_set_reference_statement.value.field_to_match.type, "") == "COOKIES" ? [regex_pattern_set_reference_statement.value.field_to_match] : []
            iterator = ftm_cookies
            content {
              match_scope       = try(ftm_cookies.value.match_scope, "ALL")
              oversize_handling = try(ftm_cookies.value.oversize_handling, "NO_MATCH")
              match_pattern {
                dynamic "all" {
                  for_each = try(ftm_cookies.value.included_cookies, null) == null && try(ftm_cookies.value.excluded_cookies, null) == null ? [1] : []
                  content {}
                }
                included_cookies = try(ftm_cookies.value.included_cookies, null)
                excluded_cookies = try(ftm_cookies.value.excluded_cookies, null)
              }
            }
          }
          dynamic "headers" {
            for_each = try(regex_pattern_set_reference_statement.value.field_to_match.type, "") == "HEADERS" ? [regex_pattern_set_reference_statement.value.field_to_match] : []
            iterator = ftm_headers
            content {
              match_scope       = try(ftm_headers.value.match_scope, "ALL")
              oversize_handling = try(ftm_headers.value.oversize_handling, "NO_MATCH")
              match_pattern {
                dynamic "all" {
                  for_each = try(ftm_headers.value.included_headers, null) == null && try(ftm_headers.value.excluded_headers, null) == null ? [1] : []
                  content {}
                }
                included_headers = try(ftm_headers.value.included_headers, null)
                excluded_headers = try(ftm_headers.value.excluded_headers, null)
              }
            }
          }
          dynamic "json_body" {
            for_each = try(regex_pattern_set_reference_statement.value.field_to_match.type, "") == "JSON_BODY" ? [regex_pattern_set_reference_statement.value.field_to_match] : []
            iterator = ftm_json
            content {
              match_scope               = try(ftm_json.value.match_scope, "ALL")
              oversize_handling         = try(ftm_json.value.oversize_handling, "NO_MATCH")
              invalid_fallback_behavior = try(ftm_json.value.invalid_fallback_behavior, "NO_MATCH")
              match_pattern {
                dynamic "all" {
                  for_each = try(ftm_json.value.included_paths, null) == null ? [1] : []
                  content {}
                }
                included_paths = try(ftm_json.value.included_paths, null)
              }
            }
          }
          dynamic "method" {
            for_each = try(regex_pattern_set_reference_statement.value.field_to_match.type, "") == "METHOD" ? [1] : []
            content {}
          }
          dynamic "query_string" {
            for_each = try(regex_pattern_set_reference_statement.value.field_to_match.type, "") == "QUERY_STRING" ? [1] : []
            content {}
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
          dynamic "uri_path" {
            for_each = try(regex_pattern_set_reference_statement.value.field_to_match.type, "") == "URI_PATH" ? [1] : []
            content {}
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

    ##
    # NOT Statement — wraps any single leaf statement
    ##
    dynamic "not_statement" {
      for_each = try(each.value.not_statement, null) != null ? [each.value.not_statement] : []
      iterator = not_stmt
      content {
        statement {
          dynamic "ip_set_reference_statement" {
            for_each = try(not_stmt.value.ip_set_reference, null) != null ? [not_stmt.value.ip_set_reference] : []
            content {
              arn = try(ip_set_reference_statement.value.ref, null) != null ? aws_wafv2_ip_set.this[ip_set_reference_statement.value.ref].arn : ip_set_reference_statement.value.arn
            }
          }
          dynamic "geo_match_statement" {
            for_each = try(not_stmt.value.geo_match, null) != null ? [not_stmt.value.geo_match] : []
            content {
              country_codes = geo_match_statement.value.country_codes
            }
          }
          dynamic "label_match_statement" {
            for_each = try(not_stmt.value.label_match, null) != null ? [not_stmt.value.label_match] : []
            content {
              scope = label_match_statement.value.scope
              key   = label_match_statement.value.key
            }
          }
          dynamic "asn_match_statement" {
            for_each = try(not_stmt.value.asn_match, null) != null ? [not_stmt.value.asn_match] : []
            content {
              asn_list = asn_match_statement.value.asn_list
            }
          }
          dynamic "rate_based_statement" {
            for_each = try(not_stmt.value.rate_based, null) != null ? [not_stmt.value.rate_based] : []
            content {
              limit                 = rate_based_statement.value.limit
              aggregate_key_type    = try(rate_based_statement.value.aggregate_key_type, "IP")
              evaluation_window_sec = try(rate_based_statement.value.evaluation_window_sec, 300)
            }
          }
          dynamic "byte_match_statement" {
            for_each = try(not_stmt.value.byte_match, null) != null ? [not_stmt.value.byte_match] : []
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
          dynamic "size_constraint_statement" {
            for_each = try(not_stmt.value.size_constraint, null) != null ? [not_stmt.value.size_constraint] : []
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
          dynamic "sqli_match_statement" {
            for_each = try(not_stmt.value.sqli_match, null) != null ? [not_stmt.value.sqli_match] : []
            content {
              sensitivity_level = try(sqli_match_statement.value.sensitivity_level, "LOW")
              field_to_match {
                dynamic "uri_path" {
                  for_each = try(sqli_match_statement.value.field_to_match.type, "") == "URI_PATH" ? [1] : []
                  content {}
                }
                dynamic "query_string" {
                  for_each = try(sqli_match_statement.value.field_to_match.type, "") == "QUERY_STRING" ? [1] : []
                  content {}
                }
                dynamic "body" {
                  for_each = try(sqli_match_statement.value.field_to_match.type, "") == "BODY" ? [1] : []
                  content {
                    oversize_handling = try(sqli_match_statement.value.field_to_match.oversize_handling, "NO_MATCH")
                  }
                }
                dynamic "single_header" {
                  for_each = try(sqli_match_statement.value.field_to_match.type, "") == "SINGLE_HEADER" ? [1] : []
                  content {
                    name = lower(sqli_match_statement.value.field_to_match.name)
                  }
                }
                dynamic "all_query_arguments" {
                  for_each = try(sqli_match_statement.value.field_to_match.type, "") == "ALL_QUERY_ARGUMENTS" ? [1] : []
                  content {}
                }
              }
              dynamic "text_transformation" {
                for_each = try(sqli_match_statement.value.text_transformations, [{ priority = 0, type = "NONE" }])
                content {
                  priority = text_transformation.value.priority
                  type     = text_transformation.value.type
                }
              }
            }
          }
          dynamic "xss_match_statement" {
            for_each = try(not_stmt.value.xss_match, null) != null ? [not_stmt.value.xss_match] : []
            content {
              field_to_match {
                dynamic "uri_path" {
                  for_each = try(xss_match_statement.value.field_to_match.type, "") == "URI_PATH" ? [1] : []
                  content {}
                }
                dynamic "query_string" {
                  for_each = try(xss_match_statement.value.field_to_match.type, "") == "QUERY_STRING" ? [1] : []
                  content {}
                }
                dynamic "body" {
                  for_each = try(xss_match_statement.value.field_to_match.type, "") == "BODY" ? [1] : []
                  content {
                    oversize_handling = try(xss_match_statement.value.field_to_match.oversize_handling, "NO_MATCH")
                  }
                }
                dynamic "single_header" {
                  for_each = try(xss_match_statement.value.field_to_match.type, "") == "SINGLE_HEADER" ? [1] : []
                  content {
                    name = lower(xss_match_statement.value.field_to_match.name)
                  }
                }
                dynamic "all_query_arguments" {
                  for_each = try(xss_match_statement.value.field_to_match.type, "") == "ALL_QUERY_ARGUMENTS" ? [1] : []
                  content {}
                }
              }
              dynamic "text_transformation" {
                for_each = try(xss_match_statement.value.text_transformations, [{ priority = 0, type = "NONE" }])
                content {
                  priority = text_transformation.value.priority
                  type     = text_transformation.value.type
                }
              }
            }
          }
          dynamic "regex_match_statement" {
            for_each = try(not_stmt.value.regex_match, null) != null ? [not_stmt.value.regex_match] : []
            content {
              regex_string = regex_match_statement.value.regex_string
              field_to_match {
                dynamic "uri_path" {
                  for_each = try(regex_match_statement.value.field_to_match.type, "") == "URI_PATH" ? [1] : []
                  content {}
                }
                dynamic "query_string" {
                  for_each = try(regex_match_statement.value.field_to_match.type, "") == "QUERY_STRING" ? [1] : []
                  content {}
                }
                dynamic "body" {
                  for_each = try(regex_match_statement.value.field_to_match.type, "") == "BODY" ? [1] : []
                  content {
                    oversize_handling = try(regex_match_statement.value.field_to_match.oversize_handling, "NO_MATCH")
                  }
                }
                dynamic "single_header" {
                  for_each = try(regex_match_statement.value.field_to_match.type, "") == "SINGLE_HEADER" ? [1] : []
                  content {
                    name = lower(regex_match_statement.value.field_to_match.name)
                  }
                }
                dynamic "all_query_arguments" {
                  for_each = try(regex_match_statement.value.field_to_match.type, "") == "ALL_QUERY_ARGUMENTS" ? [1] : []
                  content {}
                }
              }
              dynamic "text_transformation" {
                for_each = try(regex_match_statement.value.text_transformations, [{ priority = 0, type = "NONE" }])
                content {
                  priority = text_transformation.value.priority
                  type     = text_transformation.value.type
                }
              }
            }
          }
          dynamic "regex_pattern_set_reference_statement" {
            for_each = try(not_stmt.value.regex_pattern_set_reference, null) != null ? [not_stmt.value.regex_pattern_set_reference] : []
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
                dynamic "all_query_arguments" {
                  for_each = try(regex_pattern_set_reference_statement.value.field_to_match.type, "") == "ALL_QUERY_ARGUMENTS" ? [1] : []
                  content {}
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
      }
    }

    ##
    # AND Statement — wraps two or more leaf statements (all must match)
    ##
    dynamic "and_statement" {
      for_each = try(each.value.and_statement, null) != null ? [each.value.and_statement] : []
      iterator = and_stmt
      content {
        dynamic "statement" {
          for_each = and_stmt.value.statements
          iterator = inner
          content {
            dynamic "ip_set_reference_statement" {
              for_each = try(inner.value.ip_set_reference, null) != null ? [inner.value.ip_set_reference] : []
              content {
                arn = try(ip_set_reference_statement.value.ref, null) != null ? aws_wafv2_ip_set.this[ip_set_reference_statement.value.ref].arn : ip_set_reference_statement.value.arn
              }
            }
            dynamic "geo_match_statement" {
              for_each = try(inner.value.geo_match, null) != null ? [inner.value.geo_match] : []
              content {
                country_codes = geo_match_statement.value.country_codes
              }
            }
            dynamic "label_match_statement" {
              for_each = try(inner.value.label_match, null) != null ? [inner.value.label_match] : []
              content {
                scope = label_match_statement.value.scope
                key   = label_match_statement.value.key
              }
            }
            dynamic "asn_match_statement" {
              for_each = try(inner.value.asn_match, null) != null ? [inner.value.asn_match] : []
              content {
                asn_list = asn_match_statement.value.asn_list
              }
            }
            dynamic "rate_based_statement" {
              for_each = try(inner.value.rate_based, null) != null ? [inner.value.rate_based] : []
              content {
                limit                 = rate_based_statement.value.limit
                aggregate_key_type    = try(rate_based_statement.value.aggregate_key_type, "IP")
                evaluation_window_sec = try(rate_based_statement.value.evaluation_window_sec, 300)
              }
            }
            dynamic "byte_match_statement" {
              for_each = try(inner.value.byte_match, null) != null ? [inner.value.byte_match] : []
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
            dynamic "size_constraint_statement" {
              for_each = try(inner.value.size_constraint, null) != null ? [inner.value.size_constraint] : []
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
                  dynamic "all_query_arguments" {
                    for_each = try(size_constraint_statement.value.field_to_match.type, "") == "ALL_QUERY_ARGUMENTS" ? [1] : []
                    content {}
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
            dynamic "sqli_match_statement" {
              for_each = try(inner.value.sqli_match, null) != null ? [inner.value.sqli_match] : []
              content {
                sensitivity_level = try(sqli_match_statement.value.sensitivity_level, "LOW")
                field_to_match {
                  dynamic "uri_path" {
                    for_each = try(sqli_match_statement.value.field_to_match.type, "") == "URI_PATH" ? [1] : []
                    content {}
                  }
                  dynamic "query_string" {
                    for_each = try(sqli_match_statement.value.field_to_match.type, "") == "QUERY_STRING" ? [1] : []
                    content {}
                  }
                  dynamic "body" {
                    for_each = try(sqli_match_statement.value.field_to_match.type, "") == "BODY" ? [1] : []
                    content {
                      oversize_handling = try(sqli_match_statement.value.field_to_match.oversize_handling, "NO_MATCH")
                    }
                  }
                  dynamic "single_header" {
                    for_each = try(sqli_match_statement.value.field_to_match.type, "") == "SINGLE_HEADER" ? [1] : []
                    content {
                      name = lower(sqli_match_statement.value.field_to_match.name)
                    }
                  }
                  dynamic "all_query_arguments" {
                    for_each = try(sqli_match_statement.value.field_to_match.type, "") == "ALL_QUERY_ARGUMENTS" ? [1] : []
                    content {}
                  }
                }
                dynamic "text_transformation" {
                  for_each = try(sqli_match_statement.value.text_transformations, [{ priority = 0, type = "NONE" }])
                  content {
                    priority = text_transformation.value.priority
                    type     = text_transformation.value.type
                  }
                }
              }
            }
            dynamic "xss_match_statement" {
              for_each = try(inner.value.xss_match, null) != null ? [inner.value.xss_match] : []
              content {
                field_to_match {
                  dynamic "uri_path" {
                    for_each = try(xss_match_statement.value.field_to_match.type, "") == "URI_PATH" ? [1] : []
                    content {}
                  }
                  dynamic "query_string" {
                    for_each = try(xss_match_statement.value.field_to_match.type, "") == "QUERY_STRING" ? [1] : []
                    content {}
                  }
                  dynamic "body" {
                    for_each = try(xss_match_statement.value.field_to_match.type, "") == "BODY" ? [1] : []
                    content {
                      oversize_handling = try(xss_match_statement.value.field_to_match.oversize_handling, "NO_MATCH")
                    }
                  }
                  dynamic "single_header" {
                    for_each = try(xss_match_statement.value.field_to_match.type, "") == "SINGLE_HEADER" ? [1] : []
                    content {
                      name = lower(xss_match_statement.value.field_to_match.name)
                    }
                  }
                  dynamic "all_query_arguments" {
                    for_each = try(xss_match_statement.value.field_to_match.type, "") == "ALL_QUERY_ARGUMENTS" ? [1] : []
                    content {}
                  }
                }
                dynamic "text_transformation" {
                  for_each = try(xss_match_statement.value.text_transformations, [{ priority = 0, type = "NONE" }])
                  content {
                    priority = text_transformation.value.priority
                    type     = text_transformation.value.type
                  }
                }
              }
            }
            dynamic "regex_match_statement" {
              for_each = try(inner.value.regex_match, null) != null ? [inner.value.regex_match] : []
              content {
                regex_string = regex_match_statement.value.regex_string
                field_to_match {
                  dynamic "uri_path" {
                    for_each = try(regex_match_statement.value.field_to_match.type, "") == "URI_PATH" ? [1] : []
                    content {}
                  }
                  dynamic "query_string" {
                    for_each = try(regex_match_statement.value.field_to_match.type, "") == "QUERY_STRING" ? [1] : []
                    content {}
                  }
                  dynamic "body" {
                    for_each = try(regex_match_statement.value.field_to_match.type, "") == "BODY" ? [1] : []
                    content {
                      oversize_handling = try(regex_match_statement.value.field_to_match.oversize_handling, "NO_MATCH")
                    }
                  }
                  dynamic "single_header" {
                    for_each = try(regex_match_statement.value.field_to_match.type, "") == "SINGLE_HEADER" ? [1] : []
                    content {
                      name = lower(regex_match_statement.value.field_to_match.name)
                    }
                  }
                  dynamic "all_query_arguments" {
                    for_each = try(regex_match_statement.value.field_to_match.type, "") == "ALL_QUERY_ARGUMENTS" ? [1] : []
                    content {}
                  }
                }
                dynamic "text_transformation" {
                  for_each = try(regex_match_statement.value.text_transformations, [{ priority = 0, type = "NONE" }])
                  content {
                    priority = text_transformation.value.priority
                    type     = text_transformation.value.type
                  }
                }
              }
            }
            dynamic "regex_pattern_set_reference_statement" {
              for_each = try(inner.value.regex_pattern_set_reference, null) != null ? [inner.value.regex_pattern_set_reference] : []
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
                  dynamic "all_query_arguments" {
                    for_each = try(regex_pattern_set_reference_statement.value.field_to_match.type, "") == "ALL_QUERY_ARGUMENTS" ? [1] : []
                    content {}
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
        }
      }
    }

    ##
    # OR Statement — wraps two or more leaf statements (any must match)
    ##
    dynamic "or_statement" {
      for_each = try(each.value.or_statement, null) != null ? [each.value.or_statement] : []
      iterator = or_stmt
      content {
        dynamic "statement" {
          for_each = or_stmt.value.statements
          iterator = inner
          content {
            dynamic "ip_set_reference_statement" {
              for_each = try(inner.value.ip_set_reference, null) != null ? [inner.value.ip_set_reference] : []
              content {
                arn = try(ip_set_reference_statement.value.ref, null) != null ? aws_wafv2_ip_set.this[ip_set_reference_statement.value.ref].arn : ip_set_reference_statement.value.arn
              }
            }
            dynamic "geo_match_statement" {
              for_each = try(inner.value.geo_match, null) != null ? [inner.value.geo_match] : []
              content {
                country_codes = geo_match_statement.value.country_codes
              }
            }
            dynamic "label_match_statement" {
              for_each = try(inner.value.label_match, null) != null ? [inner.value.label_match] : []
              content {
                scope = label_match_statement.value.scope
                key   = label_match_statement.value.key
              }
            }
            dynamic "asn_match_statement" {
              for_each = try(inner.value.asn_match, null) != null ? [inner.value.asn_match] : []
              content {
                asn_list = asn_match_statement.value.asn_list
              }
            }
            dynamic "rate_based_statement" {
              for_each = try(inner.value.rate_based, null) != null ? [inner.value.rate_based] : []
              content {
                limit                 = rate_based_statement.value.limit
                aggregate_key_type    = try(rate_based_statement.value.aggregate_key_type, "IP")
                evaluation_window_sec = try(rate_based_statement.value.evaluation_window_sec, 300)
              }
            }
            dynamic "byte_match_statement" {
              for_each = try(inner.value.byte_match, null) != null ? [inner.value.byte_match] : []
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
            dynamic "size_constraint_statement" {
              for_each = try(inner.value.size_constraint, null) != null ? [inner.value.size_constraint] : []
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
                  dynamic "all_query_arguments" {
                    for_each = try(size_constraint_statement.value.field_to_match.type, "") == "ALL_QUERY_ARGUMENTS" ? [1] : []
                    content {}
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
            dynamic "sqli_match_statement" {
              for_each = try(inner.value.sqli_match, null) != null ? [inner.value.sqli_match] : []
              content {
                sensitivity_level = try(sqli_match_statement.value.sensitivity_level, "LOW")
                field_to_match {
                  dynamic "uri_path" {
                    for_each = try(sqli_match_statement.value.field_to_match.type, "") == "URI_PATH" ? [1] : []
                    content {}
                  }
                  dynamic "query_string" {
                    for_each = try(sqli_match_statement.value.field_to_match.type, "") == "QUERY_STRING" ? [1] : []
                    content {}
                  }
                  dynamic "body" {
                    for_each = try(sqli_match_statement.value.field_to_match.type, "") == "BODY" ? [1] : []
                    content {
                      oversize_handling = try(sqli_match_statement.value.field_to_match.oversize_handling, "NO_MATCH")
                    }
                  }
                  dynamic "single_header" {
                    for_each = try(sqli_match_statement.value.field_to_match.type, "") == "SINGLE_HEADER" ? [1] : []
                    content {
                      name = lower(sqli_match_statement.value.field_to_match.name)
                    }
                  }
                  dynamic "all_query_arguments" {
                    for_each = try(sqli_match_statement.value.field_to_match.type, "") == "ALL_QUERY_ARGUMENTS" ? [1] : []
                    content {}
                  }
                }
                dynamic "text_transformation" {
                  for_each = try(sqli_match_statement.value.text_transformations, [{ priority = 0, type = "NONE" }])
                  content {
                    priority = text_transformation.value.priority
                    type     = text_transformation.value.type
                  }
                }
              }
            }
            dynamic "xss_match_statement" {
              for_each = try(inner.value.xss_match, null) != null ? [inner.value.xss_match] : []
              content {
                field_to_match {
                  dynamic "uri_path" {
                    for_each = try(xss_match_statement.value.field_to_match.type, "") == "URI_PATH" ? [1] : []
                    content {}
                  }
                  dynamic "query_string" {
                    for_each = try(xss_match_statement.value.field_to_match.type, "") == "QUERY_STRING" ? [1] : []
                    content {}
                  }
                  dynamic "body" {
                    for_each = try(xss_match_statement.value.field_to_match.type, "") == "BODY" ? [1] : []
                    content {
                      oversize_handling = try(xss_match_statement.value.field_to_match.oversize_handling, "NO_MATCH")
                    }
                  }
                  dynamic "single_header" {
                    for_each = try(xss_match_statement.value.field_to_match.type, "") == "SINGLE_HEADER" ? [1] : []
                    content {
                      name = lower(xss_match_statement.value.field_to_match.name)
                    }
                  }
                  dynamic "all_query_arguments" {
                    for_each = try(xss_match_statement.value.field_to_match.type, "") == "ALL_QUERY_ARGUMENTS" ? [1] : []
                    content {}
                  }
                }
                dynamic "text_transformation" {
                  for_each = try(xss_match_statement.value.text_transformations, [{ priority = 0, type = "NONE" }])
                  content {
                    priority = text_transformation.value.priority
                    type     = text_transformation.value.type
                  }
                }
              }
            }
            dynamic "regex_match_statement" {
              for_each = try(inner.value.regex_match, null) != null ? [inner.value.regex_match] : []
              content {
                regex_string = regex_match_statement.value.regex_string
                field_to_match {
                  dynamic "uri_path" {
                    for_each = try(regex_match_statement.value.field_to_match.type, "") == "URI_PATH" ? [1] : []
                    content {}
                  }
                  dynamic "query_string" {
                    for_each = try(regex_match_statement.value.field_to_match.type, "") == "QUERY_STRING" ? [1] : []
                    content {}
                  }
                  dynamic "body" {
                    for_each = try(regex_match_statement.value.field_to_match.type, "") == "BODY" ? [1] : []
                    content {
                      oversize_handling = try(regex_match_statement.value.field_to_match.oversize_handling, "NO_MATCH")
                    }
                  }
                  dynamic "single_header" {
                    for_each = try(regex_match_statement.value.field_to_match.type, "") == "SINGLE_HEADER" ? [1] : []
                    content {
                      name = lower(regex_match_statement.value.field_to_match.name)
                    }
                  }
                  dynamic "all_query_arguments" {
                    for_each = try(regex_match_statement.value.field_to_match.type, "") == "ALL_QUERY_ARGUMENTS" ? [1] : []
                    content {}
                  }
                }
                dynamic "text_transformation" {
                  for_each = try(regex_match_statement.value.text_transformations, [{ priority = 0, type = "NONE" }])
                  content {
                    priority = text_transformation.value.priority
                    type     = text_transformation.value.type
                  }
                }
              }
            }
            dynamic "regex_pattern_set_reference_statement" {
              for_each = try(inner.value.regex_pattern_set_reference, null) != null ? [inner.value.regex_pattern_set_reference] : []
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
                  dynamic "all_query_arguments" {
                    for_each = try(regex_pattern_set_reference_statement.value.field_to_match.type, "") == "ALL_QUERY_ARGUMENTS" ? [1] : []
                    content {}
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
        }
      }
    }
  }

  dynamic "captcha_config" {
    for_each = try(each.value.captcha_config, null) != null ? [each.value.captcha_config] : []
    content {
      immunity_time_property {
        immunity_time = captcha_config.value.immunity_time
      }
    }
  }

  dynamic "challenge_config" {
    for_each = try(each.value.challenge_config, null) != null ? [each.value.challenge_config] : []
    content {
      immunity_time_property {
        immunity_time = challenge_config.value.immunity_time
      }
    }
  }

  dynamic "rule_label" {
    for_each = try(each.value.rule_labels, [])
    content {
      name = rule_label.value
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = try(each.value.visibility_config.cloudwatch_metrics_enabled, true)
    metric_name                = try(each.value.visibility_config.metric_name, each.value.name)
    sampled_requests_enabled   = try(each.value.visibility_config.sampled_requests_enabled, true)
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

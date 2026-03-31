##
# (c) 2021-2026
#     Cloud Ops Works LLC - https://cloudops.works/
#     Find us on:
#       GitHub: https://github.com/cloudopsworks
#       WebSite: https://cloudops.works
#     Distributed Under Apache v2.0 License
#

locals {
  # Enforce that exactly one of name or name_prefix is provided.
  # tobool() on a string always errors at plan time, producing a clear message.
  _name_check = (var.name == null && var.name_prefix == null) ? tobool("ERROR: Either 'name' or 'name_prefix' must be provided") : true

  waf_name       = var.name != null ? var.name : format("%s-%s", var.name_prefix, local.system_name)
  waf_scope      = try(var.settings.scope, "REGIONAL")
  default_action = try(var.settings.default_action, "allow")

  managed_rules         = try(var.settings.managed_rules, [])
  rule_group_references = try(var.settings.rule_group_references, [])
  custom_rule_groups    = try(var.settings.rule_groups, [])
  custom_rules          = try(var.settings.custom_rules, [])

  ip_sets              = try(var.settings.ip_sets, [])
  regex_pattern_sets   = try(var.settings.regex_pattern_sets, [])
  api_keys             = try(var.settings.api_keys, [])
  web_acl_associations = try(var.settings.associations, [])

  logging_enabled        = try(var.settings.logging.enabled, false)
  waf_log_retention_days = try(var.settings.logging.retention_in_days, 90)
  logging_destinations = concat(
    local.logging_enabled ? [aws_cloudwatch_log_group.waf_logging[0].arn] : [],
    try(var.settings.logging.destination_arns, [])
  )
}

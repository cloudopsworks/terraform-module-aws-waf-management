##
# (c) 2021-2026
#     Cloud Ops Works LLC - https://cloudops.works/
#     Find us on:
#       GitHub: https://github.com/cloudopsworks
#       WebSite: https://cloudops.works
#     Distributed Under Apache v2.0 License
#

##
# WAFv2 CloudWatch Log Group
# Created automatically when settings.logging.enabled = true.
# AWS WAF requires the log group name to begin with "aws-waf-logs-".
# The ARN of this group is automatically included in the logging configuration
# alongside any additional destination_arns provided in settings.logging.
##
resource "aws_cloudwatch_log_group" "waf_logging" {
  count             = local.logging_enabled ? 1 : 0
  name              = format("aws-waf-logs-%s", local.waf_name)
  retention_in_days = local.waf_log_retention_days
  kms_key_id        = try(var.settings.logging.kms_key_id, null)
  tags              = local.all_tags
}

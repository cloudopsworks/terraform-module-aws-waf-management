##
# (c) 2021-2026
#     Cloud Ops Works LLC - https://cloudops.works/
#     Find us on:
#       GitHub: https://github.com/cloudopsworks
#       WebSite: https://cloudops.works
#     Distributed Under Apache v2.0 License
#

output "web_acl_arn" {
  description = "ARN of the WAFv2 Web ACL"
  value       = aws_wafv2_web_acl.this.arn
}

output "web_acl_id" {
  description = "ID of the WAFv2 Web ACL"
  value       = aws_wafv2_web_acl.this.id
}

output "web_acl_name" {
  description = "Name of the WAFv2 Web ACL"
  value       = aws_wafv2_web_acl.this.name
}

output "web_acl_capacity" {
  description = "Current WAF capacity units (WCU) consumed by the Web ACL"
  value       = aws_wafv2_web_acl.this.capacity
}

output "rule_group_arns" {
  description = "Map of custom rule group names to their ARNs (only groups created by this module)"
  value       = { for k, v in aws_wafv2_rule_group.this : k => v.arn }
}

output "rule_group_ids" {
  description = "Map of custom rule group names to their IDs"
  value       = { for k, v in aws_wafv2_rule_group.this : k => v.id }
}

output "ip_set_arns" {
  description = "Map of IP set names to their ARNs (only sets created by this module)"
  value       = { for k, v in aws_wafv2_ip_set.this : k => v.arn }
}

output "ip_set_ids" {
  description = "Map of IP set names to their IDs"
  value       = { for k, v in aws_wafv2_ip_set.this : k => v.id }
}

output "regex_pattern_set_arns" {
  description = "Map of regex pattern set names to their ARNs (only sets created by this module)"
  value       = { for k, v in aws_wafv2_regex_pattern_set.this : k => v.arn }
}

output "regex_pattern_set_ids" {
  description = "Map of regex pattern set names to their IDs"
  value       = { for k, v in aws_wafv2_regex_pattern_set.this : k => v.id }
}

output "api_key_values" {
  description = "Map of API key names to their generated key values (sensitive — used with the WAFv2 mobile SDK)"
  sensitive   = true
  value       = { for k, v in aws_wafv2_api_key.this : k => v.api_key }
}

output "web_acl_association_ids" {
  description = "Map of protected resource ARNs to their Web ACL association IDs"
  value       = { for k, v in aws_wafv2_web_acl_association.this : k => v.id }
}

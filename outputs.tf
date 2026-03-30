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

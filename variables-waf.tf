##
# (c) 2021-2026
#     Cloud Ops Works LLC - https://cloudops.works/
#     Find us on:
#       GitHub: https://github.com/cloudopsworks
#       WebSite: https://cloudops.works
#     Distributed Under Apache v2.0 License
#

# name: "my-waf-acl"   # (Required if name_prefix not set) Explicit name for the WAF ACL.
variable "name" {
  description = "Explicit name for the WAF ACL. Required when name_prefix is not set."
  type        = string
  default     = null
}

# name_prefix: "proj"  # (Required if name not set) Prefix prepended to system_name to form
#                      #   the ACL name: "<name_prefix>-<system_name>".
variable "name_prefix" {
  description = "Name prefix prepended to system_name to form the WAF ACL name (<name_prefix>-<system_name>). Required when name is not set."
  type        = string
  default     = null
}

# settings:                                  # (Optional) WAF module settings. Default: {}
#
# ── Top-level ACL settings ────────────────────────────────────────────────────
#   description: "My WAF ACL"               # (Optional) Human-readable description of the ACL.
#   scope: "REGIONAL"                        # (Required) Scope: REGIONAL | CLOUDFRONT.
#   default_action: "allow"                  # (Optional) Default action when no rule matches: allow | block. Default: allow.
#
# ── Top-level visibility config ───────────────────────────────────────────────
#   visibility_config:
#     cloudwatch_metrics_enabled: true       # (Optional) Publish CloudWatch metrics. Default: true.
#     metric_name: "my-waf-acl"             # (Optional) CloudWatch metric name. Default: ACL name.
#     sampled_requests_enabled: true         # (Optional) Store a sample of matched requests. Default: true.
#
# ── IP Sets (created by this module) ──────────────────────────────────────────
#   ip_sets:
#     - name: "blocked-ips"                  # (Required) Module-internal key; also used as name suffix: "<acl-name>-<name>".
#       ip_address_version: "IPV4"           # (Required) IP version: IPV4 | IPV6.
#       addresses:                           # (Optional) List of CIDR blocks. Default: [].
#         - "203.0.113.0/24"                 #   IPv4 CIDR (when ip_address_version = IPV4).
#         - "2001:db8::/32"                  #   IPv6 CIDR (when ip_address_version = IPV6).
#       description: "Blocked IP ranges"     # (Optional) Human-readable description.
#
#   Reference in rules (choose arn or ref — not both):
#     ip_set_reference:
#       arn: "arn:aws:wafv2:..."             #   (Option A) Literal ARN of any existing ip set.
#     ip_set_reference:
#       ref: "blocked-ips"                   #   (Option B) Name of a module-managed ip set (settings.ip_sets[name]).
#
# ── Regex Pattern Sets (created by this module) ───────────────────────────────
#   regex_pattern_sets:
#     - name: "bad-paths"                    # (Required) Module-internal key; name suffix: "<acl-name>-<name>".
#       patterns:                            # (Required) List of regex strings.
#         - "^/admin/.*"                     #   (Required) PCRE-compatible regex.
#         - "^/wp-.*"
#       description: "Malicious path patterns" # (Optional) Human-readable description.
#
#   Reference in rules (choose arn or ref — not both):
#     regex_pattern_set_reference:
#       arn: "arn:aws:wafv2:..."             #   (Option A) Literal ARN of any existing regex pattern set.
#     regex_pattern_set_reference:
#       ref: "bad-paths"                     #   (Option B) Name of a module-managed set (settings.regex_pattern_sets[name]).
#
# ── API Keys (mobile SDK token domain integration) ────────────────────────────
#   api_keys:
#     - name: "mobile-app"                   # (Required) Module-internal label (used as for_each key).
#       token_domains:                       # (Required) Fully qualified domain names for token validation.
#         - "app.example.com"
#         - "api.example.com"
#
# ── Web ACL Associations ──────────────────────────────────────────────────────
#   associations:
#     - resource_arn: "arn:aws:elasticloadbalancing:..." # (Required) ARN of the protected resource.
#                                            #   Supported: ALB, API Gateway stage, AppSync GraphQL API,
#                                            #   Cognito User Pool, App Runner service, Verified Access instance.
#                                            #   Note: CLOUDFRONT-scoped ACLs cannot use associations here —
#                                            #   attach via the CloudFront distribution instead.
#
# ── AWS Managed Rule Groups ───────────────────────────────────────────────────
#   managed_rules:
#     - name: "AWSManagedRulesCommonRuleSet" # (Required) AWS managed rule group name.
#       priority: 10                         # (Required) Evaluation priority — unique across all rules in the ACL, lower = first.
#       vendor_name: "AWS"                   # (Optional) Vendor name. Default: AWS.
#       override_action: "none"              # (Optional) Override action: none (enforce) | count (monitor). Default: none.
#       version: null                        # (Optional) Managed rule group version. Default: latest.
#       excluded_rules:                      # (Optional) Rule names to override to count action.
#         - "SizeRestrictions_BODY"          #   (Optional) Rule name.
#       managed_rule_group_configs:          # (Optional) Special config required for BotControl and ATP rule groups.
#         - bot_control:                     # (Optional) AWS BotControl config.
#             inspection_level: "COMMON"     #   (Required) Inspection level: COMMON | TARGETED.
#         - atp:                             # (Optional) Account Takeover Protection config.
#             login_path: "/login"           #   (Required) Login endpoint path evaluated for credential theft.
#       visibility_config:                   # (Optional) Per-rule visibility config (inherits ACL defaults).
#         cloudwatch_metrics_enabled: true   #   (Optional) Default: true.
#         metric_name: "rule-name"           #   (Optional) Default: rule name.
#         sampled_requests_enabled: true     #   (Optional) Default: true.
#
# ── External Rule Group References ────────────────────────────────────────────
#   rule_group_references:
#     - name: "shared-ip-allowlist"         # (Required) Label used as the rule name in the ACL.
#       priority: 5                          # (Required) Evaluation priority — must be unique across all ACL rules.
#       arn: "arn:aws:wafv2:..."             # (Option A) Literal ARN of a pre-existing WAFv2 rule group.
#       ref: "ip-controls"                   # (Option B) Name of a module-managed rule group (settings.rule_groups[name]).
#                                            #   Provide arn OR ref — not both.
#       override_action: "none"              # (Optional) none | count. Default: none.
#       excluded_rules:                      # (Optional) Rule names within the group to override to count.
#         - "RuleName"
#       visibility_config:                   # (Optional) Per-rule visibility config.
#         cloudwatch_metrics_enabled: true
#         metric_name: "shared-ip-allowlist"
#         sampled_requests_enabled: true
#
# ── Custom Rule Groups (created by this module) ───────────────────────────────
#   rule_groups:
#     - name: "ip-controls"                 # (Required) Name suffix appended to the ACL name: "<acl-name>-<name>".
#       priority: 60                         # (Required) Evaluation priority in the ACL.
#       capacity: 100                        # (Required) WAF Capacity Units (WCU) reserved for the group (10–5000).
#       description: "IP controls"           # (Optional) Human-readable description of the rule group.
#       override_action: "none"              # (Optional) none | count for the ACL reference. Default: none.
#       visibility_config:                   # (Optional) Rule group-level visibility config.
#         cloudwatch_metrics_enabled: true
#         metric_name: "ip-controls"
#         sampled_requests_enabled: true
#       rules:                               # (Optional) Rules inside this rule group. Exactly one statement per rule.
#         - name: "block-bad-ips"           # (Required) Rule name — unique within the group.
#           priority: 1                      # (Required) Rule priority within the group.
#           action: "block"                  # (Required) Rule action: allow | block | count | captcha.
#           visibility_config:               # (Optional) Per-rule visibility config.
#             cloudwatch_metrics_enabled: true
#             metric_name: "block-bad-ips"
#             sampled_requests_enabled: true
#
#           # ── Statement types — exactly one must be set per rule ────────────
#
#           ip_set_reference:                # (Optional) Matches requests from IPs in an IP set.
#             arn: "arn:aws:wafv2:..."       #   (Option A) Literal ARN of any existing ip set.
#             ref: "blocked-ips"             #   (Option B) Name of a module-managed ip set (settings.ip_sets[name]).
#                                            #   Provide arn OR ref — not both.
#
#           geo_match:                       # (Optional) Matches requests originating from specific countries.
#             country_codes: ["US", "CA"]    #   (Required) ISO 3166-1 alpha-2 country codes.
#
#           rate_based:                      # (Optional) Triggers when a source exceeds a request rate threshold.
#             limit: 2000                    #   (Required) Max requests per evaluation window (100–2000000000).
#             aggregate_key_type: "IP"       #   (Optional) Aggregation key: IP | FORWARDED_IP. Default: IP.
#             evaluation_window_sec: 300     #   (Optional) Rolling window in seconds (60|120|300|600). Default: 300.
#
#           byte_match:                      # (Optional) Matches a string at a specific position in a field.
#             search_string: "badbot"        #   (Required) Literal string to search for.
#             positional_constraint: "CONTAINS" # (Required) EXACTLY | STARTS_WITH | ENDS_WITH | CONTAINS | CONTAINS_WORD.
#             field_to_match:               #   (Required) Request component to inspect.
#               type: "URI_PATH"            #     (Required) URI_PATH | QUERY_STRING | METHOD | BODY |
#                                           #       ALL_QUERY_ARGUMENTS | SINGLE_HEADER | SINGLE_QUERY_ARGUMENT.
#               name: null                  #     (Optional) Header or argument name — required for SINGLE_* types.
#               oversize_handling: "NO_MATCH" # (Optional) For BODY only: NO_MATCH | MATCH | CONTINUE.
#             text_transformations:         #   (Optional) Ordered transformations applied before matching.
#               - priority: 0              #     (Required) Transformation order — lower = applied first.
#                 type: "LOWERCASE"        #     (Required) NONE | LOWERCASE | URL_DECODE | HTML_ENTITY_DECODE |
#                                          #       COMPRESS_WHITE_SPACE | CMD_LINE.
#
#           size_constraint:               # (Optional) Matches requests where a field's size meets a condition.
#             comparison_operator: "GT"    #   (Required) EQ | NE | LE | LT | GE | GT.
#             size: 8192                   #   (Required) Threshold size in bytes.
#             field_to_match:             #   (Required) Same field types as byte_match.
#               type: "BODY"
#               oversize_handling: "CONTINUE"
#             text_transformations:
#               - priority: 0
#                 type: "NONE"
#
#           regex_pattern_set_reference:   # (Optional) Matches a field against patterns in a regex pattern set.
#             arn: "arn:aws:wafv2:..."     #   (Option A) Literal ARN of any existing regex pattern set.
#             ref: "bad-paths"             #   (Option B) Name of a module-managed set (settings.regex_pattern_sets[name]).
#                                          #   Provide arn OR ref — not both.
#             field_to_match:             #   (Required) Same field types as byte_match.
#               type: "URI_PATH"
#             text_transformations:
#               - priority: 0
#                 type: "LOWERCASE"
#
# ── Logging ───────────────────────────────────────────────────────────────────
#   logging:
#     enabled: true                          # (Optional) Enable WAF logging. Default: false.
#     destination_arns:                      # (Required when enabled) One or more log destination ARNs.
#       - "arn:aws:firehose:..."             #   Kinesis Data Firehose stream name must start with "aws-waf-logs-".
#                                            #   S3 bucket and CloudWatch Logs log group ARNs also accepted.
#     redacted_fields:                       # (Optional) Fields to omit from stored log records.
#       - type: "URI_PATH"                   #   (Required) URI_PATH | QUERY_STRING | METHOD | SINGLE_HEADER.
#         name: null                         #   (Optional) Header name — required only for SINGLE_HEADER type.
#     filter:                                # (Optional) Controls which requests are forwarded to the log destination.
#       default_behavior: "DROP"             #   (Required) Behavior for requests that match no filter: KEEP | DROP.
#       filters:                             #   (Required) Ordered list of filter rules.
#         - behavior: "KEEP"                 #     (Required) Outcome for matching requests: KEEP | DROP.
#           requirement: "MEETS_ANY"         #     (Required) Combine conditions with OR (MEETS_ANY) or AND (MEETS_ALL).
#           conditions:                      #     (Required) List of match conditions.
#             - action_condition: "BLOCK"    #       (Optional) Match on WAF action: ALLOW | BLOCK | COUNT.
#             - label_name_condition: "awswaf:managed:aws:core-rule-set:NoUserAgent_Header"
#                                            #       (Optional) Match on a label name (exact or prefix pattern).
variable "settings" {
  description = "WAF module settings — controls ACL scope/default-action, IP sets, regex pattern sets, API keys, associations, AWS managed rules, rule group references, custom rule groups, and logging."
  type        = any
  default     = {}
}

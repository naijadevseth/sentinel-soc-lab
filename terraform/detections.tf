# =============================================================================
# Sentinel SOC Lab - Phase 3: detection rules as code
#
# Each rule's KQL lives in ../detections/<name>.kql (one file per rule, with
# a header explaining what it catches and how to triage it). This file
# deploys them to Sentinel as scheduled analytics rules: every 5 minutes
# Sentinel runs the query, and any result becomes an alert and an incident.
# =============================================================================

locals {
  # Reusable entity mappings. Entities tell Sentinel WHICH user, IP or host an
  # alert is about, so incidents can be linked and investigated by entity.
  host_entity = { type = "Host", identifier = "HostName", column = "Computer" }

  detections = {
    "win-brute-force" = {
      display_name = "Windows: possible brute-force logon (5+ failures)"
      description  = "One source failed to log on to the same Windows account 5 or more times in 15 minutes."
      severity     = "Medium"
      period       = "PT15M"
      tactics      = ["CredentialAccess"]
      techniques   = ["T1110"]
      entities = [
        { type = "Account", identifier = "FullName", column = "TargetAccount" },
        { type = "IP", identifier = "Address", column = "IpAddress" },
        local.host_entity,
      ]
    }

    "win-new-local-user" = {
      display_name = "Windows: new local user account created"
      description  = "A new local account was created on a monitored Windows server."
      severity     = "Medium"
      period       = "PT5M"
      tactics      = ["Persistence"]
      techniques   = ["T1136"]
      entities = [
        { type = "Account", identifier = "FullName", column = "CreatedBy" },
        local.host_entity,
      ]
    }

    "win-admin-group-add" = {
      display_name = "Windows: member added to local Administrators"
      description  = "An account was added to the built-in Administrators group (SID S-1-5-32-544)."
      severity     = "High"
      period       = "PT5M"
      tactics      = ["PrivilegeEscalation", "Persistence"]
      techniques   = ["T1098"]
      entities = [
        { type = "Account", identifier = "FullName", column = "AddedBy" },
        { type = "Account", identifier = "Sid", column = "MemberSid" },
        local.host_entity,
      ]
    }

    "win-security-log-cleared" = {
      display_name = "Windows: Security event log cleared"
      description  = "The Windows Security log was cleared, which destroys local evidence."
      severity     = "High"
      period       = "PT5M"
      tactics      = ["DefenseEvasion"]
      techniques   = ["T1070"]
      entities = [
        { type = "Account", identifier = "FullName", column = "Account" },
        local.host_entity,
      ]
    }

    "linux-ssh-failed-logins" = {
      display_name = "Linux: repeated failed SSH logins (5+ from one IP)"
      description  = "One source IP failed to authenticate over SSH 5 or more times in 15 minutes."
      severity     = "Medium"
      period       = "PT15M"
      tactics      = ["CredentialAccess"]
      techniques   = ["T1110"]
      entities = [
        { type = "IP", identifier = "Address", column = "SourceIP" },
        local.host_entity,
      ]
    }

    "azure-nsg-change" = {
      display_name = "Azure: network security group changed"
      description  = "A network security group (cloud firewall) or one of its rules was created, changed or deleted."
      severity     = "Medium"
      period       = "PT5M"
      tactics      = ["DefenseEvasion"]
      techniques   = ["T1562"]
      entities = [
        { type = "Account", identifier = "FullName", column = "Caller" },
        { type = "IP", identifier = "Address", column = "CallerIpAddress" },
      ]
    }

    "azure-role-assignment" = {
      display_name = "Azure: new role assignment"
      description  = "Permissions were granted to an identity by creating an Azure role assignment."
      severity     = "Medium"
      period       = "PT5M"
      tactics      = ["Persistence", "PrivilegeEscalation"]
      techniques   = ["T1098"]
      entities = [
        { type = "Account", identifier = "FullName", column = "Caller" },
        { type = "IP", identifier = "Address", column = "CallerIpAddress" },
      ]
    }
  }
}

resource "azurerm_sentinel_alert_rule_scheduled" "detections" {
  for_each = local.detections

  name = each.key
  # Referencing the onboarding resource (not the workspace directly) makes
  # Terraform wait until Sentinel is switched on before creating rules.
  log_analytics_workspace_id = azurerm_sentinel_log_analytics_workspace_onboarding.soc.workspace_id

  display_name = each.value.display_name
  description  = each.value.description
  severity     = each.value.severity
  query        = file("${path.module}/../detections/${each.key}.kql")

  query_frequency   = "PT5M"            # run every 5 minutes
  query_period      = each.value.period # look back over this window
  trigger_operator  = "GreaterThan"
  trigger_threshold = 0 # any result = alert (thresholds live inside the KQL)

  tactics    = each.value.tactics
  techniques = each.value.techniques

  dynamic "entity_mapping" {
    for_each = each.value.entities
    content {
      entity_type = entity_mapping.value.type
      field_mapping {
        identifier  = entity_mapping.value.identifier
        column_name = entity_mapping.value.column
      }
    }
  }
}

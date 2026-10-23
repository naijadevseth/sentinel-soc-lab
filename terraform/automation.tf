# =============================================================================
# Sentinel SOC Lab - Phase 5: automation (SOAR)
#
# 1. Automation rule: every new High-severity incident is assigned to me and
#    tagged, so nothing serious sits unowned in the queue.
# 2. Email notification: Azure Monitor checks the SecurityIncident table every
#    5 minutes and emails me when a new High incident appears.
#
# Why Azure Monitor instead of a Logic App email playbook: the Outlook / Gmail
# Logic App connectors need a Microsoft 365 or Outlook.com mailbox, which this
# lab's Gmail-based Microsoft account doesn't have. An action group can email
# any address and needs no connector.
# =============================================================================

# The identity Terraform is running as (my Azure account via `az login`).
data "azurerm_client_config" "current" {}

# -----------------------------------------------------------------------------
# 1. Auto-triage High incidents
# -----------------------------------------------------------------------------

resource "azurerm_sentinel_automation_rule" "auto_triage_high" {
  # Sentinel requires automation rule names to be GUIDs. A fixed one keeps
  # Terraform from recreating the rule on every apply.
  name                       = "0e9a5dc5-3c37-475a-8d43-9ff51e11689c"
  log_analytics_workspace_id = azurerm_sentinel_log_analytics_workspace_onboarding.soc.workspace_id
  display_name               = "Auto-triage High severity incidents"
  order                      = 1
  triggers_on                = "Incidents"
  triggers_when              = "Created"

  condition_json = jsonencode([
    {
      conditionType = "Property"
      conditionProperties = {
        propertyName   = "IncidentSeverity"
        operator       = "Equals"
        propertyValues = ["High"]
      }
    }
  ])

  action_incident {
    order    = 1
    owner_id = data.azurerm_client_config.current.object_id
    labels   = ["auto-triaged", "priority-high"]
  }
}

# -----------------------------------------------------------------------------
# 2. Email me when a High incident is created
# -----------------------------------------------------------------------------

resource "azurerm_monitor_action_group" "soc_email" {
  name                = "ag-soc-lab-email"
  resource_group_name = azurerm_resource_group.lab.name
  short_name          = "soclab" # max 12 characters, shown in the email
  tags                = local.tags

  email_receiver {
    name                    = "soc-analyst"
    email_address           = var.alert_email
    use_common_alert_schema = true
  }
}

resource "azurerm_monitor_scheduled_query_rules_alert_v2" "high_incident_email" {
  name                = "alert-new-high-incident"
  display_name        = "Sentinel: new High severity incident"
  description         = "Emails the SOC analyst when Sentinel creates a High severity incident."
  resource_group_name = azurerm_resource_group.lab.name
  location            = azurerm_resource_group.lab.location
  scopes              = [azurerm_log_analytics_workspace.soc.id]
  severity            = 1 # Azure Monitor scale: 0 = critical ... 4 = verbose

  evaluation_frequency = "PT5M"
  window_duration      = "PT5M"

  criteria {
    # SecurityIncident gets a new row every time an incident changes (created,
    # assigned, closed...). arg_max keeps the latest row per incident, and the
    # CreatedTime filter makes sure each incident emails once, at creation.
    query = <<-KQL
      SecurityIncident
      | where Severity == "High"
      | summarize arg_max(TimeGenerated, *) by IncidentNumber
      | where CreatedTime > ago(5m)
      | project IncidentNumber, Title, Severity, Status, CreatedTime
    KQL

    time_aggregation_method = "Count"
    operator                = "GreaterThan"
    threshold               = 0

    failing_periods {
      minimum_failing_periods_to_trigger_alert = 1
      number_of_evaluation_periods             = 1
    }
  }

  action {
    action_groups = [azurerm_monitor_action_group.soc_email.id]
  }

  tags = local.tags
}

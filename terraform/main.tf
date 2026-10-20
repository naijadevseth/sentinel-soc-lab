# =============================================================================
# Sentinel SOC Lab - Phase 1a: SIEM foundation
#
# Builds the log database (Log Analytics workspace), turns Microsoft Sentinel
# on for it, and streams the subscription's Azure Activity log into it.
# Virtual machines are added in Phase 1b.
# =============================================================================

terraform {
  required_version = ">= 1.6"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }
  }
}

provider "azurerm" {
  features {}

  subscription_id = var.subscription_id

  # The six resource providers this lab needs were registered by hand with
  # `az provider register`. "none" stops Terraform trying to register dozens
  # of other providers the lab never uses.
  resource_provider_registrations = "none"
}

# -----------------------------------------------------------------------------
# Variables
# -----------------------------------------------------------------------------

variable "subscription_id" {
  description = "Azure subscription to deploy into (set in terraform.tfvars, which Git ignores)"
  type        = string
}

variable "location" {
  description = "Azure region. Student subscriptions only allow a few regions."
  type        = string
  default     = "francecentral"
}

locals {
  tags = {
    project     = "sentinel-soc-lab"
    environment = "lab"
    owner       = "seth-owolabi"
  }
}

# -----------------------------------------------------------------------------
# Resource group: one container for everything, so teardown is one step
# -----------------------------------------------------------------------------

resource "azurerm_resource_group" "lab" {
  name     = "rg-sentinel-soc-lab"
  location = var.location
  tags     = local.tags
}

# -----------------------------------------------------------------------------
# Log Analytics workspace: the database every log lands in
# -----------------------------------------------------------------------------

resource "azurerm_log_analytics_workspace" "soc" {
  name                = "law-sentinel-soc-lab"
  location            = azurerm_resource_group.lab.location
  resource_group_name = azurerm_resource_group.lab.name

  sku               = "PerGB2018" # pay-per-GB, the only plan Sentinel supports
  retention_in_days = 90          # Sentinel includes 90 days of retention at no extra cost

  # Guardrail: stop ingesting after 1 GB per day. A misconfigured log source
  # can't silently drain the credit. The Sentinel trial covers 10 GB/day free.
  daily_quota_gb = 1

  tags = local.tags
}

# -----------------------------------------------------------------------------
# Microsoft Sentinel: turn the workspace into a SIEM
# -----------------------------------------------------------------------------

resource "azurerm_sentinel_log_analytics_workspace_onboarding" "soc" {
  workspace_id = azurerm_log_analytics_workspace.soc.id
}

# -----------------------------------------------------------------------------
# Azure Activity log -> workspace
# Records every control-plane action in the subscription: who created, changed
# or deleted what. Free to ingest into Sentinel. Detections in Phase 3 use it
# to catch risky changes such as opening firewall ports or granting roles.
# -----------------------------------------------------------------------------

resource "azurerm_monitor_diagnostic_setting" "activity_log" {
  name                       = "activity-log-to-sentinel"
  target_resource_id         = "/subscriptions/${var.subscription_id}"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.soc.id

  enabled_log { category = "Administrative" } # create / update / delete operations
  enabled_log { category = "Security" }       # Defender for Cloud alerts
  enabled_log { category = "Policy" }         # Azure Policy decisions (e.g. blocked regions)
  enabled_log { category = "Alert" }          # Azure Monitor alerts firing
}

# -----------------------------------------------------------------------------
# Outputs
# -----------------------------------------------------------------------------

output "resource_group" {
  value = azurerm_resource_group.lab.name
}

output "workspace_name" {
  value = azurerm_log_analytics_workspace.soc.name
}

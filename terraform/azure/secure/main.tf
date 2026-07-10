# Hardened baseline, Azure side.

terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
  }
}

provider "azurerm" {
  features {}
}

resource "azurerm_resource_group" "demo" {
  name     = "aegis-demo-rg"
  location = "East US"

  tags = {
    Project = "aegispipeline"
    Env     = "demo"
  }
}

resource "azurerm_storage_account" "artifacts" {
  name                            = "aegisdemosecure01"
  resource_group_name             = azurerm_resource_group.demo.name
  location                        = azurerm_resource_group.demo.location
  account_tier                    = "Standard"
  account_replication_type        = "LRS"
  allow_nested_items_to_be_public = false
  https_traffic_only_enabled      = true
  min_tls_version                 = "TLS1_2"

  blob_properties {
    delete_retention_policy {
      days = 7
    }
  }

  tags = {
    Project = "aegispipeline"
    Env     = "demo"
  }
}

variable "admin_source_prefix" {
  description = "Source prefix allowed to reach RDP, e.g. x.x.x.x/32"
  type        = string
  default     = "203.0.113.10/32"
}

resource "azurerm_network_security_group" "training" {
  name                = "aegis-demo-nsg"
  location            = azurerm_resource_group.demo.location
  resource_group_name = azurerm_resource_group.demo.name

  security_rule {
    name                       = "allow-rdp-admin-only"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "3389"
    source_address_prefix      = var.admin_source_prefix
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "deny-all-inbound"
    priority                   = 4096
    direction                  = "Inbound"
    access                     = "Deny"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  tags = {
    Project = "aegispipeline"
    Env     = "demo"
  }
}

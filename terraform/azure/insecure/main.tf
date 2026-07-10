# Intentionally misconfigured. Test fixtures for the CI gate. Do not deploy.

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
  name     = "aegis-demo-rg-insecure"
  location = "East US"

  tags = {
    Project = "aegispipeline"
    Env     = "demo"
  }
}

# public blob access, no https enforcement, old TLS
resource "azurerm_storage_account" "artifacts" {
  name                            = "aegisdemoinsecure01"
  resource_group_name             = azurerm_resource_group.demo.name
  location                        = azurerm_resource_group.demo.location
  account_tier                    = "Standard"
  account_replication_type        = "LRS"
  allow_nested_items_to_be_public = true
  https_traffic_only_enabled      = false
  min_tls_version                 = "TLS1_0"

  tags = {
    Project = "aegispipeline"
    Env     = "demo"
  }
}

# rdp open to the internet
resource "azurerm_network_security_group" "training" {
  name                = "aegis-demo-nsg-insecure"
  location            = azurerm_resource_group.demo.location
  resource_group_name = azurerm_resource_group.demo.name

  security_rule {
    name                       = "allow-rdp-anywhere"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "3389"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  tags = {
    Project = "aegispipeline"
    Env     = "demo"
  }
}

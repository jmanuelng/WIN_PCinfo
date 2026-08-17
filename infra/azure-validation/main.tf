locals {
  # Tags stay non-sensitive. The threat is putting a tenant, subscription,
  # device, or network identifier into a tag that later appears in a public
  # screenshot. The mechanism is a closed set of generic keys. The trust
  # assumption is that RoundCorrelation is a short opaque token supplied only
  # in the private workspace. Safe failure is admission rejection before
  # rendering when a tag is missing or identifier-like.
  governance_tags = {
    Purpose          = var.purpose_tag
    Environment      = var.environment_tag
    Lifecycle        = var.lifecycle_tag
    ManagingTool     = var.managing_tool_tag
    RoundCorrelation = var.round_correlation_tag
    CreatedUtc       = var.created_utc_tag
    ExpiresUtc       = var.expires_utc_tag
  }
}

resource "azurerm_resource_group" "round" {
  name     = var.resource_group_name
  location = var.location
  tags     = local.governance_tags

  lifecycle {
    precondition {
      condition     = var.client_count == length(var.clients)
      error_message = "client_count must match the admitted clients list."
    }
  }
}

module "round_network" {
  source = "./modules/round-network"

  location                 = var.location
  resource_group_name      = azurerm_resource_group.round.name
  host_vnet_id             = var.host_vnet_id
  host_vnet_name           = var.host_vnet_name
  host_resource_group_name = var.host_resource_group_name
  nat_public_ip_sku        = var.nat_public_ip_sku
  allow_gateway_transit    = var.allow_gateway_transit
  allow_forwarded_traffic  = var.allow_forwarded_traffic
  use_remote_gateways      = var.use_remote_gateways
  tags                     = local.governance_tags
}

module "validation_clients" {
  source = "./modules/validation-client"
  count  = length(var.clients)

  location                   = var.location
  resource_group_name        = azurerm_resource_group.round.name
  subnet_id                  = module.round_network.subnet_id
  approved_gallery_image_id  = var.approved_gallery_image_id
  os_disk_storage_type       = var.os_disk_storage_type
  assign_vm_public_ip        = var.assign_vm_public_ip
  temporary_admin_username   = var.temporary_admin_username
  temporary_admin_password   = var.temporary_admin_password
  client_index               = count.index
  vm_sku                     = var.clients[count.index].sku
  claiming                   = var.clients[count.index].claiming
  security_type              = var.clients[count.index].security_type
  secure_boot                = var.clients[count.index].secure_boot
  vtpm                       = var.clients[count.index].vtpm
  tags                       = local.governance_tags
}

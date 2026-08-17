variable "location" {
  type = string
}

variable "resource_group_name" {
  type = string
}

variable "host_vnet_id" {
  type      = string
  sensitive = true
}

variable "host_vnet_name" {
  type        = string
  description = "Placeholder host VNet name used only to create the host-side peering object."
}

variable "host_resource_group_name" {
  type        = string
  description = "Placeholder host resource group used only to create the host-side peering object."
}

variable "nat_public_ip_sku" {
  type = string
}

variable "allow_gateway_transit" {
  type = bool
}

variable "allow_forwarded_traffic" {
  type = bool
}

variable "use_remote_gateways" {
  type = bool
}

variable "tags" {
  type = map(string)
}

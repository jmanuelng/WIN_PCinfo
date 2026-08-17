variable "location" {
  type        = string
  description = "Placeholder Azure region. Supply a real value only in a private workspace."
}

variable "resource_group_name" {
  type        = string
  description = "Placeholder validation resource group. Never commit a real name."
}

variable "host_vnet_id" {
  type        = string
  sensitive   = true
  description = "Placeholder host VNet resource ID used only for non-transitive peering."
}

variable "host_vnet_name" {
  type        = string
  description = "Placeholder host VNet name. Supply a real value only in a private workspace."
}

variable "host_resource_group_name" {
  type        = string
  description = "Placeholder host resource-group name. Supply a real value only in a private workspace."
}

variable "approved_gallery_image_id" {
  type        = string
  sensitive   = true
  description = "Placeholder approved gallery image ID. Public examples use {{APPROVED_GALLERY_IMAGE_ID}}."
}

variable "temporary_admin_username" {
  type        = string
  default     = "valiadmin"
  description = "Local administrator name used only if a later ticket applies this template."
}

variable "temporary_admin_password" {
  type        = string
  sensitive   = true
  description = "Placeholder password. Never commit a real secret; public examples use {{TEMPORARY_ADMIN_PASSWORD}}."
}

variable "client_count" {
  type        = number
  description = "Number of allowlisted small clients in this round, from 1 to 4."

  validation {
    condition     = var.client_count >= 1 && var.client_count <= 4
    error_message = "A validation round may create only one to four clients."
  }
}

variable "maximum_lifetime_minutes" {
  type        = number
  description = "Creation-to-deletion lifetime including the cleanup reserve, at most 360 minutes."

  validation {
    condition     = var.maximum_lifetime_minutes >= 31 && var.maximum_lifetime_minutes <= 360
    error_message = "The round lifetime must stay inside the six-hour ceiling."
  }
}

variable "cleanup_reserve_minutes" {
  type        = number
  description = "Minutes reserved at the end of the lifetime for verified teardown."

  validation {
    condition     = var.cleanup_reserve_minutes >= 30
    error_message = "Cleanup reserve is mandatory and must be at least 30 minutes."
  }
}

variable "nat_public_ip_sku" {
  type        = string
  default     = "Standard"
  description = "SKU of the NAT public IP. Only Standard is admitted."

  validation {
    condition     = var.nat_public_ip_sku == "Standard"
    error_message = "NAT egress must use a Standard public IP."
  }
}

variable "os_disk_storage_type" {
  type        = string
  default     = "StandardSSD_LRS"
  description = "OS disk type. Only Standard SSD is admitted."

  validation {
    condition     = var.os_disk_storage_type == "StandardSSD_LRS"
    error_message = "Validation clients must use Standard SSD disks."
  }
}

variable "assign_vm_public_ip" {
  type        = bool
  default     = false
  description = "Whether a public IP is attached to a VM NIC. Must remain false."

  validation {
    condition     = var.assign_vm_public_ip == false
    error_message = "Validation VM NICs must not have public IPs."
  }
}

variable "allow_gateway_transit" {
  type        = bool
  default     = false
  description = "Peering gateway transit. Must remain false so peering stays non-transitive."

  validation {
    condition     = var.allow_gateway_transit == false
    error_message = "Host peering must not enable gateway transit."
  }
}

variable "allow_forwarded_traffic" {
  type        = bool
  default     = false
  description = "Peering forwarded traffic. Must remain false."

  validation {
    condition     = var.allow_forwarded_traffic == false
    error_message = "Host peering must not forward traffic."
  }
}

variable "use_remote_gateways" {
  type        = bool
  default     = false
  description = "Peering remote gateways. Must remain false."

  validation {
    condition     = var.use_remote_gateways == false
    error_message = "Host peering must not use remote gateways."
  }
}

variable "purpose_tag" {
  type        = string
  default     = "WIN-PCInfoValidation"
  description = "Non-sensitive purpose tag."
}

variable "environment_tag" {
  type        = string
  default     = "EphemeralLab"
  description = "Non-sensitive environment tag."
}

variable "lifecycle_tag" {
  type        = string
  default     = "Ephemeral"
  description = "Non-sensitive lifecycle tag."
}

variable "managing_tool_tag" {
  type        = string
  default     = "Terraform"
  description = "Non-sensitive managing-tool tag."
}

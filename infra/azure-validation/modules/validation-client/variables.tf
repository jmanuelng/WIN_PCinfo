variable "location" {
  type = string
}

variable "resource_group_name" {
  type = string
}

variable "subnet_id" {
  type      = string
  sensitive = true
}

variable "approved_gallery_image_id" {
  type      = string
  sensitive = true
}

variable "os_disk_storage_type" {
  type = string
}

variable "assign_vm_public_ip" {
  type = bool
}

variable "client_index" {
  type = number
}

variable "temporary_admin_username" {
  type = string
}

variable "temporary_admin_password" {
  type      = string
  sensitive = true
}

variable "vm_sku" {
  type        = string
  description = "Allowlisted small SKU admitted for this client."
}

variable "claiming" {
  type        = bool
  description = "Whether this client may later support a Preview or Supported claim."
}

variable "security_type" {
  type        = string
  description = "TrustedLaunch for claiming Windows 11 clients; Standard only for non-claiming diagnostics."
}

variable "secure_boot" {
  type = bool
}

variable "vtpm" {
  type = bool
}

variable "tags" {
  type = map(string)
}

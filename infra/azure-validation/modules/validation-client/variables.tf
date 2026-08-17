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
  type    = string
  default = "Standard_D2s_v5"
}

variable "tags" {
  type = map(string)
}

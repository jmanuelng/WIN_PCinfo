# One fresh validation client. The threat is a reused captured image, a
# Premium disk, a public IP, or a Gen1 VM that is later treated as Windows 11
# Trusted Launch evidence. The mechanism is a private NIC, Standard SSD, and
# per-client Secure Boot/vTPM taken from the admitted plan. The trust
# assumption is that approved_gallery_image_id points at a pristine evaluation
# baseline supplied only in the private workspace. Safe failure is to keep
# assign_vm_public_ip false and to refuse a claiming VM without Trusted Launch.

resource "azurerm_network_interface" "client" {
  name                = format("nic-winpcinfo-%02d", var.client_index)
  location            = var.location
  resource_group_name = var.resource_group_name
  tags                = var.tags

  ip_configuration {
    name                          = "internal"
    subnet_id                     = var.subnet_id
    private_ip_address_allocation = "Dynamic"
  }

  lifecycle {
    precondition {
      condition     = var.assign_vm_public_ip == false
      error_message = "Validation client NICs must not receive a public IP."
    }
  }
}

resource "azurerm_windows_virtual_machine" "client" {
  name                       = format("vm-winpcinfo-%02d", var.client_index)
  location                   = var.location
  resource_group_name        = var.resource_group_name
  size                       = var.vm_sku
  admin_username             = var.temporary_admin_username
  admin_password             = var.temporary_admin_password
  network_interface_ids      = [azurerm_network_interface.client.id]
  secure_boot_enabled        = var.secure_boot
  vtpm_enabled               = var.vtpm
  encryption_at_host_enabled = false
  source_image_id            = var.approved_gallery_image_id
  tags                       = var.tags

  os_disk {
    name                 = format("osdisk-winpcinfo-%02d", var.client_index)
    caching              = "ReadWrite"
    storage_account_type = var.os_disk_storage_type
  }

  additional_capabilities {
    hibernation_enabled = false
  }

  lifecycle {
    precondition {
      condition     = !var.claiming || (var.security_type == "TrustedLaunch" && var.secure_boot && var.vtpm)
      error_message = "Claiming clients must use Trusted Launch with Secure Boot and vTPM."
    }
  }
}

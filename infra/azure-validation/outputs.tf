# Public templates may only export shape facts. The threat is an output that
# later prints a resource ID, IP, gallery reference, or hostname into a log.
# The mechanism is a closed object of counts and booleans. The trust
# assumption is that later apply tickets keep this output set closed. Safe
# failure is to omit environment values rather than redact them after the fact.
output "validation_round_shape" {
  value = {
    client_count             = length(var.clients)
    client_skus              = [for client in var.clients : client.sku]
    claiming_security_types  = [for client in var.clients : client.security_type]
    maximum_lifetime_minutes = var.maximum_lifetime_minutes
    cleanup_reserve_minutes  = var.cleanup_reserve_minutes
    nat_public_ip_sku        = var.nat_public_ip_sku
    os_disk_storage_type     = var.os_disk_storage_type
    vm_public_ip             = var.assign_vm_public_ip
    gateway_transit          = var.allow_gateway_transit
  }
}

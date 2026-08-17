output "subnet_id" {
  value     = azurerm_subnet.round.id
  sensitive = true
}

output "round_vnet_created" {
  value = true
}

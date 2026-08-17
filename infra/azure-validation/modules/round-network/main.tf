# Round-scoped private network. The threat is attaching a public IP to a
# client NIC, sharing a persistent lab subnet, or enabling transitive
# peering that turns the validation host into a router. The mechanism is a
# fresh VNet/subnet, NAT with one Standard public IP, and both peering
# objects with transit disabled. The trust assumption is that host_vnet_id
# is supplied only in a private workspace. Safe failure is a Terraform
# validation error, which this slice never executes.

resource "azurerm_virtual_network" "round" {
  name                = "vnet-winpcinfo-round"
  location            = var.location
  resource_group_name = var.resource_group_name
  address_space       = ["10.200.0.0/16"]
  tags                = var.tags
}

resource "azurerm_subnet" "round" {
  name                 = "snet-winpcinfo-round"
  resource_group_name  = var.resource_group_name
  virtual_network_name = azurerm_virtual_network.round.name
  address_prefixes     = ["10.200.1.0/24"]
}

resource "azurerm_network_security_group" "round" {
  name                = "nsg-winpcinfo-round"
  location            = var.location
  resource_group_name = var.resource_group_name
  tags                = var.tags

  security_rule {
    name                       = "allow-host-control"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_address_prefix      = "VirtualNetwork"
    source_port_range          = "*"
    destination_address_prefix = "VirtualNetwork"
    destination_port_ranges    = ["5986", "22"]
  }

  security_rule {
    name                       = "deny-inbound-internet"
    priority                   = 4096
    direction                  = "Inbound"
    access                     = "Deny"
    protocol                   = "*"
    source_address_prefix      = "Internet"
    source_port_range          = "*"
    destination_address_prefix = "*"
    destination_port_range     = "*"
  }
}

resource "azurerm_subnet_network_security_group_association" "round" {
  subnet_id                 = azurerm_subnet.round.id
  network_security_group_id = azurerm_network_security_group.round.id
}

resource "azurerm_public_ip" "nat" {
  name                = "pip-winpcinfo-round-nat"
  location            = var.location
  resource_group_name = var.resource_group_name
  allocation_method   = "Static"
  sku                 = var.nat_public_ip_sku
  tags                = var.tags
}

resource "azurerm_nat_gateway" "round" {
  name                = "nat-winpcinfo-round"
  location            = var.location
  resource_group_name = var.resource_group_name
  sku_name            = "Standard"
  tags                = var.tags
}

resource "azurerm_nat_gateway_public_ip_association" "round" {
  nat_gateway_id       = azurerm_nat_gateway.round.id
  public_ip_address_id = azurerm_public_ip.nat.id
}

resource "azurerm_subnet_nat_gateway_association" "round" {
  subnet_id      = azurerm_subnet.round.id
  nat_gateway_id = azurerm_nat_gateway.round.id
}

resource "azurerm_virtual_network_peering" "round_to_host" {
  name                         = "peer-round-to-host"
  resource_group_name          = var.resource_group_name
  virtual_network_name         = azurerm_virtual_network.round.name
  remote_virtual_network_id    = var.host_vnet_id
  allow_forwarded_traffic      = var.allow_forwarded_traffic
  allow_gateway_transit        = var.allow_gateway_transit
  allow_virtual_network_access = true
  use_remote_gateways          = var.use_remote_gateways
}

resource "azurerm_virtual_network_peering" "host_to_round" {
  name                         = "peer-host-to-round"
  resource_group_name          = var.host_resource_group_name
  virtual_network_name         = var.host_vnet_name
  remote_virtual_network_id    = azurerm_virtual_network.round.id
  allow_forwarded_traffic      = var.allow_forwarded_traffic
  allow_gateway_transit        = var.allow_gateway_transit
  allow_virtual_network_access = true
  use_remote_gateways          = var.use_remote_gateways
}

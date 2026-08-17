# Generic Terraform identity for one offline validation-round template.
# The threat is a floating provider or an accidental `terraform init` that
# downloads code and later talks to Azure. The mechanism is an exact
# required_version and an exact azurerm version. The trust assumption is that
# a later ticket acquires those binaries only after publishing version, source,
# digest, license, destination, and cleanup. Safe failure is to leave this
# file unused until offline admission has already succeeded.
terraform {
  required_version = "1.12.2"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "4.37.0"
    }
  }

  # The backend path is supplied only inside a private workspace. A public
  # example must not name a local disk, subscription, or storage account.
  backend "local" {}
}

provider "azurerm" {
  features {}

  # This slice never authenticates. A later apply path must use the host
  # managed identity and must still fail closed when the identity is absent.
  storage_use_azuread = true
}

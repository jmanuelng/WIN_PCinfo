# Generic Azure validation templates

These Terraform files are reusable source. They are not one lab and they do not create a Preview or Supported claim.

Use them only after [offline admission](../../docs/azure-validation-admission.md) has accepted a round plan. Instantiated values, backends, plans, state, locks, and `.terraform` content belong in a private workspace outside this repository.

This directory never contacts Azure. Completing a later apply ticket still requires a separate authority checkpoint.

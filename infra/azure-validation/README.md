# Generic Azure validation templates

These Terraform files are reusable source. They are not one lab and they do not create a Preview or Supported claim.

Use them only after [offline admission](../../docs/azure-validation-admission.md) has accepted a round plan. Instantiated values, backends, plans, state, locks, and `.terraform` content belong in a private workspace outside this repository.

This directory never contacts Azure. The [round controller](../../docs/azure-validation-round.md) does not apply these templates in this slice; live create stays `NotStarted` without the approved managed identity and without acquired pinned tooling.

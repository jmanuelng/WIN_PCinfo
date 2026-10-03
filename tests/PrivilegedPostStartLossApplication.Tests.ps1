[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
& (Join-Path $PSScriptRoot 'StatusDeskEngine.Tests.ps1') -QualificationPlanFault PrivilegePostStartLoss

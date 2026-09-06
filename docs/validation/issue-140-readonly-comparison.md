# Private source comparison for #161

This is an unexecuted procedure for the authorized human session in
[#161](https://github.com/jmanuelng/WIN_PCinfo/issues/161). It does not grant
collection, elevation, signing or trust authority. Its results are Restricted
Diagnostic Evidence. Keep the instantiated checklist, source values, records,
HTML and screenshots only in that session's approved private area outside the
repository. Publish only sanitized outcomes and counts.

## Before comparison

1. Identify the exact generated, signed candidate and record its digests in the
   private session log. Earlier signatures or synthetic results do not authorize
   changed bytes. Confirm initiating-user protection and approved recipients.
2. Run the ordinary Comprehensive Local Assessment / Local Only workflow with
   the authorized operator. Record preparation, one approval, privilege outcome,
   source completion, package availability, cleanup and timing. Do not substitute
   a fixture or start another assessment during an active run.
3. Open the protected report through the application's viewing workflow. Inspect
   the matching canonical record privately. Comparison reads should occur near
   the collection time; activation, charge and runtime can change naturally.
4. Use only the exact read projections below. Inspect their named projected
   properties rather than serializing whole CIM objects. Do not retrieve keys,
   serial numbers, arbitrary licensing properties, TPM owner/endorsement data or
   settings exports. Do not install tools, refresh policies, provision TPM,
   change Secure Boot or power settings, or induce failures on the device.

## Field and scope checks

| Approved read / independent comparison | Expected record fields | Expected scope / limits |
| --- | --- | --- |
| `Win32_ComputerSystem`: Manufacturer, Model, TotalPhysicalMemory, PCSystemType, HypervisorPresent | `device.manufacturer`, `device.model`, `device.memory.physical-bytes`, `device.system-type-code`, `device.hypervisor-present` | `scope:device.windows-context`; values retain their native types after normalization. Hypervisor presence alone does not establish a VM guest. |
| `Win32_Processor`: Name | `device.processor.name` | Same scope; first processor name is a bounded representative, not a complete processor inventory or performance measurement. |
| `Win32_OperatingSystem`: OperatingSystemSKU, BuildNumber; .NET RuntimeInformation.OSArchitecture | `device.windows.edition`, `device.windows.build`, `device.architecture` | Edition comes from the numeric SKU, never localized Caption. Unknown SKU remains `Sku-N`; architecture describes the OS rather than process bitness. |
| `SoftwareLicensingProduct`: LicenseStatus only, filtered by Windows ApplicationID `55c92734-d682-4d71-983e-d6ec3f16059f` | `device.windows.activation-state` | At most 16 rows, with a seventeenth detecting the bound. A returned activation code is point-in-time context, not legal entitlement or proof of installed-product ownership. Null status cannot become NotActivated. Check actual row count against the bound privately. |
| `Win32_SystemEnclosure`: ChassisTypes | `device.chassis.type-codes`; derived `device.form-factor` | One enclosure and at most eight chassis codes. Extra instances/codes are explicit constraints. Missing/inaccessible source data must not masquerade as examined absence. |
| `Win32_Battery`: BatteryStatus, EstimatedChargeRemaining, EstimatedRunTime | `device.battery.presence`, `.status`, `.charge-percent`, `.estimated-runtime-minutes` | One battery supported by this device-level projection; a second detects a constraint. Empty successful enumeration means observed absence; unavailable source does not. Charge is 0–100; runtime beyond 10,080 minutes/sentinel-like values stays unknown. No battery-health or power-plan claim. |
| Windows GetFirmwareType API; `Win32_BIOS`: SMBIOSBIOSVersion, SMBIOSMajorVersion, SMBIOSMinorVersion | `device.firmware.type`, `.bios-version`, `.smbios-version` | `scope:device.firmware-context`; API firmware type and BIOS strings have separate provenance. BIOS text bound is 128 UTF-8 bytes, SMBIOS version 16. |
| Built-in SecureBoot module `Confirm-SecureBootUEFI`, read only | `device.secure-boot.enabled` | `scope:device.secure-boot`; Boolean required. Legacy BIOS means unsupported source / NotApplicable rule; access denial or unavailable cmdlet must not mean disabled. |
| `root/CIMV2/Security/MicrosoftTpm`, `Win32_Tpm`: SpecVersion, IsEnabled_InitialValue, IsActivated_InitialValue | `device.tpm.present`, `.enabled`, `.activated`, `.specification` | `scope:device.tpm-readiness`; zero rows is absence, more than one is malformed; specification bound 32 UTF-8 bytes. No provisioning, owner authorization or secret properties/methods. |

All table field names carry the `field:` prefix in the record. Each observed
field must resolve exactly once to its source ID, collector/version, execution
context, collection time and subject. Derived form/VM fields must cite the
bounded classifier and its admitted input observations. Trace readiness,
activation, platform, power, firmware, Secure Boot and TPM findings to their
versioned rules and exact evidence references. Check that HTML agrees with the
record, shows gaps and distinguishes source facts, interpretation and advice.

## Representative private cases and disposition

Record Pass, Fail, Blocked or justified NotApplicable for each available case:
physical portable device; battery absent; VM guest/vTPM; non-English/Unicode;
activated and unknown/unactivated state; privilege denied; unavailable or
unsupported firmware/TPM source; cancel and recoverable partial report. Use
naturally available or already authorized representative devices. Synthetic
coverage of a case cannot be relabeled as live coverage; absence of suitable
hardware remains a named pending case or justified NotApplicable for that
specific environment, never a broad physical-support claim.

For each case retain privately: source revision and exact candidate digests,
source observation time, expected versus observed fields/scopes/rules/report,
coverage reason, timing, peak resource measurements, artifact retention and
verified viewing/workspace/worker cleanup. Never publish actual values or the
private destination. Close the viewing session explicitly; browser-tab closure
alone is not cleanup proof. Keep recoverable protected evidence and needed keys.

#161 owns these live comparisons and September 6 private handoff acceptance.
#158 owns the next integrated full regression and exact candidate preparation;
#162–#164 retain qualification, trust, approval and publication gates. Prior
working-set measurements above the provisional 512 MiB budget remain a #158/#161
measurement obligation, not a waiver. Escalate a mismatch to its owning slice
with sanitized reproduction information rather than changing device settings.

# Request-free WinRM configured sources (#145 correction)

This is static vendor-code evidence plus controlled-source validation, not a
live device assessment or a claim of support across Windows versions.

## Primary source and reproducible trace

Inspected installed Microsoft `WsmSvc.dll`, file version 10.0.26100.32860,
SHA-256 `593e611ff56f4fa6d9784e7364b9448390db4d5a174165dd8b807348679494cc`.
MSVC dumpbin 14.51.36248.0 performed read-only HEADERS, EXPORTS, IMPORTS and
bounded DISASM:NOBYTES/RANGE operations. No DLL entry point, internal API,
registry configuration query, service change or network operation was executed.
Image base is `0x180000000`; offsets below are RVAs unless marked VA. Tables
and UTF-16 literals were read from PE sections using their raw-file mappings.

* `CServiceConfigCache::ReadCurrentSettings` 197230 enters 078BD8 with current
  flag zero, calls 03DC24; 03E43F loads setting 7DD, then calls `GetBool` 03E610.
  `GetBool` calls `GetInt` 03E700 and converts nonzero to true. The 69-record
  normal configuration table at VA 18028FD60 has 48-byte records; record 2902D0
  maps 7DD to `auth_certificate` (VA 18020CAA8), group 1. The inspected 27-record
  policy table at VA 1801D39C0 has no 7DD entry. That absence is specific to this
  component and does not prove universal override precedence.
* `GetInt` 03E9AA supplies four bytes to `QueryRegValue` 03F260 and checks registry
  type 4 at 03EA6D. `QueryRegValue` passes the record's name to `RegQueryValueExW`.
  `OpenRegKey` 03F680 group 1 selects object +0400, initialized by `Init` 09AA40
  from `SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Service` (normal branch
  09AE9D to 09AC4C). Client certificate setting 451 is a distinct group 2 record.
* Listener settings BBA (`Port`, record 2905D0) and BBC (`enabled`, 290630) use
  the same typed integer machinery, group 3. Group 3 selects object +0C00,
  initialized from `SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Listener`.
  The OpenRegKey normal path 03F78F sets access bit 0x100 (64-bit view), 03F794
  chooses HKLM, and 03F7B4 calls `RegOpenKeyExW`. Optional internal root/path
  overrides exist; the product does not invoke or claim to resolve them.
* OpenRegKey 03F9A4–03F9CE formats the key with VA 18020BA98 `%s\%s%s+%s`:
  base, address-type prefix, address, transport suffix. Transport conversion
  0E7D34 bounds the enum to 0–1 and indexes VA 1801DC5B8; enum 0 points to
  `HTTP` at VA 1801F7348, enum 1 to `HTTPS` at VA 1801E7CE8. Settings BB8/BB9
  (address/transport) are identity keys, not ordinary registry values.
* The aligned normal DWORD branch 03EA6D goes to 03EAE4; 03EB85–03EBC6 compares
  the value with unsigned min/max words at record +1C/+20 before returning it
  at 03EDFC–03EE0B. Direct reads of those words establish certificate and enabled
  ranges 0–1, and Port 1–65535. GetBool's later nonzero conversion must not be
  used to accept out-of-range registry integers. No missing-value default was
  traced or imported into the product.

These traces establish explicit normal local configuration storage. They do
not establish defaults on missing values, full effective listener enumeration,
policy/compatibility expansion, freshness, reachability or current traffic.
[Microsoft's configuration reference](https://learn.microsoft.com/en-us/windows/win32/winrm/installation-and-configuration-for-windows-remote-management)
separately defines listener transport, port and enabled semantics and permits
multiple listeners; service runtime alone is insufficient. The
[MS-WSMV listener schema](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wsmv/c6d479c8-d487-4712-8bbb-a3cb53ba151f)
defines the configuration resource, not a request-free collection mechanism.

## Released bounded projection

The worker reads the exact Registry64 HKLM service DWORD `auth_certificate`.
Explicit zero is false; explicit one is true, matching the traced integer bounds
before GetBool. Other integers are Malformed rather than coerced to true.
Missing, denied or wrongly typed values yield unknown coverage, never defaults.
It never reads client authentication, certificate mappings, thumbprints or secrets.
The value read uses the inbox Advapi32
[RegGetValueW API](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-reggetvaluew)
with REG_DWORD-only, Registry64 and zero-on-failure flags (`0x20010010`) and a
fixed four-byte buffer. Unsupported types and oversized data are rejected by
the bounded operation; the product never retries with a larger buffer. This
avoids fetching a wrongly typed blob before checking its kind, including a
type/read race. The C# declaration compiles with the existing worker; controlled
tests replace only this native-call expression and verify its actual arguments.

Listener collection checks SubKeyCount before enumeration and rechecks the
returned count, refusing more than 32 direct records. Only selector suffixes
`+HTTP`/`+HTTPS` and explicit DWORD `Port` (1–65535) and `enabled` are interpreted.
Selector addresses are transient registry lookup names and never enter evidence.
An unrecognized selector, missing key/value, denial or malformed DWORD yields a
stable incomplete disposition. Empty storage is unknown, not no listener.

The scalar contract preserves aggregate ConfiguredEnabled, ConfiguredDisabled
or ConfiguredMixed. Transport/port are emitted only when all records agree;
different values are not collapsed to an arbitrary first endpoint. Listener
coverage remains Partial even for a fully readable local record, with explicit
LOCAL_LISTENER_CONFIG_ONLY or MULTIPLE_LOCAL_LISTENER_CONFIGS reasons. Policy,
compatibility/default expansion and runtime remain unobserved. These fields
belong to Configured Policy Signals, separate from WinRM service state.

Windows 10 and other component versions require the private #161 comparison;
this static trace does not establish their live compatibility. The source may
execute and return explicit Unavailable/Denied/Malformed/Constrained there.
Independent review must assess implementation closure; no scope waiver follows
from the deliberately bounded projection or controlled-source passes.

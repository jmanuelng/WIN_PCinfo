$script:IdentityEnrollmentPolicyBase64 = '__IDENTITY_ENROLLMENT_POLICY_BASE64__'
$script:IdentityEnrollmentPolicyDigest = '__IDENTITY_ENROLLMENT_POLICY_SHA256__'

function Get-IdentityEnrollmentPolicy {
    param([Parameter(Mandatory)] $ConvertFromJsonCommand)

    if ($script:IdentityEnrollmentPolicyBase64 -eq ('__IDENTITY_ENROLLMENT_' + 'POLICY_BASE64__')) {
        $path = Join-Path (Split-Path -Parent $PSScriptRoot) `
            'docs/spec/releases/2.0.0-preview.1-identity-enrollment.json'
        $bytes = Get-CanonicalSupervisorTextBytes -LiteralPath $path
        $expectedDigest = Get-Sha256ForSupervisorBytes -Bytes $bytes
    }
    else {
        $bytes = [Convert]::FromBase64String($script:IdentityEnrollmentPolicyBase64)
        $expectedDigest = $script:IdentityEnrollmentPolicyDigest
    }
    if ((Get-Sha256ForSupervisorBytes -Bytes $bytes) -ne $expectedDigest) {
        throw 'The Identity and Enrollment policy failed integrity validation.'
    }
    $policy = & $ConvertFromJsonCommand -InputObject (
        [Text.UTF8Encoding]::new($false, $true).GetString($bytes)
    ) -Depth 20 -ErrorAction Stop
    if ($policy.kind -ne 'win-pcinfo.identity-enrollment-policy' -or
        $policy.policyId -ne 'win-pcinfo.identity-enrollment/1.0.0' -or
        @($policy.collectors).Count -ne 3 -or @($policy.scopes).Count -ne 4 -or
        @($policy.rules).Count -ne 3 -or @($policy.discoveryTasks).Count -ne 6 -or
        @($policy.validationScenarios).Count -ne 13) {
        throw 'The Identity and Enrollment policy is not the closed release policy.'
    }
    $policy
}

function Read-IdentityEnrollmentFixture {
    param(
        [Parameter(Mandatory)] [string] $LiteralPath,
        [Parameter(Mandatory)] $ConvertFromJsonCommand,
        [Parameter(Mandatory)] $Policy
    )
    try {
        [byte[]]$bytes=[IO.File]::ReadAllBytes([IO.Path]::GetFullPath($LiteralPath))
        if($bytes.Length -lt 1 -or $bytes.Length -gt 512){throw 'Fixture size is invalid.'}
        $json=[Text.UTF8Encoding]::new($false,$true).GetString($bytes)
        $document=[Text.Json.JsonDocument]::Parse($json)
        try{
            $names=@($document.RootElement.EnumerateObject()|ForEach-Object Name)
            if((@($names|Sort-Object)-join '|') -ne 'contractVersion|scenario'){
                throw 'Fixture shape is invalid.'
            }
        }finally{$document.Dispose()}
        $fixture=& $ConvertFromJsonCommand -InputObject $json -Depth 5 -ErrorAction Stop
        if($fixture.contractVersion -ne '1.0.0' -or
            [string]$fixture.scenario -notin @($Policy.validationScenarios)){
            throw 'Fixture scenario is not release-owned.'
        }
        [string]$fixture.scenario
    }catch{
        $exception=[ArgumentException]::new('The Identity and Enrollment fixture is invalid.')
        $exception.Data['ReasonCode']='IDENTITY.FIXTURE_INVALID';throw $exception
    }
}

function Test-IdentityEnrollmentCollectorPayload {
    param([Parameter(Mandatory)] $Payload)

    $allowedNames = @(
        'sourceLocale','registrationState','userContextState','workSchoolState',
        'assessmentUserVerified','assessmentUserSessionId','assessmentUserAccountName',
        'domainJoinState','domainName','entraRegistrationType','entraDeviceId',
        'entraTenantId','workSchoolAccountPresent','workSchoolAccountIdentifier'
    )
    $names = @($Payload.PSObject.Properties.Name)
    if ($names.Count -ne $allowedNames.Count -or
        (@($names | Sort-Object) -join '|') -ne (@($allowedNames | Sort-Object) -join '|')) {
        return $false
    }
    $states = @('Complete','Unavailable','Denied','Malformed','Failed')
    if ([string]$Payload.registrationState -notin $states -or
        [string]$Payload.userContextState -notin $states -or
        [string]$Payload.workSchoolState -notin $states -or
        [Text.Encoding]::UTF8.GetByteCount([string]$Payload.sourceLocale) -gt 32 -or
        [string]$Payload.sourceLocale -notmatch '^(?:und|[A-Za-z]{2,3}(?:-[A-Za-z0-9]{2,8})*)$') {
        return $false
    }
    if ($Payload.registrationState -eq 'Complete') {
        if ([string]$Payload.domainJoinState -notin @('Workgroup','DomainJoined','Unknown') -or
            [string]$Payload.entraRegistrationType -notin @('None','EntraJoined','EntraRegistered','Unknown')) {
            return $false
        }
        foreach ($value in @($Payload.domainName,$Payload.entraDeviceId,$Payload.entraTenantId)) {
            if ($null -ne $value -and ([string]::IsNullOrWhiteSpace([string]$value) -or
                [Text.Encoding]::UTF8.GetByteCount([string]$value) -gt 256)) {
                return $false
            }
        }
    }
    elseif ($null -ne $Payload.domainJoinState -or $null -ne $Payload.domainName -or
        $null -ne $Payload.entraRegistrationType -or $null -ne $Payload.entraDeviceId -or
        $null -ne $Payload.entraTenantId) { return $false }
    if ($Payload.userContextState -eq 'Complete') {
        if ($Payload.assessmentUserVerified -isnot [bool] -or
            -not [bool]$Payload.assessmentUserVerified -or
            $Payload.assessmentUserSessionId -isnot [int] -or
            [int]$Payload.assessmentUserSessionId -lt 0 -or
            [string]::IsNullOrWhiteSpace([string]$Payload.assessmentUserAccountName) -or
            [Text.Encoding]::UTF8.GetByteCount([string]$Payload.assessmentUserAccountName) -gt 256) {
            return $false
        }
    }
    elseif ($null -ne $Payload.assessmentUserVerified -or
        $null -ne $Payload.assessmentUserSessionId -or
        $null -ne $Payload.assessmentUserAccountName) { return $false }
    if ($Payload.workSchoolState -eq 'Complete') {
        if ($Payload.workSchoolAccountPresent -isnot [bool] -or
            ($null -ne $Payload.workSchoolAccountIdentifier -and (
                [string]::IsNullOrWhiteSpace([string]$Payload.workSchoolAccountIdentifier) -or
                [Text.Encoding]::UTF8.GetByteCount([string]$Payload.workSchoolAccountIdentifier) -gt 256
            )) -or (-not [bool]$Payload.workSchoolAccountPresent -and
                $null -ne $Payload.workSchoolAccountIdentifier)) {
            return $false
        }
    }
    elseif ($null -ne $Payload.workSchoolAccountPresent -or
        $null -ne $Payload.workSchoolAccountIdentifier) { return $false }
    $true
}

function New-IdentityEnrollmentSyntheticPayload {
    param([Parameter(Mandatory)] [string] $Scenario)

    $payload = [ordered]@{
        sourceLocale='en-US';registrationState='Complete';userContextState='Complete'
        workSchoolState='Complete';assessmentUserVerified=$true
        assessmentUserSessionId=[int]3
        assessmentUserAccountName='SYNTHETIC\assessment-user'
        domainJoinState='Workgroup';domainName=$null;entraRegistrationType='None'
        entraDeviceId=$null;entraTenantId=$null;workSchoolAccountPresent=$false
        workSchoolAccountIdentifier=$null
    }
    $relationship = 'SameUser'
    switch ($Scenario) {
        'DomainJoined' {
            $payload.domainJoinState='DomainJoined';$payload.domainName='SYNTHETIC-DOMAIN'
        }
        'EntraJoined' {
            $payload.entraRegistrationType='EntraJoined'
            $payload.entraDeviceId='00000000-0000-4000-8000-000000000051'
            $payload.entraTenantId='00000000-0000-4000-8000-000000000052'
        }
        'Registered' {
            $payload.entraRegistrationType='EntraRegistered'
            $payload.entraDeviceId='00000000-0000-4000-8000-000000000053'
            $payload.entraTenantId='00000000-0000-4000-8000-000000000054'
            $payload.workSchoolAccountPresent=$true
            $payload.workSchoolAccountIdentifier='assessment.user@example.invalid'
        }
        'Mixed' {
            $payload.domainJoinState='DomainJoined';$payload.domainName='SYNTHETIC-DOMAIN'
            $payload.entraRegistrationType='EntraJoined'
            $payload.entraDeviceId='00000000-0000-4000-8000-000000000055'
            $payload.entraTenantId='00000000-0000-4000-8000-000000000056'
        }
        'UserContextUnavailable' {
            $payload.userContextState='Unavailable';$payload.assessmentUserVerified=$null
            $payload.assessmentUserSessionId=$null;$payload.assessmentUserAccountName=$null
            $relationship='Unavailable'
        }
        'Administrator' {
            $payload.registrationState='Denied';$payload.userContextState='Denied'
            $payload.workSchoolState='Denied';$payload.assessmentUserVerified=$null
            $payload.assessmentUserSessionId=$null;$payload.assessmentUserAccountName=$null
            $payload.domainJoinState=$null;$payload.domainName=$null
            $payload.entraRegistrationType=$null;$payload.entraDeviceId=$null
            $payload.entraTenantId=$null;$payload.workSchoolAccountPresent=$null
            $payload.workSchoolAccountIdentifier=$null
            $relationship='AlternateAdministrator'
        }
        'LocalSystem' {
            $payload.registrationState='Denied';$payload.userContextState='Denied'
            $payload.workSchoolState='Denied';$payload.assessmentUserVerified=$null
            $payload.assessmentUserSessionId=$null;$payload.assessmentUserAccountName=$null
            $payload.domainJoinState=$null;$payload.domainName=$null
            $payload.entraRegistrationType=$null;$payload.entraDeviceId=$null
            $payload.entraTenantId=$null;$payload.workSchoolAccountPresent=$null
            $payload.workSchoolAccountIdentifier=$null
            $relationship='ProhibitedProcessContext'
        }
        'NonEnglish' {
            $payload.sourceLocale='fr-FR';$payload.domainJoinState='DomainJoined'
            $payload.domainName='DOMAINE-ÉQUIPE';$payload.entraRegistrationType='EntraRegistered'
            $payload.entraDeviceId='00000000-0000-4000-8000-000000000057'
            $payload.entraTenantId='00000000-0000-4000-8000-000000000058'
            $payload.assessmentUserAccountName='équipe\utilisateur'
            $payload.workSchoolAccountPresent=$true
            $payload.workSchoolAccountIdentifier='utilisateur@exemple.invalid'
        }
        'Malformed' {
            $payload.registrationState='Malformed';$payload.userContextState='Malformed'
            $payload.workSchoolState='Malformed';$payload.assessmentUserVerified=$null
            $payload.assessmentUserSessionId=$null;$payload.assessmentUserAccountName=$null
            $payload.domainJoinState=$null;$payload.domainName=$null
            $payload.entraRegistrationType=$null;$payload.entraDeviceId=$null
            $payload.entraTenantId=$null;$payload.workSchoolAccountPresent=$null
            $payload.workSchoolAccountIdentifier=$null;$relationship='Unavailable'
        }
        'Denied' {
            $payload.registrationState='Denied';$payload.userContextState='Denied'
            $payload.workSchoolState='Denied';$payload.assessmentUserVerified=$null
            $payload.assessmentUserSessionId=$null;$payload.assessmentUserAccountName=$null
            $payload.domainJoinState=$null;$payload.domainName=$null
            $payload.entraRegistrationType=$null;$payload.entraDeviceId=$null
            $payload.entraTenantId=$null;$payload.workSchoolAccountPresent=$null
            $payload.workSchoolAccountIdentifier=$null;$relationship='Unavailable'
        }
    }
    [pscustomobject][ordered]@{payload=[pscustomobject]$payload;relationship=$relationship}
}

function Initialize-IdentityEnrollmentNativeSource {
    if ('WinPCInfo.IdentityEnrollment.NativeSources' -as [type]) { return }

    # Threat: process identity is not proof of the interactive user whose HKCU
    # and enrollment context the assessment promises to describe. Mechanism:
    # Terminal Services enumerates active logon sessions, while NetAPI returns
    # typed domain and Entra join structures rather than localized display
    # text. Trust assumption: these inbox APIs faithfully describe only local
    # Windows state. Safe failure: ambiguous sessions, malformed structures, or
    # an API error become coverage gaps; no process account is substituted.
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace WinPCInfo.IdentityEnrollment
{
    public sealed class NativeSnapshot
    {
        public int DomainError { get; set; }
        public int DomainJoinStatus { get; set; }
        public string DomainName { get; set; }
        public int AadError { get; set; }
        public bool AadInfoPresent { get; set; }
        public int AadJoinType { get; set; }
        public string DeviceId { get; set; }
        public string TenantId { get; set; }
        public string JoinUserEmail { get; set; }
        public bool UserContextAvailable { get; set; }
        public int ActiveUserSessionCount { get; set; }
        public int UserSessionId { get; set; }
        public string UserAccountName { get; set; }
        public string UserSid { get; set; }
        public int UserError { get; set; }
    }

    public static class NativeSources
    {
        public static bool CanVerifyUserContext(
            int activeSessionCount, int usableSessionCount, int userError)
        {
            return userError == 0 && activeSessionCount == 1 && usableSessionCount == 1;
        }
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct DSREG_JOIN_INFO
        {
            public int joinType;
            public IntPtr pJoinCertificate;
            [MarshalAs(UnmanagedType.LPWStr)] public string pszDeviceId;
            [MarshalAs(UnmanagedType.LPWStr)] public string pszIdpDomain;
            [MarshalAs(UnmanagedType.LPWStr)] public string pszTenantId;
            [MarshalAs(UnmanagedType.LPWStr)] public string pszJoinUserEmail;
            [MarshalAs(UnmanagedType.LPWStr)] public string pszTenantDisplayName;
            [MarshalAs(UnmanagedType.LPWStr)] public string pszMdmEnrollmentUrl;
            [MarshalAs(UnmanagedType.LPWStr)] public string pszMdmTermsOfUseUrl;
            [MarshalAs(UnmanagedType.LPWStr)] public string pszMdmComplianceUrl;
            [MarshalAs(UnmanagedType.LPWStr)] public string pszUserSettingSyncUrl;
            public IntPtr pUserInfo;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct WTS_SESSION_INFO
        {
            public int SessionID;
            public IntPtr pWinStationName;
            public int State;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct LUID { public uint LowPart; public int HighPart; }
        [StructLayout(LayoutKind.Sequential)]
        private struct LSA_UNICODE_STRING
        {
            public ushort Length; public ushort MaximumLength; public IntPtr Buffer;
        }
        [StructLayout(LayoutKind.Sequential)]
        private struct SECURITY_LOGON_SESSION_DATA
        {
            public uint Size; public LUID LogonId; public LSA_UNICODE_STRING UserName;
            public LSA_UNICODE_STRING LogonDomain; public LSA_UNICODE_STRING AuthenticationPackage;
            public uint LogonType; public uint Session; public IntPtr Sid; public long LogonTime;
            public LSA_UNICODE_STRING LogonServer; public LSA_UNICODE_STRING DnsDomainName;
            public LSA_UNICODE_STRING Upn;
        }

        [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
        private static extern int NetGetJoinInformation(
            string server, out IntPtr nameBuffer, out int bufferType);
        [DllImport("netapi32.dll")]
        private static extern int NetApiBufferFree(IntPtr buffer);
        [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
        private static extern int NetGetAadJoinInformation(
            string tenantId, out IntPtr joinInfo);
        [DllImport("netapi32.dll")]
        private static extern void NetFreeAadJoinInformation(IntPtr joinInfo);
        [DllImport("wtsapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool WTSEnumerateSessions(
            IntPtr server, int reserved, int version, out IntPtr sessions, out int count);
        [DllImport("wtsapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool WTSQuerySessionInformation(
            IntPtr server, int sessionId, int infoClass, out IntPtr buffer, out int bytes);
        [DllImport("wtsapi32.dll")]
        private static extern void WTSFreeMemory(IntPtr memory);
        [DllImport("secur32.dll")]
        private static extern uint LsaEnumerateLogonSessions(out ulong count, out IntPtr list);
        [DllImport("secur32.dll")]
        private static extern uint LsaGetLogonSessionData(ref LUID logonId, out IntPtr data);
        [DllImport("secur32.dll")]
        private static extern uint LsaFreeReturnBuffer(IntPtr buffer);
        [DllImport("advapi32.dll")]
        private static extern uint LsaNtStatusToWinError(uint status);

        private static string QuerySessionString(int sessionId, int infoClass, out int error)
        {
            error = 0;
            IntPtr value = IntPtr.Zero;
            int bytes;
            if (!WTSQuerySessionInformation(IntPtr.Zero, sessionId, infoClass, out value, out bytes))
            {
                error = Marshal.GetLastWin32Error();
                return null;
            }
            try { return value == IntPtr.Zero ? null : Marshal.PtrToStringUni(value); }
            finally { if (value != IntPtr.Zero) WTSFreeMemory(value); }
        }

        private static string ReadLsaString(LSA_UNICODE_STRING value)
        {
            return value.Buffer == IntPtr.Zero || value.Length == 0
                ? String.Empty : Marshal.PtrToStringUni(value.Buffer, value.Length / 2);
        }

        private static bool TryGetLocalSessionSid(
            int sessionId, string user, string domain, out string sid, out int error)
        {
            sid = null; error = 0;
            uint status = LsaEnumerateLogonSessions(out ulong count, out IntPtr list);
            if (status != 0)
            {
                error = (int)LsaNtStatusToWinError(status);
                return false;
            }
            var matchingSids = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            try
            {
                for (ulong index = 0; index < count; index++)
                {
                    var luid = Marshal.PtrToStructure<LUID>(IntPtr.Add(list, checked((int)index * 8)));
                    IntPtr data = IntPtr.Zero;
                    status = LsaGetLogonSessionData(ref luid, out data);
                    if (status != 0)
                    {
                        error = (int)LsaNtStatusToWinError(status);
                        return false;
                    }
                    try
                    {
                        if (data == IntPtr.Zero) continue;
                        var item = Marshal.PtrToStructure<SECURITY_LOGON_SESSION_DATA>(data);
                        if (item.Session != (uint)sessionId || item.Sid == IntPtr.Zero) continue;
                        if (!String.Equals(ReadLsaString(item.UserName), user,
                                StringComparison.OrdinalIgnoreCase) ||
                            !String.Equals(ReadLsaString(item.LogonDomain), domain,
                                StringComparison.OrdinalIgnoreCase)) continue;
                        matchingSids.Add(new SecurityIdentifier(item.Sid).Value);
                    }
                    finally { if (data != IntPtr.Zero) LsaFreeReturnBuffer(data); }
                }
            }
            finally { if (list != IntPtr.Zero) LsaFreeReturnBuffer(list); }
            if (matchingSids.Count != 1) { error = 1168; return false; }
            foreach (string value in matchingSids) { sid = value; }
            return true;
        }

        public static NativeSnapshot Read(string mode)
        {
            bool registrationUser = String.Equals(mode, "RegistrationUser", StringComparison.Ordinal);
            bool workSchool = String.Equals(mode, "WorkSchool", StringComparison.Ordinal);
            if (!registrationUser && !workSchool) throw new ArgumentException("Unknown native source mode.");
            var result = new NativeSnapshot { UserSessionId = -1 };
            if (registrationUser)
            {
                IntPtr domain = IntPtr.Zero;
                result.DomainError = NetGetJoinInformation(null, out domain, out int joinStatus);
                result.DomainJoinStatus = joinStatus;
                try
                {
                    if (result.DomainError == 0 && domain != IntPtr.Zero)
                        result.DomainName = Marshal.PtrToStringUni(domain);
                }
                finally { if (domain != IntPtr.Zero) NetApiBufferFree(domain); }
            }

            IntPtr aad = IntPtr.Zero;
            result.AadError = NetGetAadJoinInformation(null, out aad);
            try
            {
                if (result.AadError == 0 && aad != IntPtr.Zero)
                {
                    result.AadInfoPresent = true;
                    var info = Marshal.PtrToStructure<DSREG_JOIN_INFO>(aad);
                    result.AadJoinType = info.joinType;
                    result.DeviceId = info.pszDeviceId;
                    result.TenantId = info.pszTenantId;
                    if (workSchool) result.JoinUserEmail = info.pszJoinUserEmail;
                }
            }
            finally { if (aad != IntPtr.Zero) NetFreeAadJoinInformation(aad); }

            if (registrationUser || workSchool)
            {
                IntPtr sessions = IntPtr.Zero;
                if (WTSEnumerateSessions(IntPtr.Zero, 0, 1, out sessions, out int count))
                {
                    try
                    {
                        int size = Marshal.SizeOf<WTS_SESSION_INFO>();
                        var activeUsers = new List<Tuple<int, string, string, string>>();
                        int activeSessionCount = 0;
                        for (int index = 0; index < count; index++)
                        {
                            var item = Marshal.PtrToStructure<WTS_SESSION_INFO>(
                                IntPtr.Add(sessions, index * size));
                            if (item.State != 0) continue; // WTSActive
                            activeSessionCount++;
                            string user = QuerySessionString(item.SessionID, 5, out int userError);
                            if (userError != 0 || String.IsNullOrWhiteSpace(user))
                            {
                                result.UserError = userError == 0 ? 13 : userError;
                                continue;
                            }
                            string domainName = QuerySessionString(item.SessionID, 7, out int domainError);
                            if (domainError != 0)
                            {
                                result.UserError = domainError;
                                continue;
                            }
                            string account = String.IsNullOrWhiteSpace(domainName)
                                ? user : domainName + "\\" + user;
                            activeUsers.Add(Tuple.Create(item.SessionID, account, user,
                                domainName ?? String.Empty));
                        }
                        result.ActiveUserSessionCount = activeSessionCount;
                        if (CanVerifyUserContext(activeSessionCount, activeUsers.Count, result.UserError))
                        {
                            if (TryGetLocalSessionSid(activeUsers[0].Item1, activeUsers[0].Item3,
                                    activeUsers[0].Item4, out string sid, out int sidError))
                            {
                                result.UserContextAvailable = true;
                                result.UserSessionId = activeUsers[0].Item1;
                                result.UserAccountName = activeUsers[0].Item2;
                                result.UserSid = sid;
                            }
                            else result.UserError = sidError;
                        }
                    }
                    finally { if (sessions != IntPtr.Zero) WTSFreeMemory(sessions); }
                }
                else result.UserError = Marshal.GetLastWin32Error();
            }
            return result;
        }
    }
}
'@
}

function Test-IdentityNativeAccessDeniedCode {
    param([Parameter(Mandatory)] [int] $Code)
    # NetGetJoinInformation returns Win32 status while NetGetAadJoinInformation
    # returns HRESULT. Preserve both representations of access denied so a
    # rejected provider cannot be softened into a generic unavailable state.
    $Code -eq 5 -or $Code -eq -2147024891
}

function Test-IdentityAadSuccessCode {
    param([Parameter(Mandatory)] [int] $Code)
    # NetGetAadJoinInformation returns S_FALSE (1), not a failure, when the
    # device has no default join information. That is complete local evidence
    # for `None`; treating it as unavailable would erase the ordinary
    # workgroup/unenrolled case on real Windows hosts.
    $Code -eq 0 -or $Code -eq 1
}

function Get-IdentityAadSourceState {
    param(
        [Parameter(Mandatory)] [int] $Code,
        [Parameter(Mandatory)] [bool] $InfoPresent
    )
    if(Test-IdentityNativeAccessDeniedCode $Code){return 'Denied'}
    # The documented S_OK/NULL result also represents no default join. A
    # nonempty result with S_FALSE contradicts that absence and is rejected.
    if($Code -eq 1 -and $InfoPresent){return 'Malformed'}
    if(Test-IdentityAadSuccessCode $Code){return 'Complete'}
    'Unavailable'
}

function Assert-IdentityCollectorCleanupVerified {
    param([Parameter(Mandatory)] $Attempt)
    if($null -ne $Attempt.native -and (
        $Attempt.native.FailureStage -eq
            [WinPCInfo.ProcessSupervisor.NativeFailureStage]::TerminationIncomplete -or
        ($Attempt.native.Started -and -not [bool]$Attempt.native.CompleteOwnedTreeAbsent))){
        $exception=[InvalidOperationException]::new(
            'An identity collector attempt could not prove its owned worker absent.'
        )
        $exception.Data['ReasonCode']='IDENTITY.COLLECTOR_CLEANUP_INCOMPLETE'
        throw $exception
    }
}

function New-LiveIdentityContextGap {
    param(
        [Parameter(Mandatory)] [ValidateSet('Administrator','LocalSystem')] [string] $Context,
        [Parameter(Mandatory)] [string] $Relationship,
        [Parameter(Mandatory)] [DateTimeOffset] $StartedAt
    )
    $value = New-IdentityEnrollmentSyntheticPayload -Scenario 'LocalSystem'
    $completedAt=[DateTimeOffset]::UtcNow
    [pscustomobject][ordered]@{
        payload=$value.payload;relationship=$Relationship;executionContext=$Context
        startedAt=$StartedAt;completedAt=$completedAt
        sourceFailureReason='COLLECTION.IDENTITY_PROCESS_CONTEXT_PROHIBITED'
        collectorAttempts=@(
            [pscustomobject]@{startedAt=$StartedAt;completedAt=$completedAt
                reasonCode='COLLECTION.IDENTITY_PROCESS_CONTEXT_PROHIBITED'},
            [pscustomobject]@{startedAt=$StartedAt;completedAt=$completedAt
                reasonCode='COLLECTION.IDENTITY_PROCESS_CONTEXT_PROHIBITED'}
        )
    }
}

function Get-IdentityProcessContextDisposition {
    param(
        [Parameter(Mandatory)] [string] $ProcessSid,
        [Parameter(Mandatory)] [bool] $IsAdministrator,
        [Parameter(Mandatory)] [DateTimeOffset] $StartedAt
    )
    if($ProcessSid -eq 'S-1-5-18'){
        return New-LiveIdentityContextGap -Context 'LocalSystem' `
            -Relationship 'ProhibitedProcessContext' -StartedAt $StartedAt
    }
    if($IsAdministrator){
        return New-LiveIdentityContextGap -Context 'Administrator' `
            -Relationship 'AlternateAdministrator' -StartedAt $StartedAt
    }
    $null
}

function Invoke-BoundedIdentityNativeSnapshot {
    param(
        [Parameter(Mandatory)] $Policy,
        [Parameter(Mandatory)] [ValidateRange(0,1)] [int] $CollectorIndex,
        [Parameter(Mandatory)] [ValidateSet('RegistrationUser','WorkSchool')] [string] $Mode
    )

    Initialize-ProcessSupervisorNativeType
    $collector = $Policy.collectors[$CollectorIndex]
    $maximumMilliseconds = [int]$collector.deadlineMilliseconds
    $terminationMilliseconds = [Math]::Min(1000, [Math]::Max(1,
        [Math]::Floor($maximumMilliseconds / 4)))
    $activeMilliseconds = [Math]::Max(1, $maximumMilliseconds - $terminationMilliseconds)
    $initializerBytes = [Text.UTF8Encoding]::new($false).GetBytes(
        ${function:Initialize-IdentityEnrollmentNativeSource}.ToString()
    )
    # The child receives only release-embedded source selected here. There is
    # no caller script, path, command, or writable staging file to replace.
    # A suspended Microsoft-signed pwsh child is placed in the supervisor's
    # kill-on-close Job before the native APIs run, making even a blocked API a
    # bounded attempt whose complete owned tree can be proved absent.
    $childScript = @'
$ErrorActionPreference='Stop'
try {
    $utf8=[Text.UTF8Encoding]::new($false,$true)
    $source=$utf8.GetString([Convert]::FromBase64String($env:WINPCINFO_IDENTITY_NATIVE_SOURCE))
    & ([scriptblock]::Create($source))
    $snapshot=[WinPCInfo.IdentityEnrollment.NativeSources]::Read($env:WINPCINFO_IDENTITY_NATIVE_MODE)
    $xml=[Management.Automation.PSSerializer]::Serialize($snapshot,5)
    [Console]::Out.Write([Convert]::ToBase64String($utf8.GetBytes($xml)))
} catch { [Console]::Error.Write('Identity native source failed.'); exit 1 }
'@
    $encodedChild = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($childScript))
    $attemptStartedAt=[DateTimeOffset]::UtcNow
    $executable = [IO.Path]::GetFullPath((Join-Path $PSHOME 'pwsh.exe'))
    if (-not [IO.File]::Exists($executable) -or -not [string]::Equals(
            $executable, [Environment]::ProcessPath, [StringComparison]::OrdinalIgnoreCase)) {
        return [pscustomobject]@{succeeded=$false;snapshot=$null
            reasonCode='COLLECTION.IDENTITY_BOUNDARY_UNAVAILABLE';native=$null
            startedAt=$attemptStartedAt;completedAt=[DateTimeOffset]::UtcNow}
    }
    $environment = [Collections.Generic.Dictionary[string,string]]::new(
        [StringComparer]::OrdinalIgnoreCase
    )
    $environment['SystemRoot']=[Environment]::GetFolderPath('Windows')
    $environment['WINPCINFO_IDENTITY_NATIVE_SOURCE']=[Convert]::ToBase64String($initializerBytes)
    $environment['WINPCINFO_IDENTITY_NATIVE_MODE']=$Mode
    $eventName="Local\WINPCInfo-Identity-$([Guid]::NewGuid().ToString('N'))"
    [bool]$created=$false;$event=$null
    try {
        $event=[Threading.EventWaitHandle]::new($false,
            [Threading.EventResetMode]::ManualReset,$eventName,[ref]$created)
        if(-not $created){return [pscustomobject]@{succeeded=$false;snapshot=$null
            reasonCode='COLLECTION.IDENTITY_BOUNDARY_UNAVAILABLE';native=$null
            startedAt=$attemptStartedAt;completedAt=[DateTimeOffset]::UtcNow}}
        $native=[WinPCInfo.ProcessSupervisor.NativeRunner]::Run(
            $executable,@('-NoLogo','-NoProfile','-NonInteractive','-EncodedCommand',$encodedChild),
            $PSHOME,$environment,$activeMilliseconds,[int]$collector.resultMaximumUtf8Bytes,4096,
            (Get-AssessmentCancellationToken),$event,1,$terminationMilliseconds,$false
        )
        if(-not $native.Started -or -not [bool]$native.CompleteOwnedTreeAbsent -or
            $native.FailureStage -ne [WinPCInfo.ProcessSupervisor.NativeFailureStage]::None -or
            $native.ExitCode -ne 0 -or $native.StandardOutputExceeded -or
            $native.StandardErrorExceeded -or $native.StandardErrorBytes -ne 0){
            $reason=Get-NativeSupervisorReasonCode -NativeResult $native
            if([string]::IsNullOrWhiteSpace($reason)){$reason='COLLECTION.IDENTITY_SOURCE_FAILED'}
            return [pscustomobject]@{succeeded=$false;snapshot=$null;reasonCode=$reason;native=$native
                startedAt=$attemptStartedAt;completedAt=[DateTimeOffset]::UtcNow}
        }
        $base64=[Text.UTF8Encoding]::new($false,$true).GetString($native.StandardOutput)
        $xml=[Text.UTF8Encoding]::new($false,$true).GetString([Convert]::FromBase64String($base64))
        [pscustomobject]@{succeeded=$true
            snapshot=[Management.Automation.PSSerializer]::Deserialize($xml)
            reasonCode='';native=$native;startedAt=$attemptStartedAt
            completedAt=[DateTimeOffset]::UtcNow}
    } catch {
        [pscustomobject]@{succeeded=$false;snapshot=$null
            reasonCode='COLLECTION.IDENTITY_SOURCE_FAILED';native=$null
            startedAt=$attemptStartedAt;completedAt=[DateTimeOffset]::UtcNow}
    } finally { if($null -ne $event){$event.Dispose()} }
}

function Get-LiveIdentityEnrollmentPayload {
    param([Parameter(Mandatory)] $Policy)
    $startedAt=[DateTimeOffset]::UtcNow
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $processSessionId = [Diagnostics.Process]::GetCurrentProcess().SessionId
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    $isAdministrator = $principal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator
    )
    # Only the separately frozen MDM Bridge operation may execute as SYSTEM.
    # An elevated coordinator is likewise not silently relabeled StandardUser.
    # Both cases stop before native access and keep the privileged worker and
    # Assessment User roles separate.
    $processDisposition=Get-IdentityProcessContextDisposition `
        -ProcessSid ([string]$identity.User.Value) -IsAdministrator $isAdministrator `
        -StartedAt $startedAt
    if($null -ne $processDisposition){return $processDisposition}
    $registrationAttempt=Invoke-BoundedIdentityNativeSnapshot -Policy $Policy `
        -CollectorIndex 0 -Mode 'RegistrationUser'
    # Cleanup uncertainty stops new scheduling immediately. Starting the second
    # collector while the first tree might survive would violate both attempt
    # ownership and cleanup precedence.
    Assert-IdentityCollectorCleanupVerified -Attempt $registrationAttempt
    $registrationSnapshot=$registrationAttempt.snapshot
    # The default work account belongs to the querying token. A verified WTS
    # user alone is insufficient: both SID and session must match the caller.
    # Otherwise skip that user-scoped read and retain an explicit coverage gap.
    $sameUserContext = [bool]$registrationAttempt.succeeded -and
        [bool]$registrationSnapshot.UserContextAvailable -and
        [int]$registrationSnapshot.UserError -eq 0 -and
        [string]$registrationSnapshot.UserSid -eq [string]$identity.User.Value -and
        [int]$registrationSnapshot.UserSessionId -eq $processSessionId
    $workSchoolAttempt=if ($sameUserContext) {
        Invoke-BoundedIdentityNativeSnapshot -Policy $Policy -CollectorIndex 1 -Mode 'WorkSchool'
    } else {
        [pscustomobject]@{succeeded=$false;snapshot=$null;native=$null
            reasonCode='COLLECTION.IDENTITY_USER_CONTEXT_UNAVAILABLE'
            startedAt=[DateTimeOffset]::UtcNow;completedAt=[DateTimeOffset]::UtcNow}
    }
    Assert-IdentityCollectorCleanupVerified -Attempt $workSchoolAttempt
    $workSchoolSnapshot=$workSchoolAttempt.snapshot
    $registrationFailureState=if([bool]$registrationAttempt.succeeded){''}
        elseif($registrationAttempt.reasonCode -match 'DENIED'){'Denied'}else{'Failed'}
    $workSchoolFailureState=if([bool]$workSchoolAttempt.succeeded){''}
        elseif($workSchoolAttempt.reasonCode -eq 'COLLECTION.IDENTITY_USER_CONTEXT_UNAVAILABLE'){'Unavailable'}
        elseif($workSchoolAttempt.reasonCode -match 'DENIED'){'Denied'}else{'Failed'}
    $domainState = if(-not $registrationFailureState -and
        $registrationSnapshot.DomainError -eq 0) {
        switch ([int]$registrationSnapshot.DomainJoinStatus) {
            3 { 'DomainJoined' } # NetSetupDomainName
            1 { 'Workgroup' }    # NetSetupUnjoined
            2 { 'Workgroup' }    # NetSetupWorkgroupName
            default { 'Unknown' }
        }
    } else { $null }
    $registrationAadState=if($registrationFailureState){$registrationFailureState}else{
        Get-IdentityAadSourceState -Code ([int]$registrationSnapshot.AadError) `
            -InfoPresent ([bool]$registrationSnapshot.AadInfoPresent)
    }
    $workSchoolAadState=if($workSchoolFailureState){$workSchoolFailureState}else{
        Get-IdentityAadSourceState -Code ([int]$workSchoolSnapshot.AadError) `
            -InfoPresent ([bool]$workSchoolSnapshot.AadInfoPresent)
    }
    $entraType = if ($registrationAadState -eq 'Complete') {
        if (-not [bool]$registrationSnapshot.AadInfoPresent) { 'None' }
        else { switch ([int]$registrationSnapshot.AadJoinType) {
            1 { 'EntraJoined' }
            2 { 'EntraRegistered' }
            default { 'Unknown' }
        } }
    } else { $null }
    $registrationState = if($registrationFailureState){$registrationFailureState}
    elseif ((Test-IdentityNativeAccessDeniedCode ([int]$registrationSnapshot.DomainError)) -or
        $registrationAadState -eq 'Denied') {
        'Denied'
    } elseif($registrationAadState -eq 'Malformed') {
        'Malformed'
    } elseif ($registrationSnapshot.DomainError -ne 0 -or
        $registrationAadState -ne 'Complete') {
        'Unavailable'
    } else { 'Complete' }
    if ($registrationState -eq 'Complete' -and $entraType -ne 'EntraJoined' -and -not $sameUserContext) {
        $registrationState = 'Unavailable'
    }
    $userState = if($registrationFailureState){$registrationFailureState}
    elseif (Test-IdentityNativeAccessDeniedCode ([int]$registrationSnapshot.UserError)) {
        'Denied'
    } elseif ([bool]$registrationSnapshot.UserContextAvailable -and
        [Text.Encoding]::UTF8.GetByteCount([string]$registrationSnapshot.UserAccountName) -le 256) {
        'Complete'
    } else { 'Unavailable' }
    $workSchoolState = $workSchoolAadState
    if ($workSchoolState -eq 'Complete' -and (
        -not [bool]$workSchoolSnapshot.UserContextAvailable -or
        [int]$workSchoolSnapshot.UserError -ne 0 -or
        [string]$workSchoolSnapshot.UserSid -ne [string]$identity.User.Value -or
        [int]$workSchoolSnapshot.UserSessionId -ne $processSessionId)) {
        $workSchoolState = if (Test-IdentityNativeAccessDeniedCode ([int]$workSchoolSnapshot.UserError)) {
            'Denied'
        } else { 'Unavailable' }
    }
    $workSchoolType=if($workSchoolState -eq 'Complete'){
        if (-not [bool]$workSchoolSnapshot.AadInfoPresent) { 'None' }
        else { switch([int]$workSchoolSnapshot.AadJoinType){1{'EntraJoined'}2{'EntraRegistered'}default{'Unknown'}} }
    }else{$null}
    # NetGetAadJoinInformation(NULL) prefers the device join on a joined
    # device. That result cannot prove absence of separate user work accounts.
    if ($workSchoolState -eq 'Complete' -and $workSchoolType -in @('EntraJoined','Unknown')) {
        $workSchoolState = 'Unavailable'
    }
    $workSchoolPresent = $workSchoolType -eq 'EntraRegistered'
    $payload = [pscustomobject][ordered]@{
        sourceLocale='und';registrationState=$registrationState;userContextState=$userState
        workSchoolState=$workSchoolState
        assessmentUserVerified=if($userState -eq 'Complete'){$true}else{$null}
        assessmentUserSessionId=if($userState -eq 'Complete'){[int]$registrationSnapshot.UserSessionId}else{$null}
        assessmentUserAccountName=if($userState -eq 'Complete'){[string]$registrationSnapshot.UserAccountName}else{$null}
        domainJoinState=if($registrationState -eq 'Complete'){$domainState}else{$null}
        domainName=if($registrationState -eq 'Complete' -and $domainState -eq 'DomainJoined'){
            $registrationSnapshot.DomainName
        }else{$null}
        entraRegistrationType=if($registrationState -eq 'Complete'){$entraType}else{$null}
        entraDeviceId=if($registrationState -eq 'Complete' -and $entraType -ne 'None'){
            $registrationSnapshot.DeviceId
        }else{$null}
        entraTenantId=if($registrationState -eq 'Complete' -and $entraType -ne 'None'){
            $registrationSnapshot.TenantId
        }else{$null}
        workSchoolAccountPresent=if($workSchoolState -eq 'Complete'){
            [bool]$workSchoolPresent
        }else{$null}
        workSchoolAccountIdentifier=if($workSchoolState -eq 'Complete' -and $workSchoolPresent){
            $workSchoolSnapshot.JoinUserEmail
        }else{$null}
    }
    $relationship = if ($userState -ne 'Complete') { 'Unavailable' }
        elseif ([string]::Equals([string]$identity.User.Value,
            [string]$registrationSnapshot.UserSid,[StringComparison]::OrdinalIgnoreCase)) { 'SameUser' }
        else { 'SeparateProcessIdentity' }
    [pscustomobject][ordered]@{
        payload=$payload;relationship=$relationship
        assessmentUserSid=if($userState -eq 'Complete'){[string]$registrationSnapshot.UserSid}else{''}
        executionContext='StandardUser';startedAt=$startedAt;completedAt=[DateTimeOffset]::UtcNow
        sourceFailureReason=''
        collectorAttempts=@(
            [pscustomobject]@{startedAt=$registrationAttempt.startedAt;completedAt=$registrationAttempt.completedAt
                reasonCode=[string]$registrationAttempt.reasonCode},
            [pscustomobject]@{startedAt=$workSchoolAttempt.startedAt;completedAt=$workSchoolAttempt.completedAt
                reasonCode=[string]$workSchoolAttempt.reasonCode}
        )
    }
}

function Get-IdentityCoverageReason {
    param([Parameter(Mandatory)] [string] $State)
    switch ($State) {
        'Denied' { 'COLLECTION.IDENTITY_SOURCE_DENIED' }
        'Malformed' { 'COLLECTION.IDENTITY_PAYLOAD_MALFORMED' }
        'Failed' { 'COLLECTION.IDENTITY_SOURCE_FAILED' }
        default { 'COLLECTION.IDENTITY_SOURCE_UNAVAILABLE' }
    }
}

function Invoke-IdentityEnrollmentCollection {
    param(
        [Parameter(Mandatory)] $Policy,
        [Parameter()] [switch] $Live,
        [Parameter()] [ValidateSet(
            'Workgroup','DomainJoined','EntraJoined','Registered','Mixed','Unenrolled',
            'UserContextUnavailable','StandardUser','Administrator','LocalSystem',
            'NonEnglish','Malformed','Denied'
        )] [string] $ValidationScenario = 'Workgroup'
    )

    $sourceResult = if ($Live) {
        Get-LiveIdentityEnrollmentPayload -Policy $Policy
    } else {
        $value = New-IdentityEnrollmentSyntheticPayload -Scenario $ValidationScenario
        $now=[DateTimeOffset]::UtcNow
        $value | Add-Member -NotePropertyName executionContext -NotePropertyValue 'Synthetic'
        $value | Add-Member -NotePropertyName startedAt -NotePropertyValue $now
        $value | Add-Member -NotePropertyName completedAt -NotePropertyValue $now
        $value | Add-Member -NotePropertyName sourceFailureReason -NotePropertyValue ''
        $value | Add-Member -NotePropertyName assessmentUserSid `
            -NotePropertyValue 'S-1-5-21-1000-1000-1000-1001'
        $value | Add-Member -NotePropertyName collectorAttempts -NotePropertyValue @(
            [pscustomobject]@{startedAt=$now;completedAt=$now;reasonCode=''},
            [pscustomobject]@{startedAt=$now;completedAt=$now;reasonCode=''}
        )
        $value
    }
    $payload = $sourceResult.payload
    if (-not (Test-IdentityEnrollmentCollectorPayload -Payload $payload)) {
        throw 'The Identity and Enrollment collector payload is not release-shaped.'
    }
    $runId = [Guid]::NewGuid().ToString('N')
    $startedAt = ([DateTimeOffset]$sourceResult.startedAt).ToString('o')
    $collectedAt = ([DateTimeOffset]$sourceResult.completedAt).ToString('o')
    $deviceSubject = 'subject:device:primary'
    $userSubject = 'subject:assessment-user:primary'
    $specs = @(
        @{scope='scope:identity.assessment-user-context';state=[string]$payload.userContextState;collector=0;subject=$userSubject;fields=@(
            @{id='field:identity.assessment-user.verified';property='assessmentUserVerified'},
            @{id='field:identity.assessment-user.session-id';property='assessmentUserSessionId'},
            @{id='field:identity.assessment-user.account-name';property='assessmentUserAccountName'}
        )},
        @{scope='scope:device.registration-context';state=[string]$payload.registrationState;collector=0;subject=$deviceSubject;fields=@(
            @{id='field:device.domain-join.state';property='domainJoinState'},
            @{id='field:device.domain-join.name';property='domainName';absent=$payload.domainJoinState -eq 'Workgroup'},
            @{id='field:device.entra-registration.type';property='entraRegistrationType'},
            @{id='field:device.entra-registration.device-id';property='entraDeviceId';absent=$payload.entraRegistrationType -eq 'None'},
            @{id='field:device.entra-registration.tenant-id';property='entraTenantId';absent=$payload.entraRegistrationType -eq 'None'}
        )},
        @{scope='scope:device.work-school-registration-context';state=[string]$payload.workSchoolState;collector=1;subject=$deviceSubject;fields=@(
            @{id='field:device.work-school-registration.present';property='workSchoolAccountPresent'},
            @{id='field:device.work-school-registration.identifier';property='workSchoolAccountIdentifier';absent=$payload.workSchoolAccountPresent -eq $false}
        )}
    )
    $observations = [Collections.Generic.List[object]]::new()
    $provenance = [Collections.Generic.List[object]]::new()
    $coverage = [Collections.Generic.List[object]]::new()
    $diagnostics = [Collections.Generic.List[object]]::new()
    foreach ($scope in $specs) {
        $scopeObservations = [Collections.Generic.List[string]]::new()
        if ($scope.state -eq 'Complete') {
            foreach ($field in $scope.fields) {
                $suffix = ([string]$field.id).Substring(6).Replace('.', '-')
                $observationId = "observation:$suffix`:$runId"
                $provenanceId = "provenance:$suffix`:$runId"
                $value = $payload.([string]$field.property)
                $valueState = if ($null -eq $value -and $field.ContainsKey('absent') -and $field.absent) {
                    'ObservedAbsent'
                } elseif ($null -eq $value -or (
                    $field.property -in @('domainJoinState','entraRegistrationType') -and $value -eq 'Unknown'
                )) { 'SourceReportedUnknown' } else { 'ObservedValue' }
                $observation = [ordered]@{
                    observationId=$observationId;fieldId=[string]$field.id
                    subjectId=[string]$scope.subject;provenanceId=$provenanceId
                    valueState=$valueState
                }
                if ($valueState -eq 'ObservedValue') { $observation.value=$value }
                $observations.Add([pscustomobject]$observation)
                $collector = $Policy.collectors[[int]$scope.collector]
                $provenance.Add([pscustomobject][ordered]@{
                    provenanceId=$provenanceId;fieldId=[string]$field.id
                    subjectId=[string]$scope.subject
                    sourceId=if([int]$scope.collector -eq 0){'source:windows.native.registration-user-context'}else{'source:windows.native.work-school-context'}
                    collectorId=[string]$collector.collectorId
                    collectorVersion=[string]$collector.collectorVersion
                    executionContext=[string]$sourceResult.executionContext;collectedAt=$collectedAt
                    sourceLocale=[string]$payload.sourceLocale
                })
                $scopeObservations.Add($observationId)
            }
        }
        $coverageId = "coverage:$(([string]$scope.scope).Substring(6).Replace('.', '-')):$runId"
        $coverageItem = [ordered]@{
            coverageId=$coverageId;scopeId=[string]$scope.scope;state=[string]$scope.state
            observationIds=@($scopeObservations);diagnosticIds=@()
        }
        if ($scope.state -ne 'Complete') {
            $diagnosticId = "diagnostic:$(([string]$scope.scope).Substring(6).Replace('.', '-')):$runId"
            $attemptReason=[string]$sourceResult.collectorAttempts[[int]$scope.collector].reasonCode
            $coverageItem.reasonCode = if(-not [string]::IsNullOrWhiteSpace($attemptReason)){$attemptReason
            }else{Get-IdentityCoverageReason -State ([string]$scope.state)}
            $coverageItem.diagnosticIds=@($diagnosticId)
            $diagnostics.Add([pscustomobject][ordered]@{
                diagnosticId=$diagnosticId;scopeId=[string]$scope.scope;phase='Collection'
                reasonCode=[string]$coverageItem.reasonCode
                operatorMessageId='identity.collection.unavailable'
            })
        }
        $coverage.Add([pscustomobject]$coverageItem)
    }
    $envelopes = foreach ($collectorIndex in 0,1) {
        $collector = $Policy.collectors[$collectorIndex]
        $attempt=$sourceResult.collectorAttempts[$collectorIndex]
        $collectorScopes = @($specs | Where-Object collector -eq $collectorIndex)
        $scopeIds = @($collectorScopes.scope)
        $coverageIds = @($coverage | Where-Object scopeId -in $scopeIds | ForEach-Object coverageId)
        $observationIds = @($observations | Where-Object {
            $provenanceItem = @($provenance | Where-Object provenanceId -eq $_.provenanceId)[0]
            $provenanceItem.collectorId -eq $collector.collectorId
        } | ForEach-Object observationId)
        [pscustomobject][ordered]@{
            envelopeId="envelope:identity-$collectorIndex`:$runId"
            collectorId=[string]$collector.collectorId
            collectorVersion=[string]$collector.collectorVersion
            operationId=[string]$collector.operationId;intendedScopeIds=$scopeIds
            subjectIds=@($collectorScopes.subject | Sort-Object -Unique)
            startedAt=([DateTimeOffset]$attempt.startedAt).ToString('o')
            completedAt=([DateTimeOffset]$attempt.completedAt).ToString('o')
            executionContext=[string]$sourceResult.executionContext
            attempts=1;observationIds=$observationIds;coverageIds=$coverageIds
            diagnosticIds=@($diagnostics | Where-Object scopeId -in $scopeIds | ForEach-Object diagnosticId)
        }
    }
    [pscustomobject][ordered]@{
        state='Completed';reasonCode='IDENTITY.COLLECTION_COMPLETED'
        validationScenario=if($Live){'Live'}else{$ValidationScenario}
        processRelationship=[string]$sourceResult.relationship
        privateAssessmentUserSid=if($sourceResult.PSObject.Properties['assessmentUserSid']){
            [string]$sourceResult.assessmentUserSid
        }else{''}
        payload=$payload;observations=@($observations);provenance=@($provenance)
        coverage=@($coverage);diagnostics=@($diagnostics);collectorResults=@($envelopes)
    }
}

function Add-IdentityEnrollmentEvidenceRecord {
    param(
        [Parameter(Mandatory)] $Record,
        [Parameter(Mandatory)] $CollectorResult,
        [Parameter(Mandatory)] $SystemResult,
        [Parameter(Mandatory)] $Policy
    )

    if ([string]$Record.run.evidenceProfileId -ne 'profile:device-and-firmware-readiness' -or
        @($Record.findings).Count -ne 7 -or
        [string]$CollectorResult.state -ne 'Completed' -or
        -not (Test-IdentityEnrollmentCollectorPayload -Payload $CollectorResult.payload) -or
        $null -eq $SystemResult.collectorResult) {
        throw 'Identity evidence requires accepted Device/Firmware and closed collector results.'
    }
    $runId = [string]$Record.run.runId
    $deviceSubjectId = 'subject:device:primary'
    $userSubjectId = 'subject:assessment-user:primary'
    if (@($Record.subjects | Where-Object subjectId -eq $userSubjectId).Count -eq 0) {
        $Record.subjects = @($Record.subjects) + [pscustomobject][ordered]@{
            subjectId=$userSubjectId;kind='User'
        }
    }
    $Record.provenance = @($Record.provenance) + @($CollectorResult.provenance)
    $Record.observations = @($Record.observations) + @($CollectorResult.observations)
    $Record.coverage = @($Record.coverage) + @($CollectorResult.coverage)
    $Record.diagnostics = @($Record.diagnostics) + @($CollectorResult.diagnostics)
    $Record.collectorResults = @($Record.collectorResults) + @($CollectorResult.collectorResults)

    # The predefined SYSTEM source and the standard collectors share the same
    # package-local Device subject. Composition reconstructs the closed schema
    # shape without changing its source value, operation identity, timestamps,
    # coverage, or actual execution context.
    $systemEnvelopeSource = $SystemResult.collectorResult.Envelope
    $systemObservations = @($SystemResult.collectorResult.Observations | ForEach-Object {
        $item = [pscustomobject][ordered]@{
            observationId=[string]$_.observationId;fieldId=[string]$_.fieldId
            subjectId=$deviceSubjectId;provenanceId=[string]$_.provenanceId
            valueState=[string]$_.valueState
        }
        if ($_.PSObject.Properties['value']) {
            $item | Add-Member -NotePropertyName value -NotePropertyValue $_.value
        }
        $item
    })
    $systemProvenance = @($SystemResult.collectorResult.Provenance | ForEach-Object {
        [pscustomobject][ordered]@{
            provenanceId=[string]$_.provenanceId;fieldId=[string]$_.fieldId
            subjectId=$deviceSubjectId;sourceId=[string]$_.sourceId
            collectorId=[string]$_.collectorId;collectorVersion=[string]$_.collectorVersion
            executionContext=[string]$_.executionContext;collectedAt=[string]$_.collectedAt
            sourceLocale=[string]$_.sourceLocale
        }
    })
    $systemCoverage = @($SystemResult.collectorResult.Coverage | ForEach-Object {
        $item = [ordered]@{
            coverageId=[string]$_.coverageId;scopeId=[string]$_.scopeId
            state=[string]$_.state;observationIds=@($_.observationIds)
            diagnosticIds=@($_.diagnosticIds)
        }
        if ([string]$_.state -ne 'Complete' -and $_.PSObject.Properties['reasonCode']) {
            $item.reasonCode=[string]$_.reasonCode
        }
        [pscustomobject]$item
    })
    $systemDiagnostics = @($SystemResult.collectorResult.Diagnostics)
    $systemEnvelope = [pscustomobject][ordered]@{
        envelopeId=[string]$systemEnvelopeSource.envelopeId
        collectorId=[string]$systemEnvelopeSource.collectorId
        collectorVersion=[string]$systemEnvelopeSource.collectorVersion
        operationId=[string]$systemEnvelopeSource.operationId
        intendedScopeIds=@($systemEnvelopeSource.intendedScopeIds)
        subjectIds=@($deviceSubjectId);startedAt=[string]$systemEnvelopeSource.startedAt
        completedAt=[string]$systemEnvelopeSource.completedAt
        executionContext=[string]$systemEnvelopeSource.executionContext
        attempts=[int]$systemEnvelopeSource.attempts
        observationIds=@($systemEnvelopeSource.observationIds)
        coverageIds=@($systemEnvelopeSource.coverageIds)
        diagnosticIds=@($systemEnvelopeSource.diagnosticIds)
    }
    $Record.provenance = @($Record.provenance) + $systemProvenance
    $Record.observations = @($Record.observations) + $systemObservations
    $Record.coverage = @($Record.coverage) + $systemCoverage
    $Record.diagnostics = @($Record.diagnostics) + $systemDiagnostics
    $Record.collectorResults = @($Record.collectorResults) + $systemEnvelope
    $Record.run.evidenceProfileId = [string]$Policy.evidenceProfileId
    $Record.run.outcome = if (@($Record.coverage | Where-Object state -ne 'Complete').Count -eq 0) {
        'Completed'
    } else { 'CompletedWithGaps' }
    $Record
}

function New-IdentityEnrollmentFinding {
    param(
        [Parameter(Mandatory)] [string] $Kind,
        [Parameter(Mandatory)] [string] $RuleId,
        [Parameter(Mandatory)] $Record,
        [Parameter(Mandatory)] [string] $SubjectId,
        [Parameter(Mandatory)] [string[]] $FieldIds
    )
    [pscustomobject][ordered]@{
        findingId="finding:$Kind`:$($Record.run.runId)";ruleId=$RuleId
        targetSubjectId=$SubjectId;outcome='Indeterminate'
        reasonCode='FINDING.EVALUATION_PENDING'
        evidenceReferences=@($Record.observations | Where-Object fieldId -in $FieldIds |
            ForEach-Object { [pscustomobject][ordered]@{
                observationId=$_.observationId;fieldId=$_.fieldId;subjectId=$_.subjectId
            } })
    }
}

function Set-IdentityEnrollmentFindingResult {
    param($Finding,[string]$Outcome,[string]$ReasonCode='')
    $Finding.outcome=$Outcome
    if ($ReasonCode) { $Finding.reasonCode=$ReasonCode }
    else { $Finding.PSObject.Properties.Remove('reasonCode') }
}

function Get-IdentityRuleNativeFailureReason {
    param([Parameter(Mandatory)] $NativeResult)
    if($NativeResult.FailureStage -eq
        [WinPCInfo.ProcessSupervisor.NativeFailureStage]::TerminationIncomplete -or
        ($NativeResult.Started -and -not [bool]$NativeResult.CompleteOwnedTreeAbsent)){
        return 'IDENTITY.RULE_CLEANUP_INCOMPLETE'
    }
    'IDENTITY.RULE_BOUNDARY_FAILED'
}

function Invoke-IdentityEnrollmentRuleEvaluation {
    param(
        [Parameter(Mandatory)] $Rule,
        [Parameter(Mandatory)] $Inputs,
        [Parameter()] [switch] $SimulateUncooperativeRule
    )
    Initialize-ProcessSupervisorNativeType
    $maximumMilliseconds=[int]$Rule.deadlineMilliseconds
    $terminationMilliseconds=[Math]::Min(500,[Math]::Max(1,
        [Math]::Floor($maximumMilliseconds/4)))
    $activeMilliseconds=[Math]::Max(1,$maximumMilliseconds-$terminationMilliseconds)
    $inputBytes=[Text.UTF8Encoding]::new($false).GetBytes(
        [Management.Automation.PSSerializer]::Serialize($Inputs,5)
    )
    if($inputBytes.Length -gt 4096){
        throw "The $($Rule.operationId) Rule Evaluation exceeded its input bound."
    }
    # Threat: even a release-owned pure rule can regress into an infinite loop.
    # Mechanism: this fixed evaluator runs in the same suspended, kill-on-close
    # Job boundary as collectors. Trust assumption: the parent selects the
    # closed rule kind and inputs; no caller script enters the child. Safe
    # failure: deadline or malformed output proves the worker absent and admits
    # no finding.
    $childScript=@'
$ErrorActionPreference='Stop'
try {
    if($env:WINPCINFO_IDENTITY_RULE_TEST_HANG -eq '1'){
        [Threading.Thread]::Sleep(30000)
    }
    $utf8=[Text.UTF8Encoding]::new($false,$true)
    $xml=$utf8.GetString([Convert]::FromBase64String($env:WINPCINFO_IDENTITY_RULE_INPUT))
    $input=[Management.Automation.PSSerializer]::Deserialize($xml)
    $result=switch($env:WINPCINFO_IDENTITY_RULE_KIND){
        'assessment-user-context' {
            if($input.verifiedState -eq 'ObservedValue' -and [bool]$input.verifiedValue){
                [pscustomobject]@{outcome='ExpectedCondition'}
            }else{[pscustomobject]@{outcome='Indeterminate';reasonCode='FINDING.ASSESSMENT_USER_CONTEXT_UNAVAILABLE'}}
        }
        'device-registration-context' {
            if($input.domainState -eq 'ObservedValue' -and $input.entraState -eq 'ObservedValue'){
                [pscustomobject]@{outcome='Informational'}
            }else{[pscustomobject]@{outcome='Indeterminate';reasonCode='FINDING.REGISTRATION_CONTEXT_INCOMPLETE'}}
        }
        'work-school-enrollment-context' {
            if($input.workSchoolState -eq 'ObservedValue' -and $input.mdmState -eq 'ObservedValue'){
                [pscustomobject]@{outcome='Informational'}
            }else{[pscustomobject]@{outcome='Indeterminate';reasonCode='FINDING.ENROLLMENT_CONTEXT_INCOMPLETE'}}
        }
        default { throw 'Unknown identity rule.' }
    }
    $output=[Management.Automation.PSSerializer]::Serialize($result,3)
    [Console]::Out.Write([Convert]::ToBase64String($utf8.GetBytes($output)))
}catch{[Console]::Error.Write('Identity rule failed.');exit 1}
'@
    $encodedChild=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($childScript))
    $executable=[IO.Path]::GetFullPath((Join-Path $PSHOME 'pwsh.exe'))
    if(-not [IO.File]::Exists($executable) -or -not [string]::Equals(
            $executable,[Environment]::ProcessPath,[StringComparison]::OrdinalIgnoreCase)){
        throw "The $($Rule.operationId) Rule Evaluation boundary is unavailable."
    }
    $environment=[Collections.Generic.Dictionary[string,string]]::new(
        [StringComparer]::OrdinalIgnoreCase
    )
    $environment['SystemRoot']=[Environment]::GetFolderPath('Windows')
    $environment['WINPCINFO_IDENTITY_RULE_KIND']=[string]$Rule.findingKind
    $environment['WINPCINFO_IDENTITY_RULE_INPUT']=[Convert]::ToBase64String($inputBytes)
    if($SimulateUncooperativeRule){$environment['WINPCINFO_IDENTITY_RULE_TEST_HANG']='1'}
    $eventName="Local\WINPCInfo-IdentityRule-$([Guid]::NewGuid().ToString('N'))"
    [bool]$created=$false;$event=$null
    try{
        $event=[Threading.EventWaitHandle]::new($false,
            [Threading.EventResetMode]::ManualReset,$eventName,[ref]$created)
        if(-not $created){throw "The $($Rule.operationId) Rule Evaluation event is unavailable."}
        $native=[WinPCInfo.ProcessSupervisor.NativeRunner]::Run(
            $executable,@('-NoLogo','-NoProfile','-NonInteractive','-EncodedCommand',$encodedChild),
            $PSHOME,$environment,$activeMilliseconds,2048,2048,
            [Threading.CancellationToken]::None,$event,1,$terminationMilliseconds,$false
        )
        $nativeFailureReason=Get-IdentityRuleNativeFailureReason -NativeResult $native
        if($nativeFailureReason -eq 'IDENTITY.RULE_CLEANUP_INCOMPLETE'){
            $exception=[InvalidOperationException]::new(
                "The $($Rule.operationId) Rule Evaluation cleanup was not verified."
            )
            $exception.Data['ReasonCode']=$nativeFailureReason
            throw $exception
        }
        if(-not $native.Started -or
            $native.FailureStage -ne [WinPCInfo.ProcessSupervisor.NativeFailureStage]::None -or
            $native.ExitCode -ne 0 -or $native.StandardOutputExceeded -or
            $native.StandardErrorExceeded -or $native.StandardErrorBytes -ne 0){
            throw "The $($Rule.operationId) Rule Evaluation violated its frozen deadline or boundary."
        }
        $base64=[Text.UTF8Encoding]::new($false,$true).GetString($native.StandardOutput)
        $xml=[Text.UTF8Encoding]::new($false,$true).GetString([Convert]::FromBase64String($base64))
        $value=[Management.Automation.PSSerializer]::Deserialize($xml)
        if([string]$value.outcome -notin @(
            'ExpectedCondition','NeedsAttention','Informational','Indeterminate','NotApplicable')){
            throw "The $($Rule.operationId) Rule Evaluation returned an invalid result."
        }
        $value
    }finally{if($null -ne $event){$event.Dispose()}}
}

function Complete-ValidatedIdentityEnrollmentAssessmentRecord {
    param(
        [Parameter(Mandatory)] $Record,
        [Parameter(Mandatory)] $Policy,
        [Parameter(Mandatory)] $ContractValidation
    )
    if (-not [bool]$ContractValidation.accepted -or
        $ContractValidation.reasonCode -ne 'CONTRACT.ACCEPTED' -or
        @($Record.findings).Count -ne 7 -or
        [string]$Record.run.evidenceProfileId -ne [string]$Policy.evidenceProfileId) {
        throw 'Identity rules require an accepted source-only combined record.'
    }
    $rules=@{}
    foreach($rule in @($Policy.rules)){$rules[[string]$rule.findingKind]=$rule}
    $userSubjectId='subject:assessment-user:primary';$deviceSubjectId='subject:device:primary'
    $userFinding=New-IdentityEnrollmentFinding -Kind 'assessment-user-context' `
        -RuleId $rules['assessment-user-context'].ruleId -Record $Record `
        -SubjectId $userSubjectId -FieldIds @(
            'field:identity.assessment-user.verified','field:identity.assessment-user.session-id',
            'field:identity.assessment-user.account-name'
        )
    $registrationFinding=New-IdentityEnrollmentFinding -Kind 'device-registration-context' `
        -RuleId $rules['device-registration-context'].ruleId -Record $Record `
        -SubjectId $deviceSubjectId -FieldIds @(
            'field:device.domain-join.state','field:device.domain-join.name',
            'field:device.entra-registration.type','field:device.entra-registration.device-id',
            'field:device.entra-registration.tenant-id'
        )
    $enrollmentFinding=New-IdentityEnrollmentFinding -Kind 'work-school-enrollment-context' `
        -RuleId $rules['work-school-enrollment-context'].ruleId -Record $Record `
        -SubjectId $deviceSubjectId -FieldIds @(
            'field:device.work-school-registration.present','field:device.work-school-registration.identifier',
            'field:device.mdm-bridge.provider-available'
        )
    foreach($pair in @(
        @{finding=$userFinding;rule=$rules['assessment-user-context']},
        @{finding=$registrationFinding;rule=$rules['device-registration-context']},
        @{finding=$enrollmentFinding;rule=$rules['work-school-enrollment-context']}
    )){
        if(@($pair.finding.evidenceReferences).Count -gt [int]$pair.rule.maximumInputObservations){
            throw 'An identity rule widened beyond its frozen evidence bound.'
        }
    }
    $byField=@{};foreach($observation in @($Record.observations)){
        $byField[[string]$observation.fieldId]=$observation
    }
    $verified=$byField['field:identity.assessment-user.verified']
    $userResult=Invoke-IdentityEnrollmentRuleEvaluation `
        -Rule $rules['assessment-user-context'] -Inputs ([pscustomobject]@{
            verifiedState=if($null -eq $verified){''}else{[string]$verified.valueState}
            verifiedValue=if($null -eq $verified -or -not $verified.PSObject.Properties['value']){
                $false}else{[bool]$verified.value}
        })
    Set-IdentityEnrollmentFindingResult $userFinding ([string]$userResult.outcome) `
        $(if($userResult.PSObject.Properties['reasonCode']){[string]$userResult.reasonCode}else{''})
    $domain=$byField['field:device.domain-join.state']
    $entra=$byField['field:device.entra-registration.type']
    $registrationResult=Invoke-IdentityEnrollmentRuleEvaluation `
        -Rule $rules['device-registration-context'] -Inputs ([pscustomobject]@{
            domainState=if($null -eq $domain){''}else{[string]$domain.valueState}
            entraState=if($null -eq $entra){''}else{[string]$entra.valueState}
        })
    Set-IdentityEnrollmentFindingResult $registrationFinding ([string]$registrationResult.outcome) `
        $(if($registrationResult.PSObject.Properties['reasonCode']){[string]$registrationResult.reasonCode}else{''})
    $workSchool=$byField['field:device.work-school-registration.present']
    $mdm=$byField['field:device.mdm-bridge.provider-available']
    $enrollmentResult=Invoke-IdentityEnrollmentRuleEvaluation `
        -Rule $rules['work-school-enrollment-context'] -Inputs ([pscustomobject]@{
            workSchoolState=if($null -eq $workSchool){''}else{[string]$workSchool.valueState}
            mdmState=if($null -eq $mdm){''}else{[string]$mdm.valueState}
        })
    Set-IdentityEnrollmentFindingResult $enrollmentFinding ([string]$enrollmentResult.outcome) `
        $(if($enrollmentResult.PSObject.Properties['reasonCode']){[string]$enrollmentResult.reasonCode}else{''})
    $Record.findings=@($Record.findings)+@($userFinding,$registrationFinding,$enrollmentFinding)

    # A local registration or provider signal never proves tenant assignment,
    # compliance, licensing, or organizational intent. The product creates
    # bounded questions for an authorized tenant-side role and performs no
    # authentication or network request itself.
    $findingIds=@([string]$registrationFinding.findingId,[string]$enrollmentFinding.findingId)
    $Record.recommendations=@($Record.recommendations)+@($Policy.discoveryTasks | ForEach-Object {
        [pscustomobject][ordered]@{
            recommendationId="recommendation:$(([string]$_.definitionId).Substring(5).Replace('/','-')):$($Record.run.runId)"
            definitionId=[string]$_.definitionId;kind='TenantSideDiscoveryTask'
            findingIds=$findingIds
        }
    })
    $Record.run.outcome=if(@($Record.coverage|Where-Object state -ne 'Complete').Count -eq 0){
        'Completed'
    }else{'CompletedWithGaps'}
    $Record
}

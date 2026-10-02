# Internal ARM channel for the admitted round adapter.
# Construction supplies exact request routes, never live authority. The outer
# factory must validate the private approval, pinned inputs and recovery first.
# Injected requests use this same validation and token/response interpretation.
# No network operation occurs while this module is sourced or constructed.

function ConvertFrom-AzureArmPrivateJson {
    param([Parameter(Mandatory)][byte[]] $Bytes)
    if ($Bytes.Length -eq 0 -or $Bytes.Length -gt 4194304) {
        throw 'VALIDATION.SERVICE_RESPONSE_INVALID'
    }
    $document = $null
    try {
        $text = [Text.UTF8Encoding]::new($false, $true).GetString($Bytes)
        $options = [System.Text.Json.JsonDocumentOptions]::new()
        $options.MaxDepth = 24
        $document = [System.Text.Json.JsonDocument]::Parse($text, $options)
        Assert-AzureArmJsonNames -Element $document.RootElement
        ConvertFrom-Json -InputObject $text -AsHashtable -Depth 24 -ErrorAction Stop
    }
    catch { throw 'VALIDATION.SERVICE_RESPONSE_INVALID' }
    finally { if ($null -ne $document) { $document.Dispose() } }
}

function Assert-AzureArmJsonNames {
    param([Parameter(Mandatory)][System.Text.Json.JsonElement] $Element)
    if ($Element.ValueKind -eq [System.Text.Json.JsonValueKind]::Object) {
        $names = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($property in $Element.EnumerateObject()) {
            if (-not $names.Add($property.Name)) { throw 'VALIDATION.SERVICE_RESPONSE_INVALID' }
            Assert-AzureArmJsonNames -Element $property.Value
        }
    }
    elseif ($Element.ValueKind -eq [System.Text.Json.JsonValueKind]::Array) {
        foreach ($item in $Element.EnumerateArray()) {
            Assert-AzureArmJsonNames -Element $item
        }
    }
}

function Assert-AzureArmProtocolFields {
    param(
        [Parameter(Mandatory)][Collections.IDictionary] $Document,
        [Parameter(Mandatory)][string[]] $Names
    )
    # Optional fields must not become absent because their casing is malformed.
    # This operates on protocol objects only, never user-defined tag names.
    foreach ($field in $Document.Keys) {
        foreach ($canonicalField in $Names) {
            if ([StringComparer]::OrdinalIgnoreCase.Equals([string]$field,$canonicalField) -and
                -not [StringComparer]::Ordinal.Equals([string]$field,$canonicalField)) {
                throw 'VALIDATION.SERVICE_RESPONSE_INVALID'
            }
        }
    }
}

function Assert-AzureArmDispatchRequest {
    param([Parameter(Mandatory)] $Request)
    $imds = 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https%3A%2F%2Fmanagement.azure.com%2F'
    $parsed = $null
    if ($Request.CancellationToken -isnot [Threading.CancellationToken] -or
        $Request.DeadlineUtc -isnot [DateTimeOffset] -or
        $Request.TimeoutMilliseconds -isnot [int] -or
        $Request.TimeoutMilliseconds -lt 1 -or $Request.TimeoutMilliseconds -gt 30000) {
        throw 'VALIDATION.SERVICE_REQUEST_INVALID'
    }
    if ([string] $Request.Uri -ceq $imds) {
        if ($Request.Method -cne 'GET' -or $null -ne $Request.Body -or
            $Request.Headers -isnot [Collections.IDictionary] -or
            $Request.Headers.Count -ne 1 -or $Request.Headers.Metadata -cne 'true' -or
            [long] $Request.MaximumBytes -ne 131072) {
            throw 'VALIDATION.SERVICE_REQUEST_INVALID'
        }
        return
    }
    if (-not [uri]::TryCreate([string] $Request.Uri, [UriKind]::Absolute, [ref] $parsed) -or
        [string] $Request.Uri -cnotmatch '\Ahttps://management\.azure\.com/' -or
        $parsed.Scheme -cne 'https' -or $parsed.Host -cne 'management.azure.com' -or
        $parsed.Port -ne 443 -or $parsed.UserInfo -ne '' -or $parsed.Fragment -ne '' -or
        $Request.Method -cnotin @('GET','PUT','POST','DELETE') -or
        $Request.Headers -isnot [Collections.IDictionary] -or
        $Request.Headers.Count -ne 2 -or $Request.Headers.Accept -cne 'application/json' -or
        [string] $Request.Headers.Authorization -cnotmatch '\ABearer [A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\z' -or
        [long] $Request.MaximumBytes -ne 4194304) {
        throw 'VALIDATION.SERVICE_REQUEST_INVALID'
    }
}

function Invoke-AzureArmHttpRequest {
    param(
        [Parameter(Mandatory)] $Request,
        [Parameter()][Net.Http.HttpMessageHandler] $InternalMessageHandler
    )
    # Defense in depth: never dispatch a bearer token to a URI derived from
    # mutable metadata or a nextLink. The native sender independently checks
    # origin/header separation even after the channel validates its route.
    Assert-AzureArmDispatchRequest -Request $Request
    # Never inherit HTTP proxy routing for IMDS; redirects are forbidden for
    # both endpoints so an Authorization header cannot follow a substituted URI.
    # The internal CLR message-handler seam exercises real HttpClient framing
    # and stream bounds without sockets. Ordinary channels never bind this
    # parameter; service injection already marks their evidence non-qualifying.
    $handler = $InternalMessageHandler
    if ($null -eq $handler) {
        $handler = [Net.Http.HttpClientHandler]::new()
        $handler.AllowAutoRedirect = $false
        $handler.UseProxy = $false
    }
    $client = [Net.Http.HttpClient]::new($handler)
    $remaining = [long] [Math]::Ceiling(
        ($Request.DeadlineUtc - [DateTimeOffset]::UtcNow).TotalMilliseconds)
    if ($Request.CancellationToken.IsCancellationRequested -or $remaining -le 0) {
        try { $client.Dispose() } catch { }
        throw 'VALIDATION.ROUND_INTERRUPTED'
    }
    $timeout = [int] [Math]::Min([long] $Request.TimeoutMilliseconds, $remaining)
    $client.Timeout = [TimeSpan]::FromMilliseconds($timeout)
    $message = [Net.Http.HttpRequestMessage]::new(
        [Net.Http.HttpMethod]::new([string] $Request.Method), [uri] $Request.Uri)
    $response = $null
    $stream = $null
    $cancel = [Threading.CancellationTokenSource]::CreateLinkedTokenSource(
        $Request.CancellationToken, [Threading.CancellationToken]::None)
    $cancel.CancelAfter($timeout)
    $failureReason = $null
    $result = $null
    $cleanupFailed = $false
    try {
        foreach ($name in $Request.Headers.Keys) {
            if (-not $message.Headers.TryAddWithoutValidation($name, [string] $Request.Headers[$name])) {
                throw 'VALIDATION.SERVICE_REQUEST_INVALID'
            }
        }
        if ($null -ne $Request.Body) {
            $message.Content = [Net.Http.ByteArrayContent]::new([byte[]] $Request.Body)
            $message.Content.Headers.ContentType = [Net.Http.Headers.MediaTypeHeaderValue]::new('application/json')
        }
        $response = $client.SendAsync($message,
            [Net.Http.HttpCompletionOption]::ResponseHeadersRead,
            $cancel.Token).GetAwaiter().GetResult()
        if ($null -ne $response.Content.Headers.ContentLength -and
            $response.Content.Headers.ContentLength -gt [long] $Request.MaximumBytes) {
            throw 'VALIDATION.SERVICE_RESPONSE_INVALID'
        }
        $stream = $response.Content.ReadAsStreamAsync($cancel.Token).GetAwaiter().GetResult()
        $buffer = [byte[]]::new(8192)
        $memory = [IO.MemoryStream]::new()
        try {
            while ($true) {
                $count = $stream.ReadAsync($buffer, 0, $buffer.Length,
                    $cancel.Token).GetAwaiter().GetResult()
                if ($count -eq 0) { break }
                if ($memory.Length + $count -gt [long] $Request.MaximumBytes) {
                    throw 'VALIDATION.SERVICE_RESPONSE_INVALID'
                }
                $memory.Write($buffer, 0, $count)
            }
            $result = [pscustomobject]@{
                StatusCode = [int] $response.StatusCode
                Uri = [string] $response.RequestMessage.RequestUri.AbsoluteUri
                Body = $memory.ToArray()
            }
        }
        finally {
            [Array]::Clear($buffer, 0, $buffer.Length)
            $memory.Dispose()
        }
    }
    catch {
        if ($Request.CancellationToken.IsCancellationRequested -or
            [DateTimeOffset]::UtcNow -ge $Request.DeadlineUtc) {
            $failureReason = 'VALIDATION.ROUND_INTERRUPTED'
        }
        else { $failureReason = 'VALIDATION.SERVICE_TRANSPORT_FAILED' }
    }
    finally {
        # Attempt every cleanup independently. Disposal faults must not skip
        # later handles or expose private exception text over a closed reason.
        foreach ($ownedResource in @($stream,$response,$message,$cancel,$client)) {
            if ($null -eq $ownedResource) { continue }
            try { $ownedResource.Dispose() }
            catch { $cleanupFailed = $true }
        }
    }
    if ($null -ne $failureReason) { throw $failureReason }
    if ($cleanupFailed) { throw 'VALIDATION.SERVICE_TRANSPORT_FAILED' }
    $result
}

function New-AzureValidationArmChannel {
    param(
        [Parameter(Mandatory)][guid] $ExpectedPrincipalId,
        [Parameter(Mandatory)][guid] $ExpectedTenantId,
        [Parameter(Mandatory)][string] $ExpectedIdentityResourceId,
        [Parameter(Mandatory)][object[]] $Routes,
        [Parameter(Mandatory)][DateTimeOffset] $DeadlineUtc,
        [Parameter()][Threading.CancellationToken] $CancellationToken = [Threading.CancellationToken]::None,
        [Parameter()][scriptblock] $SendRequest,
        [Parameter()][scriptblock] $UtcNow = { [DateTimeOffset]::UtcNow }
    )
    if ($ExpectedPrincipalId -eq [guid]::Empty -or $ExpectedTenantId -eq [guid]::Empty -or
        $ExpectedIdentityResourceId -cnotmatch '\A/subscriptions/[0-9a-fA-F-]{36}/resourceGroups/[A-Za-z0-9_.()-]+/providers/Microsoft.Compute/virtualMachines/[A-Za-z0-9_.()-]+\z' -or
        $Routes.Count -lt 1 -or $Routes.Count -gt 256) {
        throw 'VALIDATION.SERVICE_REQUEST_INVALID'
    }
    $clockValues = @(& $UtcNow)
    if ($clockValues.Count -ne 1 -or $clockValues[0] -isnot [DateTimeOffset] -or
        $DeadlineUtc -le $clockValues[0] -or $DeadlineUtc -gt $clockValues[0].AddHours(6)) {
        throw 'VALIDATION.SERVICE_REQUEST_INVALID'
    }
    $catalog = [Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
    foreach ($route in $Routes) {
        if ($route -isnot [Collections.IDictionary] -or
            @($route.Keys | Where-Object { $_ -notin @('Name','Method','Path','ApiVersion','Paginated','ScopePrefix','ResourceType') }).Count -ne 0 -or
            [string] $route.Name -cnotmatch '\A[A-Za-z][A-Za-z0-9]{0,63}\z' -or
            [string] $route.Method -cnotin @('GET','PUT','DELETE','POST') -or
            [string] $route.Path -cnotmatch '\A/subscriptions/[0-9a-fA-F-]{36}/[A-Za-z0-9_./()-]+\z' -or
            [string] $route.Path -match '(^|/)\.\.?(/|$)|//|/\z' -or
            [string] $route.ApiVersion -cnotmatch '\A\d{4}-\d{2}-\d{2}(-preview)?\z' -or
            $route.Paginated -isnot [bool] -or
            ($route.Paginated -and $route.Method -cne 'GET')) {
            throw 'VALIDATION.SERVICE_REQUEST_INVALID'
        }
        if ($route.Paginated -and (
            [string] $route.ScopePrefix -cnotmatch '\A/subscriptions/[0-9a-fA-F-]{36}(/resourceGroups/[A-Za-z0-9_.()-]+)?\z' -or
            -not ([string] $route.Path).StartsWith(([string] $route.ScopePrefix + '/'), [StringComparison]::OrdinalIgnoreCase) -or
            ([string] $route.ResourceType -cne '*' -and
                [string] $route.ResourceType -cnotmatch '\AMicrosoft\.[A-Za-z0-9]+/[A-Za-z0-9]+(/[A-Za-z0-9]+)*\z'))) {
            throw 'VALIDATION.SERVICE_REQUEST_INVALID'
        }
        # Clone the route: mutation of a caller's mutable dictionary cannot
        # widen the channel after the outer round factory has admitted it.
        if ($catalog.ContainsKey([string] $route.Name)) { throw 'VALIDATION.SERVICE_REQUEST_INVALID' }
        $values = [Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
        $values.Add('Method', [string] $route.Method)
        $values.Add('Path', [string] $route.Path)
        $values.Add('ApiVersion', [string] $route.ApiVersion)
        $values.Add('Paginated', [bool] $route.Paginated)
        $values.Add('ScopePrefix', [string] $route.ScopePrefix)
        $values.Add('ResourceType', [string] $route.ResourceType)
        $catalog.Add([string] $route.Name,
            [Collections.ObjectModel.ReadOnlyDictionary[string,object]]::new($values))
    }
    $kind = 'ManagedIdentity'
    if ($null -eq $SendRequest) {
        $SendRequest = { param($request) Invoke-AzureArmHttpRequest -Request $request }
    }
    else { $kind = 'InjectedNonQualifying' }
    if ($PSBoundParameters.ContainsKey('UtcNow')) { $kind = 'InjectedNonQualifying' }
    $binding = [Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
    $binding.Add('Kind', $kind)
    $binding.Add('PrincipalId', $ExpectedPrincipalId.ToString('D'))
    $binding.Add('TenantId', $ExpectedTenantId.ToString('D'))
    $binding.Add('IdentityResourceId', $ExpectedIdentityResourceId)
    $binding.Add('Routes', [Collections.ObjectModel.ReadOnlyDictionary[string,object]]::new($catalog))
    $binding.Add('Send', $SendRequest)
    $binding.Add('Clock', $UtcNow)
    $binding.Add('DeadlineUtc', $DeadlineUtc)
    $binding.Add('CancellationToken', $CancellationToken)
    [Collections.ObjectModel.ReadOnlyDictionary[string,object]]::new($binding)
}

function Assert-AzureArmChannelActive {
    param([Parameter(Mandatory)] $Channel)
    $clockValues = @(& $Channel.Clock)
    if ($clockValues.Count -ne 1 -or $clockValues[0] -isnot [DateTimeOffset]) {
        throw 'VALIDATION.ROUND_INTERRUPTED'
    }
    $remaining = [long] [Math]::Ceiling(
        ($Channel.DeadlineUtc - $clockValues[0]).TotalMilliseconds)
    if ($Channel.CancellationToken.IsCancellationRequested -or $remaining -le 0) {
        throw 'VALIDATION.ROUND_INTERRUPTED'
    }
    [int] [Math]::Min(30000L, $remaining)
}

function Invoke-AzureArmBoundedRequest {
    param([Parameter(Mandatory)] $Channel, [Parameter(Mandatory)] $Request)
    # Ordinary work channels stop on cancellation/cutoff. Cleanup uses a
    # separately admitted GET/DELETE-only channel with its own bounded deadline;
    # a round expiry never authorizes abandoning or broadening cleanup.
    $timeout = Assert-AzureArmChannelActive -Channel $Channel
    $Request | Add-Member -NotePropertyName TimeoutMilliseconds -NotePropertyValue $timeout
    $Request | Add-Member -NotePropertyName DeadlineUtc -NotePropertyValue $Channel.DeadlineUtc
    $Request | Add-Member -NotePropertyName CancellationToken -NotePropertyValue $Channel.CancellationToken
    # Injected/native senders share the exact endpoint/header checks.
    Assert-AzureArmDispatchRequest -Request $Request
    try {
        $results = @(& $Channel.Send $Request)
        if ($results.Count -ne 1) { throw 'invalid' }
        $response = $results[0]
        if ($response.StatusCode -isnot [int] -or
            $response.Body -isnot [byte[]] -or
            $response.Body.Length -gt [long] $Request.MaximumBytes -or
            [string] $response.Uri -cne [string] $Request.Uri -or
            $response.StatusCode -lt 100 -or $response.StatusCode -gt 599 -or
            ($response.StatusCode -ge 300 -and $response.StatusCode -lt 400)) {
            throw 'invalid'
        }
    }
    catch {
        # A cancellation/expiry thrown during native I/O retains its closed
        # interruption reason; private service exception text is never emitted.
        $null = Assert-AzureArmChannelActive -Channel $Channel
        throw 'VALIDATION.SERVICE_TRANSPORT_FAILED'
    }
    $null = Assert-AzureArmChannelActive -Channel $Channel
    $response
}

function Get-AzureArmManagedIdentityToken {
    param([Parameter(Mandatory)] $Channel)
    # Fixed VM IMDS protocol; IDENTITY_ENDPOINT, user login and stored secrets
    # are deliberately not discovery sources. The expected system identity is
    # bound to its VM resource ID/principal/tenant by the outer approval.
    $uri = 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https%3A%2F%2Fmanagement.azure.com%2F'
    $response = Invoke-AzureArmBoundedRequest -Channel $Channel -Request ([pscustomobject]@{
        Method = 'GET'; Uri = $uri; Headers = @{ Metadata = 'true' }
        Body = $null; MaximumBytes = 131072
    })
    if ($response.StatusCode -ne 200) { throw 'VALIDATION.IDENTITY_UNAVAILABLE' }
    try {
        $token = ConvertFrom-AzureArmPrivateJson -Bytes $response.Body
        if ($token -isnot [Collections.IDictionary] -or
            $token.token_type -cne 'Bearer' -or
            $token.resource -cne 'https://management.azure.com/' -or
            $token.access_token -isnot [string] -or
            $token.access_token.Length -gt 65536 -or
            $token.access_token -cnotmatch '\A[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\z' -or
            [string] $token.expires_on -cnotmatch '\A[0-9]{1,12}\z') { throw 'invalid' }
        $payload = $token.access_token.Split('.')[1].Replace('-','+').Replace('_','/')
        if ($payload.Length % 4 -eq 1) { throw 'invalid' }
        $payload = $payload.PadRight($payload.Length + ((4 - ($payload.Length % 4)) % 4), '=')
        $claims = ConvertFrom-AzureArmPrivateJson -Bytes ([Convert]::FromBase64String($payload))
        $now = [DateTimeOffset] (& $Channel.Clock)
        $expiration = [DateTimeOffset]::FromUnixTimeSeconds([long] $token.expires_on)
        if ($claims -isnot [Collections.IDictionary] -or
            [string] $claims.oid -cne $Channel.PrincipalId -or
            [string] $claims.tid -cne $Channel.TenantId -or
            -not [StringComparer]::OrdinalIgnoreCase.Equals(
                [string] $claims.xms_mirid, [string] $Channel.IdentityResourceId) -or
            [string] $claims.aud -cnotin @('https://management.azure.com/', 'https://management.core.windows.net/') -or
            ($claims.exp -isnot [long] -and $claims.exp -isnot [int]) -or
            [long] $claims.exp -ne [long] $token.expires_on -or
            $expiration -le $now.AddMinutes(2) -or
            $expiration -gt $now.AddHours(24)) { throw 'invalid' }
        # Claims are an identity mismatch guard, not local JWT authentication.
        # The fixed ARM service authenticates the token. Never expose either
        # raw token or claims in public outcomes or caught exception messages.
        [string] $token.access_token
    }
    catch { throw 'VALIDATION.IDENTITY_UNAVAILABLE' }
}

function Resolve-AzureArmRouteUri {
    param(
        [Parameter(Mandatory)] $Route,
        [Parameter()][string] $Continuation
    )
    if ([string] $Route.Path -cnotmatch '\A/subscriptions/[0-9a-fA-F-]{36}/[A-Za-z0-9_./()-]+\z' -or
        [string] $Route.Path -match '(^|/)\.\.?(/|$)|//|/\z' -or
        [string] $Route.ApiVersion -cnotmatch '\A\d{4}-\d{2}-\d{2}(-preview)?\z') {
        throw 'VALIDATION.SERVICE_REQUEST_INVALID'
    }
    $base = 'https://management.azure.com' + $Route.Path + '?api-version=' + $Route.ApiVersion
    if ([string]::IsNullOrEmpty($Continuation)) { return $base }
    if (-not $Route.Paginated -or $Continuation.Length -gt 16384) {
        throw 'VALIDATION.SERVICE_RESPONSE_INVALID'
    }
    # Accept only the exact admitted collection and API version. A skip token
    # is data in the query, never an independently trusted next request URI.
    $parsed = $null
    if (-not [uri]::TryCreate($Continuation, [UriKind]::Absolute, [ref] $parsed) -or
        $parsed.Scheme -cne 'https' -or $parsed.Host -cne 'management.azure.com' -or
        $parsed.Port -ne 443 -or $parsed.UserInfo -ne '' -or $parsed.Fragment -ne '' -or
        $parsed.AbsolutePath -cne $Route.Path -or
        $Continuation -cnotmatch '\Ahttps://management\.azure\.com/') {
        throw 'VALIDATION.SERVICE_RESPONSE_INVALID'
    }
    # System.Uri normalizes malformed percent escapes and dot segments.
    # Validate original text so that normalization cannot repair an invalid
    # service response or widen the admitted collection path.
    $prefix = 'https://management.azure.com' + $Route.Path + '?'
    if (-not $Continuation.StartsWith($prefix, [StringComparison]::Ordinal)) {
        throw 'VALIDATION.SERVICE_RESPONSE_INVALID'
    }
    $query = @{}
    foreach ($pair in $Continuation.Substring($prefix.Length).Split('&')) {
        $parts = $pair.Split('=',2)
        if ($parts.Count -ne 2 -or $query.ContainsKey($parts[0]) -or
            $parts[0] -cnotin @('api-version','$skiptoken') -or $parts[1].Length -eq 0) {
            throw 'VALIDATION.SERVICE_RESPONSE_INVALID'
        }
        $query[$parts[0]] = $parts[1]
    }
    if ($query.Count -ne 2 -or $query['api-version'] -cne $Route.ApiVersion -or
        $query['$skiptoken'] -cnotmatch '\A[A-Za-z0-9_.~%+-]+\z' -or
        $query['$skiptoken'] -match '%(?![0-9a-fA-F]{2})') {
        throw 'VALIDATION.SERVICE_RESPONSE_INVALID'
    }
    $base + '&$skiptoken=' + $query['$skiptoken']
}

function Invoke-AzureValidationArmRoute {
    param(
        [Parameter(Mandatory)] $Channel,
        [Parameter(Mandatory)][string] $Name,
        [Parameter()][byte[]] $Body,
        [Parameter()][string] $Continuation
    )
    if (-not $Channel.Routes.ContainsKey($Name)) { throw 'VALIDATION.SERVICE_REQUEST_INVALID' }
    $route = $Channel.Routes[$Name]
    if (($route.Method -in @('GET','DELETE') -and $null -ne $Body) -or
        ($route.Method -in @('PUT','POST') -and ($null -eq $Body -or $Body.Length -eq 0)) -or
        ($null -ne $Body -and $Body.Length -gt 1048576)) {
        throw 'VALIDATION.SERVICE_REQUEST_INVALID'
    }
    # Validate malformed requests before any token/network request.
    if ($null -ne $Body) { $null = ConvertFrom-AzureArmPrivateJson -Bytes $Body }
    $uri = Resolve-AzureArmRouteUri -Route $route -Continuation $Continuation
    $accessToken = $null
    try {
        $accessToken = Get-AzureArmManagedIdentityToken -Channel $Channel
        $response = Invoke-AzureArmBoundedRequest -Channel $Channel -Request ([pscustomobject]@{
            Method = $route.Method; Uri = $uri
            Headers = @{ Authorization = 'Bearer ' + $accessToken; Accept = 'application/json' }
            Body = $Body; MaximumBytes = 4194304
        })
        $document = $null
        # Error bodies remain private and are never parsed into public reasons.
        if ($response.StatusCode -ge 200 -and $response.StatusCode -lt 300 -and $response.Body.Length -gt 0) {
            $document = ConvertFrom-AzureArmPrivateJson -Bytes $response.Body
        }
        [pscustomobject]@{
            StatusCode = $response.StatusCode
            Document = $document
            NonQualifying = ($Channel.Kind -ceq 'InjectedNonQualifying')
        }
    }
    finally { $accessToken = $null }
}

function Get-AzureValidationArmCollection {
    param(
        [Parameter(Mandatory)] $Channel,
        [Parameter(Mandatory)][string] $Name,
        [Parameter()][string] $MissingParentRouteName
    )
    if (-not $Channel.Routes.ContainsKey($Name) -or -not $Channel.Routes[$Name].Paginated) {
        throw 'VALIDATION.SERVICE_REQUEST_INVALID'
    }
    if (-not [string]::IsNullOrEmpty($MissingParentRouteName)) {
        $collectionRoute = $Channel.Routes[$Name]
        if (-not $Channel.Routes.ContainsKey($MissingParentRouteName) -or
            $Channel.Routes[$MissingParentRouteName].Method -cne 'GET' -or
            $Channel.Routes[$MissingParentRouteName].Paginated -or
            $Channel.Routes[$MissingParentRouteName].Path -cne $collectionRoute.ScopePrefix -or
            $Channel.Routes[$MissingParentRouteName].ApiVersion -cne '2021-04-01' -or
            $collectionRoute.ApiVersion -cne '2021-04-01' -or
            $collectionRoute.Path -cne ($collectionRoute.ScopePrefix + '/resources') -or
            $collectionRoute.ScopePrefix -cnotmatch '\A/subscriptions/[0-9a-fA-F-]{36}/resourceGroups/[A-Za-z0-9_.()-]+\z') {
            throw 'VALIDATION.SERVICE_REQUEST_INVALID'
        }
    }
    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $ids = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $items = [Collections.Generic.List[object]]::new()
    $continuation = ''
    for ($page = 0; $page -lt 50; $page++) {
        $response = Invoke-AzureValidationArmRoute -Channel $Channel -Name $Name -Continuation $continuation
        # Only an initial missing group collection with a second exact parent
        # GET404 can be empty. A404 after any page remains incomplete evidence.
        if ($response.StatusCode -eq 404 -and $page -eq 0 -and $items.Count -eq 0 -and
            -not [string]::IsNullOrEmpty($MissingParentRouteName)) {
            $parent = Invoke-AzureValidationArmRoute -Channel $Channel -Name $MissingParentRouteName
            if ($parent.StatusCode -ne 404) { throw 'VALIDATION.SERVICE_RESPONSE_INVALID' }
            $null = Assert-AzureArmChannelActive -Channel $Channel
            return [pscustomobject]@{
                Items = @()
                Complete = $true
                ScopeAbsent = $true
                NonQualifying = ($Channel.Kind -ceq 'InjectedNonQualifying')
            }
        }
        if ($response.StatusCode -ne 200 -or
            $response.Document -isnot [Collections.IDictionary] -or
            -not $response.Document.Contains('value') -or
            $response.Document.value -isnot [array]) { throw 'VALIDATION.SERVICE_RESPONSE_INVALID' }
        Assert-AzureArmProtocolFields -Document $response.Document -Names @('value','nextLink')
        foreach ($item in $response.Document.value) {
            if ($item -isnot [Collections.IDictionary] -or $item.id -isnot [string] -or
                $item.id -cnotmatch '\A/subscriptions/[0-9a-fA-F-]{36}/[A-Za-z0-9_./()-]+\z' -or
                $item.id -match '(^|/)\.\.?(/|$)|//|/\z' -or
                -not ([string] $item.id).StartsWith(
                    ([string] $Channel.Routes[$Name].ScopePrefix + '/'), [StringComparison]::OrdinalIgnoreCase) -or
                -not $ids.Add($item.id) -or $items.Count -ge 10000) {
                throw 'VALIDATION.SERVICE_RESPONSE_INVALID'
            }
            Assert-AzureArmProtocolFields -Document $item -Names @('id','type','tags','properties')
            if ($item.id -cnotmatch '\A/subscriptions/[0-9a-fA-F-]{36}/resourceGroups/[A-Za-z0-9_.()-]+/providers/Microsoft\.[A-Za-z0-9]+/[^/]+/[^/]+(/[^/]+/[^/]+)*\z') {
                throw 'VALIDATION.SERVICE_RESPONSE_INVALID'
            }
            $segments = $item.id.Split('/')
            $resourceType = $segments[6]
            for ($index = 7; $index -lt $segments.Length; $index += 2) {
                $resourceType += '/' + $segments[$index]
            }
            # Some closed subresource APIs omit optional type. Validate kind
            # from exact ID and admitted typed collection without adding a
            # fictional observed field. Wildcard lists require an explicit
            # service type; contradictory or null types always refuse.
            if (($item.Contains('type') -and ($item.type -isnot [string] -or
                    -not [StringComparer]::OrdinalIgnoreCase.Equals($resourceType,[string]$item.type))) -or
                (-not $item.Contains('type') -and $Channel.Routes[$Name].ResourceType -ceq '*') -or
                ($Channel.Routes[$Name].ResourceType -cne '*' -and
                    -not [StringComparer]::OrdinalIgnoreCase.Equals($resourceType,[string]$Channel.Routes[$Name].ResourceType))) {
                throw 'VALIDATION.SERVICE_RESPONSE_INVALID'
            }
            $items.Add($item)
        }
        if (-not $response.Document.Contains('nextLink') -or $null -eq $response.Document.nextLink) {
            $null = Assert-AzureArmChannelActive -Channel $Channel
            return [pscustomobject]@{
                Items = $items.ToArray()
                Complete = $true
                ScopeAbsent = $false
                NonQualifying = ($Channel.Kind -ceq 'InjectedNonQualifying')
            }
        }
        if ($response.Document.nextLink -isnot [string] -or
            [string]::IsNullOrEmpty($response.Document.nextLink)) { throw 'VALIDATION.SERVICE_RESPONSE_INVALID' }
        $continuation = Resolve-AzureArmRouteUri -Route $Channel.Routes[$Name] -Continuation $response.Document.nextLink
        if (-not $seen.Add($continuation)) { throw 'VALIDATION.SERVICE_RESPONSE_INVALID' }
    }
    # No partial collection may support a VM count or absence decision.
    throw 'VALIDATION.SERVICE_RESPONSE_INVALID'
}

# Jellyfin SSO Integration — Phase 2 Plan

> **Status:** Planning / Pre-implementation
> **Stack:** C# 13 / .NET 10, ASP.NET Core 10, EF Core, Kestrel HTTP server
> **Auth today:** Custom `MediaBrowser` token scheme, no OIDC support
> **Target:** Transparent SSO via Cloudflare Access (or any OIDC-compliant reverse proxy), with retained local auth and Device Flow for TV/mobile apps

---

## 1 — Audit: Current Auth Architecture

### 1.1 Language & Framework

| Component | Technology |
|---|---|
| Language | C# 13 / .NET 10 |
| Web framework | ASP.NET Core 10 (Kestrel) |
| ORM | EF Core 10 (SQLite) |
| DI | Microsoft.Extensions.DependencyInjection |
| Existing SSO/OIDC libs | **None** |
| Existing auth libs | Custom only (no Passport/OpenIdConnect middleware) |

### 1.2 Auth Call Chain (current)

```
HTTP Request
    ↓
[Startup.cs] UseAuthentication() / UseAuthorization()
    ↓
CustomAuthenticationHandler.HandleAuthenticateAsync()
  [Jellyfin.Api/Auth/CustomAuthenticationHandler.cs]
    ↓
IAuthService.Authenticate(HttpRequest)
  [Emby.Server.Implementations/HttpServer/Security/AuthService.cs]
    ↓
IAuthorizationContext.GetAuthorizationInfo(HttpRequest)
  [Jellyfin.Server.Implementations/Security/AuthorizationContext.cs]
    ↓
  Parses "Authorization: MediaBrowser Token=..." header (or legacy X-Emby-Authorization)
  Looks up token in Device table (EF) → resolves User
    ↓
Returns AuthorizationInfo { User, Token, IsAuthenticated, IsApiKey, DeviceId, ... }
    ↓
CustomAuthenticationHandler builds ClaimsPrincipal
  Claims: Name, Role (User|Administrator), UserId, DeviceId, Device, Client, Version, Token, IsApiKey
    ↓
DefaultAuthorizationHandler (DefaultAuthorizationPolicy)
  [Jellyfin.Api/Auth/DefaultAuthorizationPolicy/DefaultAuthorizationHandler.cs]
  Checks parental schedule, remote access permission, admin role
```

### 1.3 Login Endpoint (credential auth)

```
POST /Users/AuthenticateByName
  [Jellyfin.Api/Controllers/UserController.cs:AuthenticateUserByName()]
    ↓
ISessionManager.AuthenticateNewSession(AuthenticationRequest)
  [Emby.Server.Implementations/Session/SessionManager.cs:AuthenticateNewSessionInternal()]
    ↓
  IUserManager.AuthenticateUser(username, password, ip, ...)
    Delegates to IAuthenticationProvider chain (local password hash check)
    ↓
  GetAuthorizationToken() → creates/rotates Device record in DB → returns opaque AccessToken
  LogSessionActivity() → creates in-memory SessionInfo
    ↓
Returns AuthenticationResult { AccessToken, SessionInfo, User }
```

### 1.4 Token Storage Model

- Each session = a `Device` row in the EF database (`Jellyfin.Database.Implementations.Entities.Security.Device`)
- Fields: `UserId`, `AccessToken` (GUID hex opaque), `AppName`, `AppVersion`, `DeviceName`, `DeviceId`, `DateLastActivity`
- Tokens have **no built-in expiry** — they are revoked explicitly via `ISessionManager.Logout()` or `RevokeUserTokens()`

### 1.5 Existing Auth Extensibility Points

| Interface | Purpose | Relevant to SSO |
|---|---|---|
| `IAuthenticationProvider` | Username+password validation; pluggable | ✅ New SSO provider can implement this |
| `IAuthorizationContext` | Parses request → `AuthorizationInfo` | ✅ Injection point for proxy JWT reading |
| `ISessionManager.AuthenticateDirect()` | Creates a session without password check | ✅ Used by QuickConnect; reuse for SSO |
| `CustomAuthenticationHandler` | ASP.NET Core auth handler | ✅ Can add parallel SSO scheme |
| `ServerConfiguration.EnableLegacyAuthorization` | Feature flag pattern already exists | ✅ Reuse same pattern for SSO flag |

### 1.6 Proxy Header Awareness (current state)

In `Jellyfin.Server/Extensions/ApiServiceCollectionExtensions.cs:ConfigureForwardHeaders()`:
- `ForwardedHeaders` (`X-Forwarded-For`, `X-Forwarded-Proto`, `X-Forwarded-Host`) are **conditionally enabled** — only if `KnownProxies` is configured in Network settings.
- If `KnownProxies` is empty: `ForwardedHeaders.None` → proxy headers are **ignored by default**. Operators must explicitly add their proxy IP.

**Gap:** No explicit trust of `CF-Access-Jwt-Assertion` header. No Cloudflare Access IP range support.

### 1.7 Sessions & Cookies

- Jellyfin does **not** use browser cookies for API auth. Everything is token-based (stored client-side).
- The web client stores the `AccessToken` in `localStorage` and sends it via `Authorization: MediaBrowser Token=<token>` on every request.
- There is **no ASP.NET `AddSession()` or cookie middleware** in `Startup.cs`. This simplifies the SSO implementation: we keep the same token model and just add a new way to *obtain* that token.

### 1.8 QuickConnect (existing device-flow analog)

`QuickConnectManager` implements a short-lived code flow (code → authorize via browser → poll → get Jellyfin token). This is **structurally similar to RFC 8628 Device Authorization Grant** but uses Jellyfin's own credential system, not an external IdP. We will model our TV Device Flow endpoint on this.

### 1.9 Mobile/TV API endpoints (current)

| Endpoint | Auth|
|---|---|
| `POST /Users/AuthenticateByName` | username+password |
| `POST /Users/AuthenticateWithQuickConnect` | Quick-connect secret |
| `POST /QuickConnect/Initiate` | Start quick-connect code |
| `POST /QuickConnect/Authorize` | Browser approves code |
| `GET /QuickConnect/Status` | Device polls status |

Device (TV/mobile) flow currently reuses QuickConnect which is Jellyfin-internal. A true RFC 8628 Device Flow to an external IdP is not present.

---

## 2 — Technical Design: Two Options

### Option A — Proxy-led SSO (Recommended starting point)

**Concept:** Cloudflare Access (or any OIDC-capable Zero Trust proxy) sits in front of Jellyfin. When an authenticated user hits Jellyfin, the proxy injects a signed JWT (`CF-Access-Jwt-Assertion` header). Jellyfin reads, verifies, and maps this to a Jellyfin user, then mints an internal access token transparently.

```
Browser / Mobile
    │  (authenticated browser = Cloudflare session cookie already present)
    ↓
Cloudflare Access (or Nginx + OIDC auth_request)
    │  Injects: CF-Access-Jwt-Assertion: <JWT>
    ↓
Jellyfin Kestrel
    │  New: SsoAuthenticationHandler reads JWT header
    │  Verifies signature via JWKS endpoint (cached)
    │  Maps email/sub claim → Jellyfin User
    │  Calls AuthenticateDirect() → mints Jellyfin token
    │  Returns token in response body (web client stores it)
    ↓
All subsequent API calls use standard Jellyfin token
```

**Mobile/TV with Option A:**
- Mobile apps (behind Cloudflare Access → Mobile Apps policy): same JWT flow, app stores token normally.
- TV apps (limited input): Use RFC 8628 Device Flow pointing at Cloudflare/IdP's device endpoint, then once device is authorized, Jellyfin exchanges the resulting IdP token for a Jellyfin session.

**Pros:**
- Minimal changes to Jellyfin's internal auth model
- Auth logic centralized at proxy — easy to swap IdP
- No need to implement OIDC Authorization Code flow in Jellyfin itself

**Cons:**
- Requires proxy to always be in path (direct access bypasses SSO unless blocked)
- CF-specific header name is non-standard (though configurable via env)
- Mobile clients need Cloudflare Access mobile configuration (cloudflared app or service token)

**Security notes:**
- Must validate JWT `iss`, `aud`, `exp`, `nbf`, signature (JWKS)
- Must only accept header if request comes from a trusted proxy IP (existing `KnownProxies` mechanism)
- Never forward or log the full JWT

---

### Option B — App-led OIDC

**Concept:** Jellyfin itself integrates directly with an OIDC provider (Keycloak, Auth0, Azure AD, etc.) as a native OIDC client. Users are redirected to the IdP for login.

```
Browser
    ↓ GET /sso/authorize?redirect_uri=...
Jellyfin
    ↓ 302 → IdP Authorization Endpoint (PKCE, state, nonce)
IdP login page
    ↓ 302 → /sso/callback?code=...&state=...
Jellyfin callback handler
    ↓ POST token endpoint (exchange code+PKCE verifier)
    ↓ Validate id_token (JWT)
    ↓ Map claims → Jellyfin User
    ↓ AuthenticateDirect() → mint Jellyfin token
    ↓ Return token to web client via redirect or JSON
```

**Pros:**
- Works without a reverse proxy
- Supports any OIDC provider directly
- PKCE is suitable for mobile (public clients)

**Cons:**
- Higher implementation complexity in Jellyfin
- Requires HTTPS and valid `redirect_uri` configuration
- Callback URL deep links for mobile apps require special handling
- Jellyfin becomes a confidential OIDC client (needs client_secret storage)

**Recommendation:**
Start with **Option A** as it requires fewer changes to the Jellyfin core and leverages existing proven infrastructure (Cloudflare Access). Implement **Option B** capabilities in Phase 3 for environments without a proxy. The RFC 8628 Device Flow (TV apps) applies to both options and is implemented at the Jellyfin layer calling the IdP's device endpoint.

---

## 3 — Step-by-Step Implementation Plan

### Phase 2.1 — Foundation: Feature Flags & Config

#### 3.1.1 Add SSO config to `ServerConfiguration`

**File:** `MediaBrowser.Model/Configuration/ServerConfiguration.cs`

```csharp
// Add after EnableLegacyAuthorization:

/// <summary>
/// Gets or sets a value indicating whether SSO via upstream proxy JWT is enabled.
/// When enabled, a valid CF-Access-Jwt-Assertion (or configured header) will be
/// accepted as authentication, bypassing local credential check.
/// </summary>
public bool EnableSso { get; set; } = false;

/// <summary>
/// Gets or sets the SSO provider type ("CloudflareAccess" | "GenericOidc").
/// </summary>
public string SsoProviderType { get; set; } = "CloudflareAccess";

/// <summary>
/// Gets or sets the OIDC/JWKS issuer URL for JWT validation.
/// For Cloudflare Access: https://{team}.cloudflareaccess.com
/// </summary>
public string SsoIssuer { get; set; } = string.Empty;

/// <summary>
/// Gets or sets the expected JWT audience (CF Application AUD tag or OIDC client_id).
/// </summary>
public string SsoAudience { get; set; } = string.Empty;

/// <summary>
/// Gets or sets the HTTP header name containing the proxy-injected JWT.
/// Default: CF-Access-Jwt-Assertion (Cloudflare). Use "Authorization" for Bearer flows.
/// </summary>
public string SsoJwtHeaderName { get; set; } = "CF-Access-Jwt-Assertion";

/// <summary>
/// Gets or sets the JWT claim used to map identity to a Jellyfin username.
/// Default: "email". Alternative: "sub".
/// </summary>
public string SsoUsernameClaim { get; set; } = "email";

/// <summary>
/// Gets or sets a value indicating whether to auto-provision users from SSO claims
/// (create Jellyfin user account on first login if not found).
/// </summary>
public bool SsoAutoProvisionUsers { get; set; } = false;

/// <summary>
/// Gets or sets a value indicating whether the Device Authorization Grant (TV flow) is enabled.
/// Requires SsoOidcDeviceEndpoint to be set.
/// </summary>
public bool SsoDeviceFlowEnabled { get; set; } = false;

/// <summary>
/// Gets or sets the IdP Device Authorization endpoint URL.
/// e.g. https://idp.example.com/oauth2/device/authorize
/// </summary>
public string SsoOidcDeviceEndpoint { get; set; } = string.Empty;

/// <summary>
/// Gets or sets the OIDC Client ID used for Device Flow.
/// </summary>
public string SsoOidcClientId { get; set; } = string.Empty;
```

**Environment variable overrides** (loaded in `Program.cs` or a new `SsoOptionsExtensions`):

```
JELLYFIN_SSO_ENABLED=true
JELLYFIN_SSO_ISSUER=https://team.cloudflareaccess.com
JELLYFIN_SSO_AUDIENCE=abc123...
JELLYFIN_SSO_JWT_HEADER=CF-Access-Jwt-Assertion
JELLYFIN_SSO_USERNAME_CLAIM=email
JELLYFIN_SSO_AUTO_PROVISION=false
JELLYFIN_SSO_DEVICE_FLOW=false
JELLYFIN_SSO_DEVICE_ENDPOINT=
JELLYFIN_SSO_CLIENT_ID=
```

---

### Phase 2.2 — Proxy Header Trust

#### 3.2.1 Extend `KnownProxies` to include Cloudflare IP ranges

**File:** `Jellyfin.Server/Extensions/ApiServiceCollectionExtensions.cs`

No code change needed — operators simply add Cloudflare IP ranges to `KnownProxies` in network config, which already routes through `ConfigureForwardHeaders()`.

Document the Cloudflare IP ranges in the `.env.sample` and README.

---

### Phase 2.3 — JWKS-based JWT Validator Service

#### 3.3.1 Create `ISsoJwtValidator` interface

**File (new):** `MediaBrowser.Controller/Sso/ISsoJwtValidator.cs`

```csharp
namespace MediaBrowser.Controller.Sso;

/// <summary>Interface for validating SSO JWTs from upstream proxy.</summary>
public interface ISsoJwtValidator
{
    /// <summary>
    /// Validates the JWT and returns extracted claims if valid.
    /// </summary>
    /// <param name="jwt">The JSON Web Token string.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Dictionary of claims on success, null if invalid/disabled.</returns>
    Task<IReadOnlyDictionary<string, string>?> ValidateAsync(
        string jwt,
        CancellationToken cancellationToken = default);
}
```

#### 3.3.2 Implement `JwksJwtValidator`

**File (new):** `Jellyfin.Server.Implementations/Sso/JwksJwtValidator.cs`

Key responsibilities:
- Fetch JWKS from `{issuer}/cdn-cgi/access/certs` (Cloudflare) or `{issuer}/.well-known/jwks.json` (generic OIDC)
- Cache JWKS with a configurable TTL (default: 1 hour); refresh on validation failure (key rotation)
- Use `System.IdentityModel.Tokens.Jwt` (`Microsoft.IdentityModel.JsonWebTokens`) for validation
- Validate: `iss`, `aud`, `exp`, `nbf`, signature
- Return claim dictionary (`email`, `sub`, `name`, `groups`)

**NuGet package to add:**
```xml
<!-- Jellyfin.Server.Implementations.csproj -->
<PackageReference Include="Microsoft.IdentityModel.JsonWebTokens" Version="8.*" />
```

```csharp
// Skeleton — implement fully
using System.Net.Http;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using MediaBrowser.Controller.Configuration;
using MediaBrowser.Controller.Sso;

namespace Jellyfin.Server.Implementations.Sso;

public class JwksJwtValidator : ISsoJwtValidator
{
    private readonly IServerConfigurationManager _config;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ILogger<JwksJwtValidator> _logger;
    private ConfigurationManager<OpenIdConnectConfiguration>? _oidcConfig;
    private string _lastIssuer = string.Empty;

    public JwksJwtValidator(
        IServerConfigurationManager config,
        IHttpClientFactory httpClientFactory,
        ILogger<JwksJwtValidator> logger)
    {
        // ...
    }

    public async Task<IReadOnlyDictionary<string, string>?> ValidateAsync(
        string jwt,
        CancellationToken cancellationToken = default)
    {
        var serverConfig = _config.Configuration;
        if (!serverConfig.EnableSso || string.IsNullOrEmpty(serverConfig.SsoIssuer))
            return null;

        // Refresh OIDC config if issuer changed
        EnsureOidcConfig(serverConfig.SsoIssuer);

        var oidcConfig = await _oidcConfig!
            .GetConfigurationAsync(cancellationToken)
            .ConfigureAwait(false);

        var validationParams = new TokenValidationParameters
        {
            ValidIssuer = serverConfig.SsoIssuer,
            ValidAudience = serverConfig.SsoAudience,
            IssuerSigningKeys = oidcConfig.SigningKeys,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ClockSkew = TimeSpan.FromSeconds(30)
        };

        var handler = new JsonWebTokenHandler();
        var result = await handler.ValidateTokenAsync(jwt, validationParams)
            .ConfigureAwait(false);

        if (!result.IsValid)
        {
            _logger.LogWarning("SSO JWT validation failed: {Reason}", result.Exception?.Message);
            return null;
        }

        return result.Claims
            .Where(c => c.Value is string)
            .ToDictionary(c => c.Key, c => c.Value.ToString()!);
    }

    private void EnsureOidcConfig(string issuer)
    {
        if (string.Equals(_lastIssuer, issuer, StringComparison.Ordinal) && _oidcConfig is not null)
            return;

        // Cloudflare Access specific vs. generic OIDC discovery
        var metadataAddress = issuer.TrimEnd('/') + "/.well-known/openid-configuration";
        _oidcConfig = new ConfigurationManager<OpenIdConnectConfiguration>(
            metadataAddress,
            new OpenIdConnectConfigurationRetriever(),
            new HttpDocumentRetriever(_httpClientFactory.CreateClient(NamedClient.Default)));
        _lastIssuer = issuer;
    }
}
```

Additional NuGet:
```xml
<PackageReference Include="Microsoft.IdentityModel.Protocols.OpenIdConnect" Version="8.*" />
```

---

### Phase 2.4 — SSO Authentication Handler

#### 3.4.1 Create `SsoAuthenticationHandler`

**File (new):** `Jellyfin.Api/Auth/SsoProxyAuthenticationHandler.cs`

This runs in parallel with `CustomAuthenticationHandler` (both are registered as authentication schemes). It fires first via middleware ordering.

```csharp
using System.Globalization;
using System.Security.Claims;
using System.Text.Encodings.Web;
using Jellyfin.Api.Constants;
using MediaBrowser.Controller.Configuration;
using MediaBrowser.Controller.Library;
using MediaBrowser.Controller.Session;
using MediaBrowser.Controller.Sso;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Jellyfin.Api.Auth;

/// <summary>
/// Authentication handler that validates upstream proxy JWTs (SSO).
/// On success, creates/fetches a Jellyfin session and injects a standard
/// Jellyfin token claim so downstream code works without changes.
/// </summary>
public class SsoProxyAuthenticationHandler : AuthenticationHandler<AuthenticationSchemeOptions>
{
    private readonly ISsoJwtValidator _jwtValidator;
    private readonly IServerConfigurationManager _config;
    private readonly IUserManager _userManager;
    private readonly ISessionManager _sessionManager;
    private readonly ILogger<SsoProxyAuthenticationHandler> _logger;

    public SsoProxyAuthenticationHandler(
        ISsoJwtValidator jwtValidator,
        IServerConfigurationManager config,
        IUserManager userManager,
        ISessionManager sessionManager,
        IOptionsMonitor<AuthenticationSchemeOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder)
        : base(options, logger, encoder)
    {
        // ... assign fields
    }

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var serverConfig = _config.Configuration;
        if (!serverConfig.EnableSso)
            return AuthenticateResult.NoResult();

        var headerName = serverConfig.SsoJwtHeaderName;
        if (!Request.Headers.TryGetValue(headerName, out var jwtValues) || jwtValues.Count == 0)
            return AuthenticateResult.NoResult();

        var jwt = jwtValues[0];
        var claims = await _jwtValidator.ValidateAsync(jwt).ConfigureAwait(false);

        if (claims is null)
            return AuthenticateResult.NoResult();

        // Map IdP identity → Jellyfin user
        var usernameClaim = serverConfig.SsoUsernameClaim;
        if (!claims.TryGetValue(usernameClaim, out var username) || string.IsNullOrEmpty(username))
        {
            _logger.LogWarning(
                "SSO JWT valid but missing configured claim '{Claim}'. Check SsoUsernameClaim config.",
                usernameClaim);
            return AuthenticateResult.Fail("Missing identity claim in JWT.");
        }

        var user = _userManager.GetUserByName(username);

        if (user is null)
        {
            if (!serverConfig.SsoAutoProvisionUsers)
            {
                _logger.LogWarning("SSO login for unknown user '{Username}' (auto-provision disabled)", username);
                return AuthenticateResult.Fail($"User '{username}' not found. Auto-provisioning is disabled.");
            }

            // Auto-provision: create user without password (SSO-only account)
            user = await _userManager.CreateUserAsync(username).ConfigureAwait(false);
            _logger.LogInformation("Auto-provisioned SSO user '{Username}'", username);
        }

        // Create/refresh Jellyfin session (no password required — IdP has already authenticated)
        var deviceId = Request.Headers["X-Jellyfin-DeviceId"].FirstOrDefault()
            ?? $"sso-{username}";
        var deviceName = Request.Headers["X-Jellyfin-Device"].FirstOrDefault()
            ?? "SSO Session";
        var appName = Request.Headers["X-Jellyfin-Client"].FirstOrDefault()
            ?? "Jellyfin SSO";
        var appVersion = Request.Headers["X-Jellyfin-Version"].FirstOrDefault()
            ?? "1.0.0";

        var authResult = await _sessionManager.AuthenticateDirect(new AuthenticationRequest
        {
            UserId = user.Id,
            DeviceId = deviceId,
            DeviceName = deviceName,
            App = appName,
            AppVersion = appVersion,
            RemoteEndPoint = HttpContext.GetNormalizedRemoteIP().ToString()
        }).ConfigureAwait(false);

        // Build ClaimsPrincipal identical to what CustomAuthenticationHandler produces,
        // so all downstream authorization handlers work without modification
        var role = user.HasPermission(Jellyfin.Database.Implementations.Enums.PermissionKind.IsAdministrator)
            ? UserRoles.Administrator
            : UserRoles.User;

        var claimsList = new[]
        {
            new Claim(ClaimTypes.Name, user.Username),
            new Claim(ClaimTypes.Role, role),
            new Claim(InternalClaimTypes.UserId, user.Id.ToString("N", CultureInfo.InvariantCulture)),
            new Claim(InternalClaimTypes.DeviceId, deviceId),
            new Claim(InternalClaimTypes.Device, deviceName),
            new Claim(InternalClaimTypes.Client, appName),
            new Claim(InternalClaimTypes.Version, appVersion),
            new Claim(InternalClaimTypes.Token, authResult.AccessToken),
            new Claim(InternalClaimTypes.IsApiKey, "false")
        };

        var identity = new ClaimsIdentity(claimsList, AuthenticationSchemes.SsoAuthentication);
        var principal = new ClaimsPrincipal(identity);
        var ticket = new AuthenticationTicket(principal, AuthenticationSchemes.SsoAuthentication);

        // Surface the minted Jellyfin token in a response header so web
        // clients can read it (once) and store in localStorage
        Response.Headers["X-Jellyfin-Token"] = authResult.AccessToken;

        _logger.LogInformation(
            "SSO login successful for user '{Username}' via {Scheme}",
            username,
            Scheme.Name);

        return AuthenticateResult.Success(ticket);
    }
}
```

#### 3.4.2 Add `SsoAuthentication` scheme name

**File:** `Jellyfin.Api/Constants/AuthenticationSchemes.cs`

```csharp
// Add:
public const string SsoAuthentication = "Sso";
```

---

### Phase 2.5 — Register SSO Handler in DI

**File:** `Jellyfin.Server/Extensions/ApiServiceCollectionExtensions.cs`

```csharp
// In AddCustomAuthentication(), extend the builder:
public static AuthenticationBuilder AddCustomAuthentication(
    this IServiceCollection serviceCollection)
{
    return serviceCollection
        .AddAuthentication(AuthenticationSchemes.CustomAuthentication)
        .AddScheme<AuthenticationSchemeOptions, CustomAuthenticationHandler>(
            AuthenticationSchemes.CustomAuthentication, null)
        .AddScheme<AuthenticationSchemeOptions, SsoProxyAuthenticationHandler>(
            AuthenticationSchemes.SsoAuthentication, null);
}
```

Update `AddJellyfinApiAuthorization` to include both schemes in the default policy:

```csharp
options.DefaultPolicy = new AuthorizationPolicyBuilder()
    .AddAuthenticationSchemes(
        AuthenticationSchemes.CustomAuthentication,
        AuthenticationSchemes.SsoAuthentication)  // ← add this
    .AddRequirements(new DefaultAuthorizationRequirement())
    .Build();
```

Register `ISsoJwtValidator` and `JwksJwtValidator` in DI:

**File:** `Jellyfin.Server.Implementations/Extensions/ServiceCollectionExtensions.cs` (or similar)

```csharp
services.AddSingleton<ISsoJwtValidator, JwksJwtValidator>();
```

---

### Phase 2.6 — Transparent SSO Endpoint for Web Client

The web client currently always redirects to a manual login page. To enable transparent SSO, add a lightweight endpoint that:

1. Reads and validates the proxy JWT
2. Returns the Jellyfin `AccessToken` as JSON (for localStorage storage)

**File (new):** `Jellyfin.Api/Controllers/SsoController.cs`

```csharp
[Route("Sso")]
[ApiController]
public class SsoController : BaseJellyfinApiController
{
    // GET /Sso/Token
    // Returns the Jellyfin token derived from the proxy JWT, if SSO is enabled.
    // The web client calls this on page load to detect silent SSO.
    [HttpGet("Token")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<ActionResult<AuthenticationResult>> GetSsoToken(
        [FromServices] ISsoJwtValidator jwtValidator,
        [FromServices] IServerConfigurationManager config,
        [FromServices] IUserManager userManager,
        [FromServices] ISessionManager sessionManager)
    {
        // ... same logic as SsoProxyAuthenticationHandler.HandleAuthenticateAsync()
        // but returns full AuthenticationResult JSON for the web client boot flow
    }
}
```

---

### Phase 2.7 — Device Authorization Grant (TV Apps)

For TV apps (Roku, Apple TV, Android TV, etc.) with limited input:

**File (new):** `Jellyfin.Api/Controllers/DeviceAuthController.cs`

```csharp
[Route("DeviceAuth")]
[ApiController]
public class DeviceAuthController : BaseJellyfinApiController
{
    /// POST /DeviceAuth/Authorize
    /// Proxies to IdP device_authorization endpoint and returns
    /// { device_code, user_code, verification_uri, verification_uri_complete, expires_in, interval }
    [HttpPost("Authorize")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public async Task<ActionResult<DeviceAuthorizationResponse>> StartDeviceAuth(
        [FromServices] IServerConfigurationManager config,
        [FromServices] IHttpClientFactory httpClientFactory)
    {
        var cfg = config.Configuration;
        if (!cfg.SsoDeviceFlowEnabled || string.IsNullOrEmpty(cfg.SsoOidcDeviceEndpoint))
            return StatusCode(StatusCodes.Status503ServiceUnavailable, "Device flow not configured.");

        var client = httpClientFactory.CreateClient(NamedClient.Default);
        var response = await client.PostAsync(
            cfg.SsoOidcDeviceEndpoint,
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                { "client_id", cfg.SsoOidcClientId },
                { "scope", "openid email profile" }
            })).ConfigureAwait(false);

        var body = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
        return Content(body, "application/json");
    }

    /// POST /DeviceAuth/Token
    /// Device polls this. Jellyfin proxies to IdP token endpoint.
    /// On success, exchanges IdP token for a Jellyfin session token.
    [HttpPost("Token")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<ActionResult<AuthenticationResult>> PollDeviceToken(
        [FromForm] string device_code,
        [FromServices] IServerConfigurationManager config,
        [FromServices] IHttpClientFactory httpClientFactory,
        [FromServices] ISsoJwtValidator jwtValidator,
        [FromServices] IUserManager userManager,
        [FromServices] ISessionManager sessionManager)
    {
        // 1. POST to IdP token endpoint with grant_type=urn:ietf:params:oauth:grant-type:device_code
        // 2. On authorization_pending → return 400 with error=authorization_pending
        // 3. On success: extract id_token, validate via jwtValidator, map to Jellyfin user, AuthenticateDirect()
        // 4. Return Jellyfin AuthenticationResult
    }
}
```

---

### Phase 2.8 — Settings Toggle in Admin Dashboard

**File:** `Jellyfin.Server/Controllers/DashboardController.cs` (or existing Config controller)

The SSO settings toggle is already persistent via `ServerConfiguration.EnableSso`. The existing `/System/Configuration` PATCH endpoint will automatically handle enabling/disabling SSO since `ServerConfiguration` is serialized/deserialized via the existing config manager.

The front-end (jellyfin-web) will need a settings page — separate from this repo.

---

### Phase 2.9 — Observability

Add structured logging at each key transition in `SsoProxyAuthenticationHandler` and `JwksJwtValidator`:

| Event | Level | Fields |
|---|---|---|
| JWT validation failure | Warning | reason, header truncated (never full token) |
| JWT validation success | Debug | username_claim_value, cached_keys |
| JWKS refresh | Info | issuer, key_count |
| SSO login success | Information | username, client_app, device_id |
| SSO login failure (user not found) | Warning | username_claim |
| Auto-provision user created | Information | username |
| Device flow start | Information | device_endpoint, client_id |
| Device flow authorized | Information | username |
| Device flow expired | Warning | device_code_prefix |

**Metrics (Prometheus, already in Startup.cs via `UseHttpMetrics()`):**
- Track `/Sso/Token` hit rate (incoming proxy auth attempts)
- Track `/DeviceAuth/*` hit rate and poll interval compliance
- Add counter for SSO validation failures (`sso_jwt_validation_failures_total`)

---

## 4 — Migration Path

| Step | Risk | Rollback |
|---|---|---|
| Add `EnableSso = false` to `ServerConfiguration` | ✅ None — config additive | Remove property |
| Register SSO handler (disabled by default) | ✅ None — scheme only fires when header present | Deregister scheme |
| Add `/Sso/Token` endpoint | ✅ None — new route | Delete route |
| Operator enables `EnableSso = true` + configures issuer/audience | ⚠️ Medium — misconfiguration could lock out | Toggle `EnableSso = false` via config file |
| Enable `SsoAutoProvisionUsers = true` | ⚠️ Medium — could create ghost accounts | Disable flag, clean up DB |

---

## 5 — Acceptance Criteria & Test Plan

### 5.1 Unit Tests

New test project or extension of `tests/Jellyfin.Server.Implementations.Tests/`:

| Test | Assertion |
|---|---|
| Valid JWT → `ValidateAsync()` returns claims | Pass |
| Expired JWT → returns null | Pass |
| Wrong audience → returns null | Pass |
| Invalid signature → returns null | Pass |
| Bad issuer → returns null | Pass |
| JWKS refresh on 401 from IdP | Pass |

### 5.2 Integration Tests

| Scenario | Expected behavior |
|---|---|
| Request with valid proxy JWT + `EnableSso=true` | 200 + `X-Jellyfin-Token` header returned; user logged in |
| Request with valid proxy JWT + `EnableSso=false` | Falls through to standard auth (no SSO) |
| Request with invalid proxy JWT | `AuthenticateResult.NoResult()` → falls through to CustomAuth |
| Request from unknown username + `SsoAutoProvisionUsers=false` | 401 |
| Request from unknown username + `SsoAutoProvisionUsers=true` | 200 + new user created in DB |
| `GET /Sso/Token` without proxy JWT | 401 |
| Device flow start → poll before authorization | 400 authorization_pending |
| Device flow start → authorize on IdP → poll → success | 200 AuthenticationResult |
| Device flow poll after expiry | 400 expired_token |

### 5.3 Security Tests

| Test | Expected |
|---|---|
| JWT sent from untrusted IP (not in `KnownProxies`) | Forwarded headers stripped by ASP.NET; JWT header still readable but `iss` mismatch → 401 (defense in depth: also filter at proxy) |
| JWT replayed after expiry | `exp` check fails → 401 |
| JWT with wrong `aud` | validation failed → 401 |
| CSRF attempt (cookie-less model) | Not applicable — Jellyfin is token-based |
| Full JWT logged | Verify logs show only truncated/hashed values |
| Secrets in config file | Verify no OIDC client_secret appears in logs |

### 5.4 End-to-End Manual Test Plan

1. **Browser SSO (Cloudflare Access):**
   - Place Jellyfin behind Cloudflare Access tunnel
   - Navigate to `https://jellyfin.example.com`
   - Authenticate at Cloudflare → land on Jellyfin without any further login prompt
   - Verify session created in Jellyfin Admin Dashboard → Sessions

2. **Direct login fallback:**
   - Access Jellyfin directly (bypassing proxy) with `EnableSso=true`
   - Standard login form should work normally

3. **Mobile app:**
   - Configure Cloudflare Access mobile app (or service token for API clients)
   - Login from Infuse / Jellyfin iOS app
   - Verify token is returned and app functions normally

4. **TV app Device Flow:**
   - Call `POST /DeviceAuth/Authorize` from TV app
   - Display `user_code` and `verification_uri` to user
   - User opens browser, authenticates on IdP
   - TV polls `POST /DeviceAuth/Token` at `interval` seconds
   - TV receives Jellyfin `AuthenticationResult` → stores token

5. **Logout:**
   - Log out from one device → verify only that session's token is revoked
   - Use "Sign out all sessions" in user profile → verify all tokens revoked

---

## 6 — `.env.sample`

```env
# Jellyfin SSO Configuration
# Enable proxy-led SSO authentication
JELLYFIN_SSO_ENABLED=false

# SSO provider: CloudflareAccess | GenericOidc
JELLYFIN_SSO_PROVIDER=CloudflareAccess

# OIDC issuer / Cloudflare Access team domain
# Example: https://myteam.cloudflareaccess.com
JELLYFIN_SSO_ISSUER=

# JWT audience (Cloudflare AUD tag or OIDC client_id)
JELLYFIN_SSO_AUDIENCE=

# Header containing the proxy-injected JWT
# Cloudflare default: CF-Access-Jwt-Assertion
JELLYFIN_SSO_JWT_HEADER=CF-Access-Jwt-Assertion

# JWT claim to use as Jellyfin username (email | sub | preferred_username)
JELLYFIN_SSO_USERNAME_CLAIM=email

# Auto-create Jellyfin user on first SSO login (false = must pre-create users)
JELLYFIN_SSO_AUTO_PROVISION=false

# Device Authorization Grant (RFC 8628) for TV/limited-input clients
JELLYFIN_SSO_DEVICE_FLOW=false
JELLYFIN_SSO_DEVICE_ENDPOINT=
JELLYFIN_SSO_CLIENT_ID=

# Known proxy IPs (comma-separated CIDR) — required to trust forwarded headers
# Cloudflare IPv4: https://www.cloudflare.com/ips-v4
# Cloudflare IPv6: https://www.cloudflare.com/ips-v6
# Example: 173.245.48.0/20,103.21.244.0/22,...
JELLYFIN_KNOWN_PROXIES=
```

---

## 7 — Architecture Note (README section)

```markdown
## SSO Authentication (Phase 2)

Jellyfin supports transparent Single Sign-On via a trusted reverse proxy
(e.g. Cloudflare Access) or via the RFC 8628 Device Authorization Grant for
TV/limited-input clients.

### Proxy-led SSO (Cloudflare Access / Zero Trust)

1. Place Jellyfin behind a Cloudflare Access application (or equivalent OIDC proxy).
2. Configure `JELLYFIN_SSO_ENABLED=true`, `JELLYFIN_SSO_ISSUER`, and `JELLYFIN_SSO_AUDIENCE`.
3. Add your proxy IP ranges to `JELLYFIN_KNOWN_PROXIES` in the network configuration.
4. Users who pass the proxy auth gate will be silently logged into Jellyfin using the
   injected JWT — no separate Jellyfin login required.

### Fallback Local Auth

When SSO is enabled, local username/password auth remains active as a fallback.
To restrict access to SSO only, configure your proxy to block all direct connections
to Jellyfin's port.

### Device Flow (TV Apps)

Set `JELLYFIN_SSO_DEVICE_FLOW=true` and configure your IdP's device endpoint.
TV clients call `POST /DeviceAuth/Authorize`, display the user code, then poll
`POST /DeviceAuth/Token` until the user authenticates in their browser.
```

---

## 8 — Phased Delivery Checklist

### Phase 2.1 (This PR)
- [ ] `ServerConfiguration` SSO fields added
- [ ] `.env.sample` created
- [ ] Unit tests for `JwksJwtValidator`

### Phase 2.2 (Next PR)
- [ ] `JwksJwtValidator` implementation
- [ ] `SsoProxyAuthenticationHandler` implementation
- [ ] DI registrations
- [ ] `GET /Sso/Token` endpoint
- [ ] Integration tests for SSO handler

### Phase 2.3 (Subsequent PR)
- [ ] `POST /DeviceAuth/Authorize` endpoint
- [ ] `POST /DeviceAuth/Token` endpoint
- [ ] Device flow integration tests

### Phase 2.4 (Frontend — jellyfin-web repo)
- [ ] Silent SSO detection on load (`GET /Sso/Token`)
- [ ] Admin settings page for SSO config
- [ ] TV app device flow UI (code display + polling)

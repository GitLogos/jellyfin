using System;
using System.Globalization;
using System.Linq;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using Jellyfin.Api.Constants;
using Jellyfin.Api.Extensions;
using Jellyfin.Database.Implementations.Enums;
using MediaBrowser.Controller.Authentication;
using MediaBrowser.Controller.Configuration;
using MediaBrowser.Controller.Library;
using MediaBrowser.Controller.Sso;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Jellyfin.Api.Auth;

/// <summary>
/// ASP.NET Core authentication handler for SSO via upstream proxy-injected JWTs.
/// Runs alongside <see cref="CustomAuthenticationHandler"/> as a separate authentication scheme.
/// When SSO is disabled or the configured header is absent, returns <c>NoResult</c>
/// so the standard <see cref="CustomAuthenticationHandler"/> handles the request normally.
/// </summary>
public class SsoProxyAuthenticationHandler : AuthenticationHandler<AuthenticationSchemeOptions>
{
    private readonly ISsoJwtValidator _jwtValidator;
    private readonly IServerConfigurationManager _config;
    private readonly IUserManager _userManager;
    private readonly ISessionManager _sessionManager;

    /// <summary>
    /// Initializes a new instance of the <see cref="SsoProxyAuthenticationHandler"/> class.
    /// </summary>
    /// <param name="jwtValidator">The SSO JWT validator.</param>
    /// <param name="config">The server configuration manager.</param>
    /// <param name="userManager">The user manager.</param>
    /// <param name="options">Authentication scheme options monitor.</param>
    /// <param name="logger">The logger factory.</param>
    /// <param name="encoder">The URL encoder.</param>
    public SsoProxyAuthenticationHandler(
        ISsoJwtValidator jwtValidator,
        IServerConfigurationManager config,
        IUserManager userManager,
        IOptionsMonitor<AuthenticationSchemeOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder)
        : base(options, logger, encoder)
    {
        _jwtValidator = jwtValidator;
        _config = config;
        _userManager = userManager;
    }

    /// <inheritdoc />
    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var serverConfig = _config.Configuration;

        // SSO short-circuit: do nothing when feature is disabled
        if (!serverConfig.EnableSso)
        {
            return AuthenticateResult.NoResult();
        }

        // Check for the configured JWT header
        var headerName = serverConfig.SsoJwtHeaderName;
        if (!Request.Headers.TryGetValue(headerName, out var jwtValues)
            || jwtValues.Count == 0
            || string.IsNullOrEmpty(jwtValues[0]))
        {
            return AuthenticateResult.NoResult();
        }

        var rawJwt = jwtValues[0]!;

        // Strip "Bearer " prefix when using the Authorization header
        if (rawJwt.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            rawJwt = rawJwt["Bearer ".Length..];
        }

        // Validate the JWT — returns null on failure (reason already logged inside validator)
        var claims = await _jwtValidator.ValidateAsync(rawJwt).ConfigureAwait(false);
        if (claims is null)
        {
            // Fall through to the standard Jellyfin token handler
            return AuthenticateResult.NoResult();
        }

        // Extract the identity claim configured by the operator
        if (!claims.TryGetValue(serverConfig.SsoUsernameClaim, out var username)
            || string.IsNullOrEmpty(username))
        {
            Logger.LogWarning(
                "SSO JWT valid but claim '{Claim}' is missing or empty. Check SsoUsernameClaim setting.",
                serverConfig.SsoUsernameClaim);
            return AuthenticateResult.Fail("Missing identity claim in SSO JWT.");
        }

        // Resolve or auto-provision the Jellyfin user
        var user = _userManager.GetUserByName(username);

        if (user is null)
        {
            if (!serverConfig.SsoAutoProvisionUsers)
            {
                Logger.LogWarning(
                    "SSO login attempted for unknown user '{Username}' (SsoAutoProvisionUsers=false).",
                    username);
                return AuthenticateResult.Fail($"User '{username}' not found. Enable SsoAutoProvisionUsers or create the account manually.");
            }

            // Create a password-less account — authentication is always via SSO for these users
            user = await _userManager.CreateUserAsync(username).ConfigureAwait(false);
            Logger.LogInformation("Auto-provisioned Jellyfin user '{Username}' via SSO.", username);
        }

        // Read Jellyfin client metadata from headers (standard Jellyfin client convention)
        var deviceId = Request.Headers["X-Jellyfin-DeviceId"].FirstOrDefault() ?? $"sso-{username}";
        var deviceName = Request.Headers["X-Jellyfin-Device"].FirstOrDefault() ?? "SSO Proxy Client";
        var appName = Request.Headers["X-Jellyfin-Client"].FirstOrDefault() ?? "Jellyfin SSO";
        var appVersion = Request.Headers["X-Jellyfin-Version"].FirstOrDefault() ?? "1.0.0";

        // Build exactly the same ClaimsPrincipal shape that CustomAuthenticationHandler builds
        // so every downstream authorization handler works without modification.
        var role = user.HasPermission(PermissionKind.IsAdministrator)
            ? UserRoles.Administrator
            : UserRoles.User;

        var jellyfinClaims = new[]
        {
            new Claim(ClaimTypes.Name, user.Username),
            new Claim(ClaimTypes.Role, role),
            new Claim(InternalClaimTypes.UserId, user.Id.ToString("N", CultureInfo.InvariantCulture)),
            new Claim(InternalClaimTypes.DeviceId, deviceId),
            new Claim(InternalClaimTypes.Device, deviceName),
            new Claim(InternalClaimTypes.Client, appName),
            new Claim(InternalClaimTypes.Version, appVersion),
            new Claim(InternalClaimTypes.Token, "sso-synthetic-token"),
            new Claim(InternalClaimTypes.IsApiKey, false.ToString(CultureInfo.InvariantCulture))
        };

        var identity = new ClaimsIdentity(jellyfinClaims, Scheme.Name);
        var principal = new ClaimsPrincipal(identity);
        var ticket = new AuthenticationTicket(principal, Scheme.Name);

        Logger.LogDebug(
            "SSO authentication successful for user '{Username}' (app: {App}, device: {Device}).",
            username,
            appName,
            deviceId);

        return AuthenticateResult.Success(ticket);
    }
}

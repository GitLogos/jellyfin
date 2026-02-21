using System;
using System.Net.Http;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using MediaBrowser.Common.Net;
using MediaBrowser.Controller.Configuration;
using MediaBrowser.Controller.Sso;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace Jellyfin.Server.Implementations.Sso;

/// <summary>
/// Validates JWTs issued by an upstream SSO proxy using OIDC/JWKS discovery.
/// The OIDC configuration (signing keys) is cached and refreshed automatically
/// via <see cref="ConfigurationManager{T}"/> when keys rotate.
/// </summary>
public class JwksJwtValidator : ISsoJwtValidator
{
    private readonly IServerConfigurationManager _config;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ILogger<JwksJwtValidator> _logger;

    // Cached OIDC configuration manager — recreated only when the issuer URL changes.
    private ConfigurationManager<OpenIdConnectConfiguration>? _oidcConfigManager;
    private string _lastIssuer = string.Empty;
    private readonly SemaphoreSlim _configLock = new(1, 1);

    /// <summary>
    /// Initializes a new instance of the <see cref="JwksJwtValidator"/> class.
    /// </summary>
    /// <param name="config">The server configuration manager.</param>
    /// <param name="httpClientFactory">The HTTP client factory.</param>
    /// <param name="logger">The logger.</param>
    public JwksJwtValidator(
        IServerConfigurationManager config,
        IHttpClientFactory httpClientFactory,
        ILogger<JwksJwtValidator> logger)
    {
        _config = config;
        _httpClientFactory = httpClientFactory;
        _logger = logger;
    }

    /// <inheritdoc />
    public async Task<IReadOnlyDictionary<string, string>?> ValidateAsync(
        string jwt,
        CancellationToken cancellationToken = default)
    {
        var serverConfig = _config.Configuration;

        if (!serverConfig.EnableSso)
        {
            return null;
        }

        if (string.IsNullOrEmpty(serverConfig.SsoIssuer))
        {
            _logger.LogWarning("SSO is enabled but SsoIssuer is not configured — skipping JWT validation.");
            return null;
        }

        if (string.IsNullOrEmpty(serverConfig.SsoAudience))
        {
            _logger.LogWarning("SSO is enabled but SsoAudience is not configured — skipping JWT validation.");
            return null;
        }

        var configManager = await GetOrCreateOidcConfigManagerAsync(serverConfig.SsoIssuer).ConfigureAwait(false);

        OpenIdConnectConfiguration oidcConfig;
        try
        {
            oidcConfig = await configManager.GetConfigurationAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to retrieve OIDC configuration from issuer {Issuer}", serverConfig.SsoIssuer);
            return null;
        }

        var validationParams = new TokenValidationParameters
        {
            ValidIssuer = serverConfig.SsoIssuer,
            ValidAudience = serverConfig.SsoAudience,
            IssuerSigningKeys = oidcConfig.SigningKeys,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidateIssuer = true,
            ValidateAudience = true,
            // Allow a small clock skew for distributed systems
            ClockSkew = TimeSpan.FromSeconds(30)
        };

        var handler = new JsonWebTokenHandler();

        TokenValidationResult result;
        try
        {
            result = await handler.ValidateTokenAsync(jwt, validationParams).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "SSO JWT validation threw an exception");
            return null;
        }

        if (!result.IsValid)
        {
            // Log the reason without echoing the full token
            _logger.LogWarning(
                "SSO JWT validation failed: {Reason}",
                result.Exception?.GetType().Name ?? "Unknown");
            return null;
        }

        _logger.LogDebug(
            "SSO JWT validated successfully. Signing key count: {KeyCount}",
            oidcConfig.SigningKeys?.Count() ?? 0);

        // Convert claims to a flat string dictionary; multi-value claims use the last value.
        var claims = result.Claims
            .Where(c => c.Value is not null)
            .GroupBy(c => c.Key)
            .ToDictionary(g => g.Key, g => g.Last().Value?.ToString() ?? string.Empty);

        return claims;
    }

    /// <summary>
    /// Returns (creating if needed) the OIDC configuration manager for the given issuer.
    /// Thread-safe and recreated only when the issuer URL changes.
    /// </summary>
    private async Task<ConfigurationManager<OpenIdConnectConfiguration>> GetOrCreateOidcConfigManagerAsync(string issuer)
    {
        // Fast path — no lock needed if the issuer hasn't changed
        if (_oidcConfigManager is not null
            && string.Equals(_lastIssuer, issuer, StringComparison.Ordinal))
        {
            return _oidcConfigManager;
        }

        await _configLock.WaitAsync().ConfigureAwait(false);
        try
        {
            // Double-check after acquiring lock
            if (_oidcConfigManager is not null
                && string.Equals(_lastIssuer, issuer, StringComparison.Ordinal))
            {
                return _oidcConfigManager;
            }

            // Standard OIDC discovery endpoint
            var metadataAddress = issuer.TrimEnd('/') + "/.well-known/openid-configuration";

            _logger.LogInformation("Creating OIDC configuration manager for issuer {Issuer}", issuer);

            _oidcConfigManager = new ConfigurationManager<OpenIdConnectConfiguration>(
                metadataAddress,
                new OpenIdConnectConfigurationRetriever(),
                new HttpDocumentRetriever(_httpClientFactory.CreateClient(NamedClient.Default))
                {
                    RequireHttps = true
                });

            _lastIssuer = issuer;
            return _oidcConfigManager;
        }
        finally
        {
            _configLock.Release();
        }
    }
}

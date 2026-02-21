using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;
using Jellyfin.Api.Extensions;
using MediaBrowser.Common.Net;
using MediaBrowser.Controller.Configuration;
using MediaBrowser.Controller.Library;
using MediaBrowser.Controller.Session;
using MediaBrowser.Controller.Sso;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using MediaBrowser.Controller.Authentication;

namespace Jellyfin.Api.Controllers;

/// <summary>
/// Handles RFC 8628 Device Authorization Grant flows for TV apps and CLI clients.
/// Proxies the device flow to the configured OIDC provider and exchanges the
/// resulting identity token for a Jellyfin session.
/// </summary>
[Route("DeviceAuth")]
[ApiController]
public class DeviceAuthController : BaseJellyfinApiController
{
    private readonly IServerConfigurationManager _config;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ISsoJwtValidator _jwtValidator;
    private readonly IUserManager _userManager;
    private readonly ISessionManager _sessionManager;
    private readonly ILogger<DeviceAuthController> _logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="DeviceAuthController"/> class.
    /// </summary>
    /// <param name="config">The server configuration manager.</param>
    /// <param name="httpClientFactory">The HTTP client factory.</param>
    /// <param name="jwtValidator">The SSO JWT validator.</param>
    /// <param name="userManager">The user manager.</param>
    /// <param name="sessionManager">The session manager.</param>
    /// <param name="logger">The logger.</param>
    public DeviceAuthController(
        IServerConfigurationManager config,
        IHttpClientFactory httpClientFactory,
        ISsoJwtValidator jwtValidator,
        IUserManager userManager,
        ISessionManager sessionManager,
        ILogger<DeviceAuthController> logger)
    {
        _config = config;
        _httpClientFactory = httpClientFactory;
        _jwtValidator = jwtValidator;
        _userManager = userManager;
        _sessionManager = sessionManager;
        _logger = logger;
    }

    /// <summary>
    /// Starts the device authorization flow by calling the IdP.
    /// Returns the user_code and verification_uri.
    /// </summary>
    /// <response code="200">The device code was acquired successfully.</response>
    /// <response code="503">SSO Device Flow is not configured or disabled.</response>
    /// <returns>A JSON response conforming to RFC 8628.</returns>
    [HttpPost("Authorize")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status503ServiceUnavailable)]
    public async Task<IActionResult> StartDeviceAuth()
    {
        var cfg = _config.Configuration;
        if (!cfg.EnableSso || !cfg.SsoDeviceFlowEnabled || string.IsNullOrEmpty(cfg.SsoOidcDeviceEndpoint))
        {
            return StatusCode(StatusCodes.Status503ServiceUnavailable, "Device flow is not configured.");
        }

        using var client = _httpClientFactory.CreateClient(NamedClient.Default);

        var args = new Dictionary<string, string>
        {
            { "client_id", cfg.SsoOidcClientId },
            { "scope", "openid email profile" }
        };

        try
        {
            var response = await client.PostAsync(
                cfg.SsoOidcDeviceEndpoint,
                new FormUrlEncodedContent(args)).ConfigureAwait(false);

            var body = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

            if (!response.IsSuccessStatusCode)
            {
                _logger.LogWarning("IdP device authorization failed: {Body}", body);
                return BadRequest(body);
            }

            // Proxy the JSON payload directly to the client
            return Content(body, "application/json");
        }
        catch (HttpRequestException ex)
        {
            _logger.LogError(ex, "Failed to contact OIDC device endpoint.");
            return StatusCode(StatusCodes.Status502BadGateway, "Upstream IdP error.");
        }
    }

    /// <summary>
    /// Polls the IdP token endpoint to check if the user has completed authorization.
    /// If successful, the resulting Identity Token is verified and mapped to a Jellyfin session.
    /// </summary>
    /// <param name="deviceCode">The device_code acquired from Authorize.</param>
    /// <response code="200">The device was authorized and a Jellyfin session is returned.</response>
    /// <response code="400">The device is not yet authorized (authorization_pending) or the code expired/is invalid.</response>
    /// <returns>The <see cref="AuthenticationResult"/> if authorized.</returns>
    [HttpPost("Token")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status503ServiceUnavailable)]
    public async Task<IActionResult> PollDeviceToken([FromForm, Required] string deviceCode)
    {
        var cfg = _config.Configuration;
        if (!cfg.EnableSso || !cfg.SsoDeviceFlowEnabled || string.IsNullOrEmpty(cfg.SsoOidcTokenEndpoint))
        {
            return StatusCode(StatusCodes.Status503ServiceUnavailable, "Device flow is not configured.");
        }

        using var client = _httpClientFactory.CreateClient(NamedClient.Default);

        var args = new Dictionary<string, string>
        {
            { "grant_type", "urn:ietf:params:oauth:grant-type:device_code" },
            { "client_id", cfg.SsoOidcClientId },
            { "device_code", deviceCode }
        };

        try
        {
            var response = await client.PostAsync(
                cfg.SsoOidcTokenEndpoint,
                new FormUrlEncodedContent(args)).ConfigureAwait(false);

            var body = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

            // 400 Bad Request happens during normal polling (authorization_pending or slow_down)
            if (!response.IsSuccessStatusCode)
            {
                // Proxy the exact error back so the Jellyfin TV app knows to keep polling or stop
                return Content(body, "application/json", System.Text.Encoding.UTF8) { StatusCode = 400 };
            }

            // Success! The user authorized it on their phone/PC.
            using var jsonDoc = JsonDocument.Parse(body);
            var root = jsonDoc.RootElement;

            if (!root.TryGetProperty("id_token", out var idTokenElement))
            {
                _logger.LogError("IdP returned success for device flow but no id_token was present.");
                return StatusCode(StatusCodes.Status502BadGateway, "IdP response missing id_token.");
            }

            var idTokenStr = idTokenElement.GetString();
            if (string.IsNullOrEmpty(idTokenStr))
            {
                return StatusCode(StatusCodes.Status502BadGateway, "id_token string is empty.");
            }

            // Validate the Identity Token just like a proxy JWT
            var claims = await _jwtValidator.ValidateAsync(idTokenStr).ConfigureAwait(false);
            if (claims is null)
            {
                return Unauthorized("Identity mapping failed. The id_token was rejected.");
            }

            // Extract username
            if (!claims.TryGetValue(cfg.SsoUsernameClaim, out var username) || string.IsNullOrEmpty(username))
            {
                _logger.LogWarning("Device Flow id_token missing SSO claim '{Claim}'.", cfg.SsoUsernameClaim);
                return Unauthorized("Missing identity claim in id_token.");
            }

            var user = _userManager.GetUserByName(username);
            if (user is null)
            {
                if (!cfg.SsoAutoProvisionUsers)
                {
                    return Unauthorized($"User '{username}' does not exist and auto-provision is disabled.");
                }

                user = await _userManager.CreateUserAsync(username).ConfigureAwait(false);
            }

            // Identify device (for TV clients, these are often provided)
            var deviceId = Request.Headers["X-Jellyfin-DeviceId"].ToString();
            if (string.IsNullOrEmpty(deviceId))
            {
                deviceId = $"sso-device-{username}";
            }

            var deviceName = Request.Headers["X-Jellyfin-Device"].ToString();
            if (string.IsNullOrEmpty(deviceName))
            {
                deviceName = "SSO Device Client";
            }

            var appName = Request.Headers["X-Jellyfin-Client"].ToString();
            if (string.IsNullOrEmpty(appName))
            {
                appName = "Jellyfin TV";
            }

            var appVersion = Request.Headers["X-Jellyfin-Version"].ToString();
            if (string.IsNullOrEmpty(appVersion))
            {
                appVersion = "1.0.0";
            }

            var authResult = await _sessionManager.AuthenticateDirect(new MediaBrowser.Controller.Session.AuthenticationRequest
            {
                UserId = user.Id,
                DeviceId = deviceId,
                DeviceName = deviceName,
                App = appName,
                AppVersion = appVersion,
                RemoteEndPoint = HttpContext.GetNormalizedRemoteIP().ToString()
            }).ConfigureAwait(false);

            _logger.LogInformation("Device Flow login successful for {Username}", username);

            return Ok(authResult);
        }
        catch (HttpRequestException ex)
        {
            _logger.LogError(ex, "Failed to contact OIDC token endpoint.");
            return StatusCode(StatusCodes.Status502BadGateway, "Upstream IdP error.");
        }
    }
}

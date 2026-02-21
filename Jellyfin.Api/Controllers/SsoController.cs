using System.ComponentModel.DataAnnotations;
using System.Security.Authentication;
using System.Threading.Tasks;
using Jellyfin.Api.Constants;
using Jellyfin.Api.Extensions;
using MediaBrowser.Controller.Configuration;
using MediaBrowser.Controller.Library;
using MediaBrowser.Controller.Session;
using MediaBrowser.Model.Dto;
using MediaBrowser.Model.Session;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using MediaBrowser.Controller.Authentication;

namespace Jellyfin.Api.Controllers;

/// <summary>
/// Handles Single Sign-On (SSO) specific endpoints.
/// </summary>
[Route("Sso")]
[ApiController]
public class SsoController : BaseJellyfinApiController
{
    private readonly ISessionManager _sessionManager;
    private readonly IUserManager _userManager;
    private readonly IServerConfigurationManager _config;

    /// <summary>
    /// Initializes a new instance of the <see cref="SsoController"/> class.
    /// </summary>
    /// <param name="sessionManager">The session manager.</param>
    /// <param name="userManager">The user manager.</param>
    /// <param name="config">The server configuration manager.</param>
    public SsoController(
        ISessionManager sessionManager,
        IUserManager userManager,
        IServerConfigurationManager config)
    {
        _sessionManager = sessionManager;
        _userManager = userManager;
        _config = config;
    }

    /// <summary>
    /// Exerts an authentication check via the configured SSO proxy JWT and, if successful,
    /// returns a standard Jellyfin session token. The web client calls this on boot
    /// to transparently authenticate and cache the native token.
    /// </summary>
    /// <param name="clientAuthMode">Optional string indicating client capability.</param>
    /// <response code="200">The transparent SSO login succeeded. Returns a new authentication result.</response>
    /// <response code="401">The request lacks a valid SSO proxied authentication header or SSO is disabled.</response>
    /// <returns>A <see cref="Task"/> containing the <see cref="AuthenticationResult"/>.</returns>
    [HttpGet("Token")]
    [Authorize(AuthenticationSchemes = AuthenticationSchemes.SsoAuthentication)]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<ActionResult<AuthenticationResult>> GetSsoToken(
        [FromQuery] string? clientAuthMode = null)
    {
        if (!_config.Configuration.EnableSso)
        {
            return Unauthorized();
        }

        var username = User.Identity?.Name;
        if (string.IsNullOrEmpty(username))
        {
            return Unauthorized();
        }

        var user = _userManager.GetUserByName(username);
        if (user is null)
        {
            // Auto-provisioning occurs in the authentication handler. If we reach here and user is null,
            // provisioning is disabled or something failed.
            return Unauthorized();
        }

        // Gather device identifiers from the request, just like standard auth routes
        var deviceId = Request.Headers["X-Jellyfin-DeviceId"].ToString();
        if (string.IsNullOrEmpty(deviceId))
        {
            deviceId = $"sso-web-{username}";
        }

        var deviceName = Request.Headers["X-Jellyfin-Device"].ToString();
        if (string.IsNullOrEmpty(deviceName))
        {
            deviceName = "SSO Client Web";
        }

        var appName = Request.Headers["X-Jellyfin-Client"].ToString();
        if (string.IsNullOrEmpty(appName))
        {
            appName = "Jellyfin Web";
        }

        var appVersion = Request.Headers["X-Jellyfin-Version"].ToString();
        if (string.IsNullOrEmpty(appVersion))
        {
            appVersion = "1.0.0";
        }

        // Mint a real Jellyfin access token and create a tracking session for this device
        var authResult = await _sessionManager.AuthenticateDirect(new AuthenticationRequest
        {
            UserId = user.Id,
            DeviceId = deviceId,
            DeviceName = deviceName,
            App = appName,
            AppVersion = appVersion,
            RemoteEndPoint = HttpContext.GetNormalizedRemoteIP().ToString()
        }).ConfigureAwait(false);

        return authResult;
    }
}

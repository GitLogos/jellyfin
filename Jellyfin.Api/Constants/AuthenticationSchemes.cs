namespace Jellyfin.Api.Constants;

/// <summary>
/// Authentication schemes for user authentication in the API.
/// </summary>
public static class AuthenticationSchemes
{
    /// <summary>
    /// Scheme name for the custom legacy authentication.
    /// </summary>
    public const string CustomAuthentication = "CustomAuthentication";

    /// <summary>
    /// Scheme name for the SSO proxy JWT authentication.
    /// Active in parallel with <see cref="CustomAuthentication"/>; fires only when
    /// SSO is enabled and the configured JWT header is present in the request.
    /// </summary>
    public const string SsoAuthentication = "SsoAuthentication";
}

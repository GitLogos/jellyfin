using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace MediaBrowser.Controller.Sso;

/// <summary>
/// Validates JSON Web Tokens injected by an upstream SSO proxy (e.g. Cloudflare Access)
/// and returns the extracted claims on success.
/// </summary>
public interface ISsoJwtValidator
{
    /// <summary>
    /// Validates the JWT and returns extracted claims when valid.
    /// Returns <see langword="null"/> when SSO is disabled, the token is absent,
    /// or validation fails (expired, wrong issuer/audience, bad signature, etc.).
    /// </summary>
    /// <param name="jwt">The raw JWT string from the proxy header.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>
    /// A read-only dictionary of claim name → string value on success;
    /// <see langword="null"/> if the token is invalid or SSO is disabled.
    /// </returns>
    Task<IReadOnlyDictionary<string, string>?> ValidateAsync(
        string jwt,
        CancellationToken cancellationToken = default);
}

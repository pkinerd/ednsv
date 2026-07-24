using System.Security.Claims;

namespace Ednsv.Core.Services;

/// <summary>
/// Maps an externally authenticated principal (OIDC session or IdP-issued JWT)
/// onto the <see cref="AuthService.User"/> shape the web layer already uses,
/// so endpoints don't need to know which auth method produced the caller.
/// External users are never persisted — identity and roles are re-derived from
/// claims on every request, and their lifecycle stays with the IdP.
/// </summary>
public static class ExternalUserMapper
{
    public enum MapStatus { Success, MissingUsername, RootCollision, MissingRequiredRole }

    public sealed record MapResult(MapStatus Status, AuthService.User? User = null);

    /// <param name="usernameClaims">Claim types tried in order for the username.</param>
    /// <param name="roleClaim">Claim type holding role values (e.g. "roles" or "groups").</param>
    /// <param name="adminRoles">Any match (case-insensitive) grants IsAdmin.</param>
    /// <param name="requiredRoles">When non-empty, the principal must hold at least one.</param>
    /// <param name="usernamePrefix">Prefix for the mapped username (e.g. "app:" for service accounts).</param>
    public static MapResult Map(
        ClaimsPrincipal principal,
        IReadOnlyList<string> usernameClaims,
        string roleClaim,
        IReadOnlyList<string> adminRoles,
        IReadOnlyList<string> requiredRoles,
        string usernamePrefix = "")
    {
        string? username = null;
        foreach (var type in usernameClaims)
        {
            username = principal.FindFirst(type)?.Value;
            if (!string.IsNullOrWhiteSpace(username)) break;
        }
        if (string.IsNullOrWhiteSpace(username))
            return new MapResult(MapStatus.MissingUsername);

        username = usernamePrefix + username.Trim();

        // An IdP-controlled username equal to the root user would inherit root's
        // special powers (sees all tokens, may delete users) — refuse it outright.
        if (username.Equals(AuthService.RootUsername, StringComparison.OrdinalIgnoreCase))
            return new MapResult(MapStatus.RootCollision);

        var roles = principal.FindAll(roleClaim).Select(c => c.Value).ToList();

        if (requiredRoles.Count > 0 &&
            !roles.Any(r => requiredRoles.Contains(r, StringComparer.OrdinalIgnoreCase)))
            return new MapResult(MapStatus.MissingRequiredRole);

        var isAdmin = roles.Any(r => adminRoles.Contains(r, StringComparer.OrdinalIgnoreCase));

        return new MapResult(MapStatus.Success, new AuthService.User
        {
            Username = username,
            Hash = "",
            IssuedBy = "",
            IsAdmin = isAdmin,
            IssuedAt = DateTime.MinValue,
            Revoked = false
        });
    }
}

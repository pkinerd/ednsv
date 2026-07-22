using System.Security.Claims;
using Ednsv.Core.Services;

namespace Ednsv.Core.Tests;

public class ExternalUserMapperTests
{
    private static readonly string[] OidcUsernameClaims = { "preferred_username", "upn", "email", "sub" };
    private static readonly string[] AdminRoles = { "Ednsv.Admin" };
    private static readonly string[] NoRequiredRoles = System.Array.Empty<string>();

    private static ClaimsPrincipal Principal(params (string Type, string Value)[] claims)
        => new(new ClaimsIdentity(claims.Select(c => new Claim(c.Type, c.Value)), "test"));

    [Fact]
    public void MapsUsernameAndAdminRole()
    {
        var p = Principal(("preferred_username", "alice@contoso.com"), ("roles", "Ednsv.Admin"));
        var result = ExternalUserMapper.Map(p, OidcUsernameClaims, "roles", AdminRoles, NoRequiredRoles);

        Assert.Equal(ExternalUserMapper.MapStatus.Success, result.Status);
        Assert.Equal("alice@contoso.com", result.User!.Username);
        Assert.True(result.User.IsAdmin);
        Assert.Equal("", result.User.Hash);
        Assert.Equal("", result.User.IssuedBy);
    }

    [Fact]
    public void NonAdminWithoutAdminRole()
    {
        var p = Principal(("preferred_username", "bob@contoso.com"), ("roles", "Something.Else"));
        var result = ExternalUserMapper.Map(p, OidcUsernameClaims, "roles", AdminRoles, NoRequiredRoles);

        Assert.Equal(ExternalUserMapper.MapStatus.Success, result.Status);
        Assert.False(result.User!.IsAdmin);
    }

    [Fact]
    public void AdminRoleMatchIsCaseInsensitive()
    {
        var p = Principal(("preferred_username", "alice@contoso.com"), ("roles", "EDNSV.ADMIN"));
        var result = ExternalUserMapper.Map(p, OidcUsernameClaims, "roles", AdminRoles, NoRequiredRoles);

        Assert.True(result.User!.IsAdmin);
    }

    [Fact]
    public void UsernameFallbackChain()
    {
        // No preferred_username/upn → falls through to email, then sub.
        var withEmail = Principal(("email", "carol@contoso.com"), ("sub", "subject-id"));
        Assert.Equal("carol@contoso.com",
            ExternalUserMapper.Map(withEmail, OidcUsernameClaims, "roles", AdminRoles, NoRequiredRoles).User!.Username);

        var subOnly = Principal(("sub", "subject-id"));
        Assert.Equal("subject-id",
            ExternalUserMapper.Map(subOnly, OidcUsernameClaims, "roles", AdminRoles, NoRequiredRoles).User!.Username);
    }

    [Fact]
    public void MissingUsernameFails()
    {
        var p = Principal(("roles", "Ednsv.Admin"));
        var result = ExternalUserMapper.Map(p, OidcUsernameClaims, "roles", AdminRoles, NoRequiredRoles);

        Assert.Equal(ExternalUserMapper.MapStatus.MissingUsername, result.Status);
        Assert.Null(result.User);
    }

    [Theory]
    [InlineData("ednsv")]
    [InlineData("EDNSV")]
    public void RootUsernameCollisionRejected(string claimed)
    {
        // IdP-controlled claims must never yield the root user's identity.
        var p = Principal(("preferred_username", claimed));
        var result = ExternalUserMapper.Map(p, OidcUsernameClaims, "roles", AdminRoles, NoRequiredRoles);

        Assert.Equal(ExternalUserMapper.MapStatus.RootCollision, result.Status);
        Assert.Null(result.User);
    }

    [Fact]
    public void RequiredRolesEnforced()
    {
        var required = new[] { "Ednsv.Access" };

        var without = Principal(("preferred_username", "dave@contoso.com"));
        Assert.Equal(ExternalUserMapper.MapStatus.MissingRequiredRole,
            ExternalUserMapper.Map(without, OidcUsernameClaims, "roles", AdminRoles, required).Status);

        var with = Principal(("preferred_username", "dave@contoso.com"), ("roles", "ednsv.access"));
        Assert.Equal(ExternalUserMapper.MapStatus.Success,
            ExternalUserMapper.Map(with, OidcUsernameClaims, "roles", AdminRoles, required).Status);
    }

    [Fact]
    public void GroupsClaimVariant()
    {
        // Role mapping via Entra group object IDs instead of app roles.
        var groupId = "3f2504e0-4f89-11d3-9a0c-0305e82c3301";
        var p = Principal(("preferred_username", "erin@contoso.com"), ("groups", groupId));
        var result = ExternalUserMapper.Map(p, OidcUsernameClaims, "groups", new[] { groupId }, NoRequiredRoles);

        Assert.True(result.User!.IsAdmin);
    }

    [Fact]
    public void ServiceAccountPrefixApplied()
    {
        var p = Principal(("azp", "11111111-2222-3333-4444-555555555555"), ("roles", "Ednsv.Admin"));
        var result = ExternalUserMapper.Map(
            p, new[] { "azp", "appid" }, "roles", AdminRoles, NoRequiredRoles, usernamePrefix: "app:");

        Assert.Equal("app:11111111-2222-3333-4444-555555555555", result.User!.Username);
        Assert.True(result.User.IsAdmin);
    }

    [Fact]
    public void ServiceAccountAppIdFallback()
    {
        // v1-style tokens carry appid instead of azp.
        var p = Principal(("appid", "66666666-7777-8888-9999-000000000000"));
        var result = ExternalUserMapper.Map(
            p, new[] { "azp", "appid" }, "roles", AdminRoles, NoRequiredRoles, usernamePrefix: "app:");

        Assert.Equal("app:66666666-7777-8888-9999-000000000000", result.User!.Username);
        Assert.False(result.User.IsAdmin);
    }
}

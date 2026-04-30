using Ednsv.Core.Services;

namespace Ednsv.Core.Tests;

public sealed class AuthServiceTests : IDisposable
{
    private readonly string _dir;

    public AuthServiceTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), $"ednsv-auth-test-{Guid.NewGuid():N}");
    }

    public void Dispose()
    {
        if (Directory.Exists(_dir)) Directory.Delete(_dir, true);
    }

    [Fact]
    public void Hash_MatchesKnownVector()
    {
        // sha256("hello") = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
        // base64url(no padding) of that 32-byte digest:
        Assert.Equal("LPJNul-wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ", AuthService.Hash("hello"));
    }

    [Fact]
    public void Disabled_When_HashIsNoneOrEmpty()
    {
        Assert.True(new AuthService(_dir, "none").Disabled);
        Assert.True(new AuthService(_dir, "NONE").Disabled);
        Assert.True(new AuthService(_dir, "").Disabled);
        Assert.True(new AuthService(_dir, null).Disabled);
        Assert.False(new AuthService(_dir, "abc").Disabled);
    }

    [Fact]
    public void RootUser_AuthenticatesWithBasicAndBearer()
    {
        var token = "root-secret";
        var auth = new AuthService(_dir, AuthService.Hash(token));

        var basicHit = auth.AuthenticateBasic("ednsv", token);
        Assert.NotNull(basicHit);
        Assert.Equal("ednsv", basicHit!.Username);
        Assert.True(basicHit.IsAdmin);

        var bearerHit = auth.AuthenticateBearer(token);
        Assert.NotNull(bearerHit);
        Assert.Equal("ednsv", bearerHit!.Username);

        Assert.Null(auth.AuthenticateBasic("ednsv", "wrong"));
        Assert.Null(auth.AuthenticateBearer("wrong"));
    }

    [Fact]
    public void Issue_CreatesUser_AndTokenAuthenticates()
    {
        var auth = new AuthService(_dir, AuthService.Hash("root"));
        var result = auth.Issue("alice", isAdmin: false, issuedBy: "ednsv", issuedFromIp: "1.2.3.4");

        Assert.Equal(AuthService.IssueStatus.Success, result.Status);
        Assert.NotNull(result.Token);
        Assert.NotNull(result.User);
        Assert.Equal("alice", result.User!.Username);
        Assert.Equal("1.2.3.4", result.User.IssuedFromIp);

        var hit = auth.AuthenticateBearer(result.Token!);
        Assert.NotNull(hit);
        Assert.Equal("alice", hit!.Username);
        Assert.False(hit.IsAdmin);
    }

    [Fact]
    public void Issue_RejectsDuplicateAndRootUsername()
    {
        var auth = new AuthService(_dir, AuthService.Hash("root"));
        Assert.Equal(AuthService.IssueStatus.UsernameTaken,
            auth.Issue("ednsv", false, "ednsv", null).Status);

        auth.Issue("alice", false, "ednsv", null);
        Assert.Equal(AuthService.IssueStatus.UsernameTaken,
            auth.Issue("alice", false, "ednsv", null).Status);
        Assert.Equal(AuthService.IssueStatus.UsernameTaken,
            auth.Issue("ALICE", false, "ednsv", null).Status);
    }

    [Fact]
    public void Issue_RejectsInvalidUsernames()
    {
        var auth = new AuthService(_dir, AuthService.Hash("root"));
        Assert.Equal(AuthService.IssueStatus.InvalidUsername,
            auth.Issue("", false, "ednsv", null).Status);
        Assert.Equal(AuthService.IssueStatus.InvalidUsername,
            auth.Issue("has space", false, "ednsv", null).Status);
        Assert.Equal(AuthService.IssueStatus.InvalidUsername,
            auth.Issue("with/slash", false, "ednsv", null).Status);
        Assert.Equal(AuthService.IssueStatus.InvalidUsername,
            auth.Issue(new string('a', 65), false, "ednsv", null).Status);
    }

    [Fact]
    public void Revoke_CascadesToDescendants()
    {
        var auth = new AuthService(_dir, AuthService.Hash("root"));
        var alice = auth.Issue("alice", true, "ednsv", null);
        var bob = auth.Issue("bob", true, "alice", null);
        var carol = auth.Issue("carol", false, "bob", null);
        var dave = auth.Issue("dave", false, "ednsv", null); // sibling — should NOT be revoked

        // Root revokes alice → cascades to bob & carol but not dave.
        var result = auth.Revoke("alice", "ednsv");
        Assert.Equal(AuthService.RevokeStatus.Success, result.Status);
        Assert.Contains("alice", result.Affected!);
        Assert.Contains("bob", result.Affected!);
        Assert.Contains("carol", result.Affected!);
        Assert.DoesNotContain("dave", result.Affected!);

        Assert.Null(auth.AuthenticateBearer(alice.Token!));
        Assert.Null(auth.AuthenticateBearer(bob.Token!));
        Assert.Null(auth.AuthenticateBearer(carol.Token!));
        Assert.NotNull(auth.AuthenticateBearer(dave.Token!));
    }

    [Fact]
    public void Revoke_RequiresAncestorOrRoot()
    {
        var auth = new AuthService(_dir, AuthService.Hash("root"));
        auth.Issue("alice", true, "ednsv", null);
        auth.Issue("bob", true, "ednsv", null);

        // bob is not an ancestor of alice
        Assert.Equal(AuthService.RevokeStatus.NotAllowed,
            auth.Revoke("alice", "bob").Status);

        // alice cannot revoke root
        Assert.Equal(AuthService.RevokeStatus.NotAllowed,
            auth.Revoke("ednsv", "alice").Status);

        // root can
        Assert.Equal(AuthService.RevokeStatus.Success,
            auth.Revoke("alice", "ednsv").Status);
    }

    [Fact]
    public void Revoke_AncestorChain_AllowsIndirectAncestor()
    {
        var auth = new AuthService(_dir, AuthService.Hash("root"));
        auth.Issue("alice", true, "ednsv", null);
        auth.Issue("bob", true, "alice", null);
        auth.Issue("carol", false, "bob", null);

        // alice is an indirect ancestor of carol (alice -> bob -> carol)
        Assert.Equal(AuthService.RevokeStatus.Success,
            auth.Revoke("carol", "alice").Status);
    }

    [Fact]
    public void ListVisibleTo_ReturnsDescendantsOnly()
    {
        var auth = new AuthService(_dir, AuthService.Hash("root"));
        auth.Issue("alice", true, "ednsv", null);
        auth.Issue("bob", false, "alice", null);
        auth.Issue("carol", false, "ednsv", null);

        var rootView = auth.ListVisibleTo("ednsv");
        Assert.Equal(3, rootView.Count);

        var aliceView = auth.ListVisibleTo("alice");
        Assert.Single(aliceView);
        Assert.Equal("bob", aliceView[0].Username);

        var bobView = auth.ListVisibleTo("bob");
        Assert.Empty(bobView);
    }

    [Fact]
    public void Load_MigratesLegacyCanIssue_ToIsAdmin()
    {
        // A users.json written by the previous schema (canIssue) should still
        // load and upgrade to IsAdmin transparently.
        Directory.CreateDirectory(_dir);
        var legacyJson = """
        {
          "users": [
            { "username": "alice", "hash": "x", "issuedBy": "ednsv", "canIssue": true,  "issuedAt": "2025-01-01T00:00:00Z", "revoked": false },
            { "username": "bob",   "hash": "y", "issuedBy": "ednsv", "canIssue": false, "issuedAt": "2025-01-01T00:00:00Z", "revoked": false }
          ]
        }
        """;
        File.WriteAllText(Path.Combine(_dir, "users.json"), legacyJson);

        var auth = new AuthService(_dir, AuthService.Hash("root"));
        auth.Load();
        var users = auth.ListVisibleTo("ednsv");
        Assert.Equal(2, users.Count);
        Assert.True(users.First(u => u.Username == "alice").IsAdmin);
        Assert.False(users.First(u => u.Username == "bob").IsAdmin);
    }

    [Fact]
    public void Delete_OnlyRoot_OnlyRevoked_CascadesAndRemoves()
    {
        var auth = new AuthService(_dir, AuthService.Hash("root"));
        var alice = auth.Issue("alice", true, "ednsv", null);
        var bob = auth.Issue("bob", true, "alice", null);
        var carol = auth.Issue("carol", false, "ednsv", null);

        // Cannot delete an active user.
        Assert.Equal(AuthService.DeleteStatus.NotRevoked,
            auth.Delete("alice", "ednsv").Status);

        // Non-root cannot delete even after revocation.
        auth.Revoke("alice", "ednsv");
        Assert.Equal(AuthService.DeleteStatus.NotAllowed,
            auth.Delete("alice", "carol").Status);

        // Root cannot delete the root account.
        Assert.Equal(AuthService.DeleteStatus.NotAllowed,
            auth.Delete("ednsv", "ednsv").Status);

        // Root deletes alice → bob is wiped too (cascade), carol survives.
        var result = auth.Delete("alice", "ednsv");
        Assert.Equal(AuthService.DeleteStatus.Success, result.Status);
        Assert.Contains("alice", result.Affected!);
        Assert.Contains("bob", result.Affected!);
        Assert.DoesNotContain("carol", result.Affected!);

        var remaining = auth.ListVisibleTo("ednsv");
        Assert.Single(remaining);
        Assert.Equal("carol", remaining[0].Username);

        // Re-issuing a deleted username is now allowed.
        Assert.Equal(AuthService.IssueStatus.Success,
            auth.Issue("alice", false, "ednsv", null).Status);

        // Missing target.
        Assert.Equal(AuthService.DeleteStatus.NotFound,
            auth.Delete("nobody", "ednsv").Status);
    }

    [Fact]
    public void Persistence_RoundTripsAcrossInstances()
    {
        var rootHash = AuthService.Hash("root");
        var auth1 = new AuthService(_dir, rootHash);
        var issued = auth1.Issue("alice", true, "ednsv", "10.0.0.1");
        Assert.Equal(AuthService.IssueStatus.Success, issued.Status);

        var auth2 = new AuthService(_dir, rootHash);
        auth2.Load();
        var hit = auth2.AuthenticateBasic("alice", issued.Token!);
        Assert.NotNull(hit);
        Assert.Equal("10.0.0.1", hit!.IssuedFromIp);
    }
}

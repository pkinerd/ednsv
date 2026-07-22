# Entra ID (Azure AD) setup

How to wire ednsv's external-IdP auth to Microsoft Entra ID: interactive
single sign-on for users, and client-credentials API access for service
accounts. Config key reference: [configuration.md](configuration.md#authentication).
Any other OIDC-compliant IdP (Keycloak, Okta, Authentik, …) works the same
way — substitute its issuer URL for the Entra authority.

## 1. App registration (shared by both flows)

1. **Entra admin center → App registrations → New registration.**
   - Name: e.g. `ednsv`.
   - Supported account types: usually *Accounts in this organizational
     directory only*.
2. Note the **Application (client) ID** and **Directory (tenant) ID**.
3. The authority for all config below is
   `https://login.microsoftonline.com/{tenantId}/v2.0`.

## 2. Interactive SSO for users

1. In the app registration, **Authentication → Add a platform → Web**:
   - Redirect URI: `https://<your-host>/signin-oidc`
   - Front-channel logout URL (only needed for `SingleLogout`):
     `https://<your-host>/signout-callback-oidc`
2. **Certificates & secrets → New client secret.** Note the secret *value*.
3. **App roles → Create app role** for admins:
   - Display name / value: `Ednsv.Admin`, allowed member types: **Users/Groups**.
   - Optionally a second role (e.g. `Ednsv.User`) if you want to restrict
     sign-in to assigned users via `RequiredRoles`.
4. Assign the role(s): **Enterprise applications → ednsv → Users and groups →
   Add user/group.** To require assignment for *any* sign-in, also enable
   *Properties → Assignment required* and list the allowed roles in
   `Auth:Oidc:RequiredRoles`.
5. Configure ednsv:

```sh
export Auth__Oidc__Enabled=true
export Auth__Oidc__Authority="https://login.microsoftonline.com/{tenantId}/v2.0"
export Auth__Oidc__ClientId="{clientId}"
export EDNSV_OIDC_CLIENT_SECRET="{clientSecretValue}"
# optional:
# export Auth__Oidc__AdminRoles__0=Ednsv.Admin        # default
# export Auth__Oidc__RequiredRoles__0=Ednsv.User      # restrict sign-in
# export Auth__Oidc__SingleLogout=true                # sign out of Entra too
```

The login page now shows a **Sign in with single sign-on** button. Users
holding the `Ednsv.Admin` app role get the admin UI (config page, token
issuance when token auth is also enabled); everyone else is a standard user.
Group-based mapping is possible instead of app roles: set
`Auth:Oidc:RoleClaim=groups`, put group **object IDs** in `AdminRoles`, and
enable the groups claim on the app registration (**Token configuration → Add
groups claim**) — app roles are recommended, since large group memberships
overflow into a "groups overage" claim that ednsv does not resolve.

## 3. Service accounts (client credentials)

1. In the **ednsv app registration**, expose an API: **Expose an API → Set
   Application ID URI** (default `api://{clientId}`).
2. **App roles → Create app role** with allowed member type **Applications**,
   e.g. value `Ednsv.Access` (and/or `Ednsv.Admin` for admin service
   accounts).
3. For each service account, create its **own app registration** (client ID +
   secret), then grant it the role: in the ednsv registration's **API
   permissions** of the *service account's* registration → **Add a
   permission → My APIs → ednsv → Application permissions** → select
   `Ednsv.Access` → **Grant admin consent**.
4. Configure ednsv to accept those tokens:

```sh
export Auth__JwtBearer__Enabled=true
export Auth__JwtBearer__Authority="https://login.microsoftonline.com/{tenantId}/v2.0"
export Auth__JwtBearer__Audiences__0="api://{clientId}"
export Auth__JwtBearer__RequiredRoles__0=Ednsv.Access   # recommended
```

5. The service account requests a token and calls the API with it:

```sh
ACCESS_TOKEN=$(curl -s -X POST \
  "https://login.microsoftonline.com/{tenantId}/oauth2/v2.0/token" \
  -d grant_type=client_credentials \
  -d client_id="{serviceAccountClientId}" \
  -d client_secret="{serviceAccountSecret}" \
  -d scope="api://{clientId}/.default" | jq -r .access_token)

curl -H "Authorization: Bearer $ACCESS_TOKEN" https://<your-host>/api/auth/me
# → { "username": "app:{serviceAccountClientId}", ... }
```

ednsv identifies service accounts as `app:{clientId}` (from the token's `azp`
claim). Tokens without one of `RequiredRoles` are rejected; tokens holding an
`AdminRoles` value get admin. ednsv-issued tokens keep working on the same
`Authorization: Bearer` header — the two are distinguished automatically.

## Notes

- **HTTPS + reverse proxy:** serve ednsv over HTTPS and set
  `ASPNETCORE_FORWARDEDHEADERS_ENABLED=true` behind a proxy, or the Entra
  redirect will be built with the wrong scheme/host and the sign-in
  correlation cookie will be dropped.
- **Key rotation:** Entra signing-key rollover is handled automatically via
  the OIDC metadata endpoint; no ednsv config is involved.
- **Sessions:** SSO sessions last `Auth:Oidc:SessionHours` (sliding, default
  8h) and survive restarts as long as `{DataDir}/keys` is persisted.

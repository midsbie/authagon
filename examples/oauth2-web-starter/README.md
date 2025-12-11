# OAuth2 Web Starter

OAuth2 Web Starter is a minimal example that wires Authagon into a Go web app using the chi router. It demonstrates:

- OAuth2/OIDC login with Google and Microsoft.
- Short-lived handshake state via `JWTStateStore`.
- Long-lived app sessions via `SessionCtl`.

It is intended for local development and exploration, **not** production use.

## Installation

```bash
git clone https://github.com/midsbie/authagon.git
cd authagon/examples/oauth2-web-starter
go mod tidy
```

## Configuration

Set provider credentials via environment variables before running the app.

### Google

- Create an OAuth client in [Google Cloud Console](https://console.cloud.google.com/apis/credentials).
- Add an authorized redirect URI:
  - `http://localhost:3000/u/auth/google/callback`
- Export credentials:

  ```sh
  AUTH_OAUTH_PROVIDER_GOOGLE_KEY=your-google-client-id
  AUTH_OAUTH_PROVIDER_GOOGLE_SECRET=your-google-client-secret
  ```

- If you need a different redirect path, configure it via
  `oauth2.WithCallbackPathTemplate(...)` when constructing the `oauth2.OAuth2Service`
  and keep it in sync with the URI registered in Google.

### Microsoft

- Create an app registration in the [Azure Portal](https://portal.azure.com/).
- Configure a web redirect URI:
  - `http://localhost:3000/u/auth/microsoft/callback`
- Export credentials:

  ```sh
  AUTH_OAUTH_PROVIDER_MICROSOFT_KEY=your-microsoft-client-id
  AUTH_OAUTH_PROVIDER_MICROSOFT_SECRET=your-microsoft-client-secret
  ```

## Running

```bash
go run .
```

Then visit:

- `http://localhost:3000` – choose a provider to start login.
- `http://localhost:3000/u/profile` – view the authenticated profile (after login).

## What the Example Shows

- Browser and handshake state:
  - `store.NewCookieStore(store.WithSecure(false))` for local HTTP development.
  - `oauth2.NewJWTStateStore(...)` for short-lived OAuth2/OIDC state.
- OAuth2 service:
  - `oauth2.NewService(...)` with `oauth2.NewGoogle` and `oauth2.NewMicrosoft`.
- App sessions:
  - `store.NewMemoryStore[oauth2.AuthResult]()` plus `oauth2.NewSessionCtl(...)`.
- A simple HTML profile view that renders `AuthResult` fields (for demo only).

## Security Notes

This starter trades off security for simplicity in a few places:

- Cookies:
  - Uses `store.WithSecure(false)` so cookies work over plain HTTP on `localhost`.
  - In production, serve over HTTPS and use secure settings
    (`Secure=true`, `HttpOnly=true`, appropriate `SameSite`, `Path`, `Domain`).
- Tokens in HTML:
  - `profileTpl` renders access and refresh tokens in the page to show what’s in
    `AuthResult`. This is **not safe for production**; anyone with page access can
    reuse those tokens.
  - In a real app, keep tokens server-side and use them only when calling provider APIs.
- Audience:
  - `oauth2.JWTStateStore` can enforce an audience via `WithAudience`. Set this to a
    value that identifies your app and keep it consistent across deployments.

## License

Distributed under the MIT License. See the root `LICENSE` file for details.


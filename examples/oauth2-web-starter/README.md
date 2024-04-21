# OAuth2 Web Starter

OAuth2 Web Starter is an exemplary project that demonstrates how to implement OAuth2 authentication
in a Go web application using the chi router and authagon library. This setup simplifies
incorporating OAuth2 providers like Google into your application, managing sessions, and handling
user profiles efficiently.

## Getting Started

### Installing

```bash
git clone https://github.com/midsbie/authagon/examples/oauth2-web-starter.git
cd oauth2-web-starter
go mod tidy
```

### Configuration

Configure your OAuth2 providers directly in your system environment. Ensure these values are set
before starting the application to prevent it from erroring out.

#### Google OAuth2 Setup

1. Create a client application in [Google Cloud Platform](https://console.cloud.google.com/apis/credentials).
1. Set an authorized redirect URI to http://localhost:3000/u/auth/google/callback in your Google
   Cloud Platform project.
   - If this URI needs to be different, modify the `CallbackPathTemplate` in the
     `oauth2.ServiceConfig` configuration to match the authorized redirect URI specified in your
     Google project.
1. In the "Credentials" tab, create OAuth 2.0 Credentials and note the client ID and secret.
1. Set the following environment variables:
   ```sh
   AUTH_OAUTH_PROVIDER_GOOGLE_KEY=your-google-client-id
   AUTH_OAUTH_PROVIDER_GOOGLE_SECRET=your-google-client-secret
   ```

### Microsoft OAuth2 Setup

1. Create a client application in the [Azure
   Portal](https://portal.azure.com/#view/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/~/Overview).
1. Navigate to "App registrations" and select "New registration".
   - Set the name for your application.
   - Choose the supported account types (e.g., single tenant, multi-tenant, and personal Microsoft
     accounts).
   - Specify the redirect URI: `http://localhost:3000/u/auth/microsoft/callback`
1. Once the application is registered, go to the "Authentication" tab:
   - Ensure the redirect URI is correctly added. If not, add it under the "Web" platform settings.
1. Go to the "Overview" tab and note your application's client ID.
1. Go to the "Certificates & secrets" tab:
   - Create a new client secret and note its value.
1. Set the following environment variables:

   ```sh
   AUTH_OAUTH_PROVIDER_MICROSOFT_KEY=<your-microsoft-client-id>
   AUTH_OAUTH_PROVIDER_MICROSOFT_SECRET=<your-microsoft-client-secret>
   ```

### Usage

To run the application, simply execute:

```bash
go run .
```

This will start the web server on http://localhost:3000 and will be ready to authenticate users via
the configured providers.

Visit http://localhost:3000 and click on "Log in with <provider>" to authenticate with your provider
of choice. Once logged in, you can view the user's profile by navigating to the profile page.

## Contributing

Contributions are what make the open-source community such an amazing place to learn, inspire, and
create. All contributions are greatly appreciated.

## License

Distributed under the MIT License. See LICENSE file in the root of this repository for more
information.
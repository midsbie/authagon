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

Configure your OAuth2 providers in the `.env` file or directly in your environment. Ensure these
values are set before starting the application as they are essential for the authentication process.


#### Google OAuth2 Setup:

1. Create a client application in Google Cloud Platform.
1. Set an authorized redirect URI to http://localhost:3000/u/auth/google/callback in your Google
   Cloud Platform project.
1. If this URI needs to be different, modify the `CallbackPathTemplate` in the
   `oauth2.ServiceConfig` configuration to match the authorized redirect URI specified in your
   Google project.

Set the following environment vars:
```
AUTH_OAUTH_PROVIDER_GOOGLE_KEY=your-google-client-id
AUTH_OAUTH_PROVIDER_GOOGLE_SECRET=your-google-client-secret
```

### Usage

To run the application, simply execute:

```bash
go run .
```

This will start the web server on http://localhost:3000 and will be ready to authenticate users via
the configured providers.

Visit http://localhost:3000 and click on "Log in with Google" to authenticate using Google. Once
logged in, you can view the user's profile by navigating to the profile page.

## Contributing

Contributions are what make the open-source community such an amazing place to learn, inspire, and
create. All contributions are greatly appreciated.

## License

Distributed under the MIT License. See LICENSE file in the root of this repository for more
information.
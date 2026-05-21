"""Static configuration for OAuth2 provider types."""

PROVIDER_CONFIG: dict[str, dict[str, str]] = {
    "oauth2-github": {
        "authorization_endpoint": "https://github.com/login/oauth/authorize",
        "token_endpoint": "https://github.com/login/oauth/access_token",
    },
}

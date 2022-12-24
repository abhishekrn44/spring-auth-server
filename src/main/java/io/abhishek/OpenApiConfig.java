package io.abhishek;

import io.swagger.v3.oas.annotations.enums.SecuritySchemeType;
import io.swagger.v3.oas.annotations.security.OAuthFlow;
import io.swagger.v3.oas.annotations.security.OAuthFlows;
import io.swagger.v3.oas.annotations.security.OAuthScope;
import io.swagger.v3.oas.annotations.security.SecurityScheme;

@SecurityScheme(name = "security_auth", type = SecuritySchemeType.OAUTH2, flows = @OAuthFlows(authorizationCode = @OAuthFlow(authorizationUrl = "http://localhost:9999/oauth2/authorize", tokenUrl = "http://localhost:9999/oauth2/token", scopes = {
		@OAuthScope(name = "read", description = "read"), @OAuthScope(name = "write", description = "write") })))
public class OpenApiConfig {
}

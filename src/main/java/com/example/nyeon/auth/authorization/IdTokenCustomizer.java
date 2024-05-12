package com.example.nyeon.auth.authorization;

import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.stereotype.Component;

@Component
public class IdTokenCustomizer implements OAuth2TokenCustomizer<JwtEncodingContext> {
    private final OidcUserInfoService oidcUserInfoService;

    public IdTokenCustomizer(OidcUserInfoService oidcUserInfoService) {
        this.oidcUserInfoService = oidcUserInfoService;
    }

    @Override
    public void customize(JwtEncodingContext context) {
        if (OidcParameterNames.ID_TOKEN.equals(context.getTokenType().getValue())) {
            OidcUserInfo oidcUserInfo = oidcUserInfoService.loadUser(context.getPrincipal().getName());
            context.getClaims().claims(claims -> claims.putAll(oidcUserInfo.getClaims()));
        }
    }
}

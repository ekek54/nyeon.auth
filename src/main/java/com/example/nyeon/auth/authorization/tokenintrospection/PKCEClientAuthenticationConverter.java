package com.example.nyeon.auth.authorization.tokenintrospection;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpMethod;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.util.matcher.AndRequestMatcher;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.StringUtils;

public class PKCEClientAuthenticationConverter implements AuthenticationConverter {
    private final RequestMatcher pkceTokenIntrospectionEndpointMatcher;

    public PKCEClientAuthenticationConverter(String tokenIntrospectionEndpointUri) {
        RequestMatcher clientIdParameterMatcher = request ->
                request.getParameter(OAuth2ParameterNames.CLIENT_ID) != null;
        this.pkceTokenIntrospectionEndpointMatcher = new AndRequestMatcher(
                clientIdParameterMatcher,
                new AntPathRequestMatcher(tokenIntrospectionEndpointUri, HttpMethod.POST.name()));
    }

    @Override
    public Authentication convert(HttpServletRequest request) {
        if (!this.pkceTokenIntrospectionEndpointMatcher.matches(request)) {
            return null;
        }

        String clientId = request.getParameter(OAuth2ParameterNames.CLIENT_ID);
        if (!StringUtils.hasText(clientId) ||
                request.getParameterValues(OAuth2ParameterNames.CLIENT_ID).length != 1) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
        }

        return new PKCEClientAuthenticationToken(clientId, ClientAuthenticationMethod.NONE, null, null);
    }
}

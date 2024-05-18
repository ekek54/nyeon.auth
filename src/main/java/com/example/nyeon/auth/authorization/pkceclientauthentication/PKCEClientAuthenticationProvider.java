package com.example.nyeon.auth.authorization.pkceclientauthentication;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

@Slf4j
public class PKCEClientAuthenticationProvider implements AuthenticationProvider {
    private static final String ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-3.2.1";
    private final RegisteredClientRepository registeredClientRepository;

    public PKCEClientAuthenticationProvider(RegisteredClientRepository registeredClientRepository) {
        this.registeredClientRepository = registeredClientRepository;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        PKCEClientAuthenticationToken pkceClientAuthentication = (PKCEClientAuthenticationToken) authentication;

        if (!ClientAuthenticationMethod.NONE.equals(pkceClientAuthentication.getClientAuthenticationMethod())) {
            return null;
        }

        String clientId = pkceClientAuthentication.getPrincipal().toString();
        RegisteredClient registeredClient = this.registeredClientRepository.findByClientId(clientId);
        if (registeredClient == null) {
            throwInvalidClient(OAuth2ParameterNames.CLIENT_ID);
        }

        if (!registeredClient.getClientAuthenticationMethods().contains(
                pkceClientAuthentication.getClientAuthenticationMethod())) {
            throwInvalidClient("authentication_method");
        }

        if (log.isTraceEnabled()) {
            log.trace("Authenticated pkce client");
        }
        PKCEClientAuthenticationToken result = new PKCEClientAuthenticationToken(
                registeredClient,
                pkceClientAuthentication.getClientAuthenticationMethod(), null);

        log.info("result: {}", result.getPrincipal().toString());

        return result;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return PKCEClientAuthenticationToken.class.isAssignableFrom(authentication);
    }

    private static void throwInvalidClient(String parameterName) {
        OAuth2Error error = new OAuth2Error(
                OAuth2ErrorCodes.INVALID_CLIENT,
                "PKCE client authentication failed: " + parameterName,
                ERROR_URI
        );
        throw new OAuth2AuthenticationException(error);
    }
}

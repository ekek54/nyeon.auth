package com.example.nyeon.auth.authorization.pkceclientauthentication;

import java.util.Map;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Transient;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

@Transient // 요청을 넘어서 인증 객체가 유지되지 않을 때 사용
public class PKCEClientAuthenticationToken extends OAuth2ClientAuthenticationToken {
    public PKCEClientAuthenticationToken(String clientId,
                                         ClientAuthenticationMethod clientAuthenticationMethod,
                                         @Nullable Object credentials, @Nullable Map<String, Object> additionalParameters) {
        super(clientId, clientAuthenticationMethod, credentials, additionalParameters);
    }

    public PKCEClientAuthenticationToken(
            RegisteredClient registeredClient,
            ClientAuthenticationMethod clientAuthenticationMethod, Object credentials) {
        super(registeredClient, clientAuthenticationMethod, credentials);
    }
}

package com.example.nyeon.auth.config;

import com.example.nyeon.auth.authorization.OidcUserInfoMapper;
import com.example.nyeon.auth.authorization.tokenintrospection.PKCEClientAuthenticationConverter;
import com.example.nyeon.auth.authorization.tokenintrospection.PKCEClientAuthenticationProvider;
import com.example.nyeon.auth.sociallogin.JWTCookieSecurityContextRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.savedrequest.CookieRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class AuthorizationServerConfig {
    private final JwtEncoder jwtEncoder;

    private final JwtDecoder jwtDecoder;

    private final OidcUserInfoMapper oidcUserInfoMapper;

    private final RegisteredClientRepository registeredClientRepository;

    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        // @formatter:off
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        OAuth2AuthorizationServerConfigurer configurer = http.getConfigurer(OAuth2AuthorizationServerConfigurer.class);

        PKCEClientAuthenticationConverter pkceClientAuthenticationConverter =
                new PKCEClientAuthenticationConverter(
                        authorizationServerSettings().getTokenIntrospectionEndpoint(),
                        authorizationServerSettings().getTokenRevocationEndpoint()
                );
        PKCEClientAuthenticationProvider pkceClientAuthenticationProvider =
                new PKCEClientAuthenticationProvider(registeredClientRepository);

        configurer
                .oidc(oidc -> oidc
                    .userInfoEndpoint(userInfo -> userInfo
                        .userInfoMapper(oidcUserInfoMapper)
                    )
                ).clientAuthentication(clientAuthentication -> clientAuthentication
                    .authenticationConverter(pkceClientAuthenticationConverter)
                    .authenticationProvider(pkceClientAuthenticationProvider)
                );

        http
                .exceptionHandling((exceptions) -> exceptions
                    .defaultAuthenticationEntryPointFor(
                        new LoginUrlAuthenticationEntryPoint("/login"),
                        new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
                    )
                )
                // Accept access tokens for User Info and/or Client Registration
                .oauth2ResourceServer((oauth2) -> oauth2.jwt(Customizer.withDefaults()))
                // defaultSecurityFilterChain과 SecurityContext를 공유하기 위해 따로 설정해 주어야 한다.
                .securityContext((securityContext) -> securityContext
                    .securityContextRepository(securityContextRepository())
                ).requestCache((requestCache) -> requestCache
                    .requestCache(cookieRequestCache())
                ).sessionManagement(session -> session
                    .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                );
        // @formatter:on
        return http.build();
    }

    @Bean
    public RequestCache cookieRequestCache() {
        return new CookieRequestCache();
    }

    @Bean
    public SecurityContextRepository securityContextRepository() {
        return new JWTCookieSecurityContextRepository(
                jwtEncoder,
                jwtDecoder,
                authorizationServerSettings().getAuthorizationEndpoint()
        );
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder().build();
    }
}

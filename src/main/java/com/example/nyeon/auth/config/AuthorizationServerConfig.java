package com.example.nyeon.auth.config;

import com.example.nyeon.auth.authorization.oidcuserinfo.IdTokenCustomizer;
import com.example.nyeon.auth.authorization.oidcuserinfo.OidcUserInfoMapper;
import com.example.nyeon.auth.authorization.pkceclientauthentication.PKCEClientAuthenticationConverter;
import com.example.nyeon.auth.authorization.pkceclientauthentication.PKCEClientAuthenticationProvider;
import com.example.nyeon.auth.authorization.refreshtoken.PublicClientRefreshTokenGenerator;
import com.example.nyeon.auth.authorization.refreshtoken.CustomTokenResponseHandler;
import com.example.nyeon.auth.sociallogin.JWTCookieSecurityContextRepository;
import java.util.Set;
import java.util.UUID;
import javax.sql.DataSource;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.DelegatingOAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.JwtGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2RefreshTokenAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
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

    private final DataSource dataSource;

    private final IdTokenCustomizer idTokenGenerator;

    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        // @formatter:off
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        OAuth2AuthorizationServerConfigurer configurer = http.getConfigurer(OAuth2AuthorizationServerConfigurer.class);
        PKCEClientAuthenticationConverter pkceClientAuthenticationConverter =
                new PKCEClientAuthenticationConverter(
                        authorizationServerSettings().getTokenIntrospectionEndpoint(),
                        authorizationServerSettings().getTokenRevocationEndpoint(),
                        authorizationServerSettings().getTokenEndpoint()
                );
        PKCEClientAuthenticationProvider pkceClientAuthenticationProvider =
                new PKCEClientAuthenticationProvider(registeredClientRepository());

        configurer
                .oidc(oidc -> oidc
                    .userInfoEndpoint(userInfo -> userInfo
                        .userInfoMapper(oidcUserInfoMapper)
                    )
                ).clientAuthentication(clientAuthentication -> clientAuthentication
                    .authenticationConverter(pkceClientAuthenticationConverter)
                    .authenticationProvider(pkceClientAuthenticationProvider)
                ).authorizationService(authorizationService()
                ).tokenEndpoint(token -> token
                    .accessTokenResponseHandler(tokenResponseHandler())
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
    public OAuth2TokenGenerator<?> tokenGenerator() {
        JwtGenerator jwtGenerator = new JwtGenerator(jwtEncoder);
        jwtGenerator.setJwtCustomizer(idTokenGenerator);
        OAuth2TokenGenerator<OAuth2RefreshToken> refreshTokenGenerator = new PublicClientRefreshTokenGenerator();
        return new DelegatingOAuth2TokenGenerator(jwtGenerator, refreshTokenGenerator);
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder().build();
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        return new JdbcRegisteredClientRepository(new JdbcTemplate(dataSource));
    }

    @Bean
    OAuth2AuthorizationService authorizationService() {
        return new JdbcOAuth2AuthorizationService(
                new JdbcTemplate(dataSource), registeredClientRepository());
    }

    @Bean
    AuthenticationSuccessHandler tokenResponseHandler() {
        return new CustomTokenResponseHandler();
    }

    @Bean
    ApplicationRunner clientRunner(RegisteredClientRepository registeredClientRepository) {
        return args -> {
            String clientTd = "postman";
            if (registeredClientRepository.findByClientId(clientTd) == null) {
                TokenSettings refreshRotateSetting = TokenSettings.builder().reuseRefreshTokens(false).build();
                registeredClientRepository.save(RegisteredClient
                        .withId(UUID.randomUUID().toString())
                        .clientId(clientTd)
                        .clientSecret("{noop}secrete")
                        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                        .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                        .redirectUri("https://oauth.pstmn.io/v1/callback")
                        .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                        .clientSettings(ClientSettings.builder()
                                .requireProofKey(true)
                                .requireAuthorizationConsent(false)
                                .build()
                        ).scopes(scopes -> scopes
                                .addAll(Set.of("openid", "profile", "email"))
                        ).tokenSettings(refreshRotateSetting)
                        .build()
                );
            }
        };
    }
}

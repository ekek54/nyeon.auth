package com.example.nyeon.auth.config;

import com.example.nyeon.auth.sociallogin.StatelessOAuth2AuthorizationRequestRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.savedrequest.RequestCache;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SocialLoginConfig {
    private final RequestCache cookieRequestCache;

    private final SecurityContextRepository securityContextRepository;

    @Value("${state.secret}")
    private String stateSecret;

    @Bean
    @Order(2)
    public SecurityFilterChain socailLoginSecurityFilterChain(HttpSecurity http)
            throws Exception {
        //Formatter:off
        http
                .authorizeHttpRequests((authorize) -> authorize
                        .requestMatchers("favicon.ico", "robots.txt", "error").permitAll()
                        .anyRequest().authenticated()
                ).oauth2Login(oauth -> oauth
                        .authorizationEndpoint(authorization -> authorization
                                .authorizationRequestRepository(authorizationRequestRepository())
                        )
                ).sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                ).csrf(AbstractHttpConfigurer::disable)
                .requestCache(requestCache -> requestCache
                        .requestCache(cookieRequestCache)
                ).securityContext(securityContext -> securityContext
                        .securityContextRepository(securityContextRepository)
                );
        return http.build();
    }

    @Bean
    public StatelessOAuth2AuthorizationRequestRepository authorizationRequestRepository() {
        return new StatelessOAuth2AuthorizationRequestRepository(stateSecret.toCharArray());
    }
}

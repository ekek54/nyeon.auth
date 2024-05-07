package com.example.nyeon.auth.config;

import com.example.nyeon.auth.security.CustomAuthenticationSuccessHandler;
import com.example.nyeon.auth.security.JWTCookieSecurityContextRepository;
import com.example.nyeon.auth.security.StatelessOAuth2AuthorizationRequestRepository;
import com.example.nyeon.auth.user.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.savedrequest.CookieRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;

@Configuration
@EnableWebSecurity
public class SocialLoginConfig {
    @Autowired
    private JwtEncoder jwtEncoder;

    @Autowired
    private JwtDecoder jwtDecoder;

    @Bean
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
                        .requestCache(cookieRequestCache())
                ).securityContext(securityContext -> securityContext
                        .securityContextRepository(securityContextRepository())
                );
        return http.build();
    }

    @Bean
    public StatelessOAuth2AuthorizationRequestRepository authorizationRequestRepository() {
        return new StatelessOAuth2AuthorizationRequestRepository();
    }

    @Bean
    public RequestCache cookieRequestCache() {
        return new CookieRequestCache();
    }

    @Bean
    public SecurityContextRepository securityContextRepository() {
        return new JWTCookieSecurityContextRepository(jwtEncoder, jwtDecoder);
    }
}

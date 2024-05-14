package com.example.nyeon.auth.sociallogin;

import com.example.nyeon.auth.util.CookieUtil;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.web.server.Cookie.SameSite;
import org.springframework.http.HttpMethod;
import org.springframework.security.core.context.DeferredSecurityContext;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2UserAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.security.web.context.HttpRequestResponseHolder;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.util.matcher.AndRequestMatcher;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;


@Slf4j
public class JWTCookieSecurityContextRepository implements SecurityContextRepository {
    private static final Duration CONTEXT_COOKIE_EXPIRY = Duration.ofHours(1);
    private static final String CONTEXT_COOKIE_NAME = "ROC"; // Resource Owner Context
    private final JwtEncoder jwtEncoder;
    private final JwtDecoder jwtDecoder;
    private final SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder
            .getContextHolderStrategy();
    private final RequestMatcher authorizationEndpointMatcher;

    public JWTCookieSecurityContextRepository(JwtEncoder jwtEncoder, JwtDecoder jwtDecoder,
                                              String authorizationEndpointUri) {
        this.jwtEncoder = jwtEncoder;
        this.jwtDecoder = jwtDecoder;
        this.authorizationEndpointMatcher =
                new AndRequestMatcher(
                        new AntPathRequestMatcher(authorizationEndpointUri,
                                HttpMethod.GET.name()
                        )
                );
    }

    @Override
    @Deprecated
    public SecurityContext loadContext(HttpRequestResponseHolder requestResponseHolder) {
        HttpServletRequest request = requestResponseHolder.getRequest();
        Optional<String> contextJWT = retrieveContextJWT(request);
        if (!authorizationEndpointMatcher.matches(request) || contextJWT.isEmpty()) {
            return securityContextHolderStrategy.createEmptyContext();
        }
        try {
            Jwt decodeJwt = jwtDecoder.decode(contextJWT.get());
            String userUUID = decodeJwt.getSubject();
            PreAuthenticatedAuthenticationToken authentication = new PreAuthenticatedAuthenticationToken(
                    userUUID, null, List.of(new OAuth2UserAuthority(Map.of("name", userUUID))));
            SecurityContext context = securityContextHolderStrategy.createEmptyContext();
            context.setAuthentication(authentication);
            return context;
        } catch (Exception e) {
            //empty context
            log.error("Failed to decode JWT", e);
            return securityContextHolderStrategy.createEmptyContext();
        }
    }


    @Override
    public DeferredSecurityContext loadDeferredContext(HttpServletRequest request) {
        return SecurityContextRepository.super.loadDeferredContext(request);
    }

    @Override
    public void saveContext(SecurityContext context, HttpServletRequest request, HttpServletResponse response) {
        if (context == null) {
            removeCookie(request, response);
            return;
        }
        if (context.getAuthentication().getPrincipal() instanceof OAuth2User principal) {
            Jwt jwt = buildJwt(principal.getName());
            Cookie cookie = buildJwtCookie(jwt, request);
            response.addCookie(cookie);
        }
    }

    @Override
    public boolean containsContext(HttpServletRequest request) {
        return authorizationEndpointMatcher.matches(request) && retrieveContextJWT(request).isPresent();
    }

    private Jwt buildJwt(String userUUID) {
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .subject(userUUID)
                .expiresAt(Instant.now().plus(CONTEXT_COOKIE_EXPIRY))
                .build();

        return jwtEncoder.encode(JwtEncoderParameters.from(claims));
    }

    private Optional<String> retrieveContextJWT(HttpServletRequest request) {
        return CookieUtil.retrieve(request.getCookies(), CONTEXT_COOKIE_NAME);
    }

    private Cookie buildJwtCookie(Jwt jwt, HttpServletRequest request) {
        return CookieUtil.cookieBuilder(request)
                .name(CONTEXT_COOKIE_NAME)
                .value(jwt.getTokenValue())
                .maxAge(CONTEXT_COOKIE_EXPIRY)
                .httpOnly(true)
                .sameSite(SameSite.LAX)
                .build();
    }

    private void removeCookie(HttpServletRequest request, HttpServletResponse response) {
        Cookie expiredCookie = buildExpiredCookie(request);
        response.addCookie(expiredCookie);
    }

    private Cookie buildExpiredCookie(HttpServletRequest request) {
        return CookieUtil.cookieBuilder(request)
                .name(CONTEXT_COOKIE_NAME)
                .value("")
                .maxAge(Duration.ZERO)
                .httpOnly(true)
                .build();
    }

}

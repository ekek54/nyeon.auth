package com.example.nyeon.auth.sociallogin;

import com.example.nyeon.auth.util.CookieUtil;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import org.springframework.boot.web.server.Cookie.SameSite;
import org.springframework.security.core.context.DeferredSecurityContext;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.context.HttpRequestResponseHolder;
import org.springframework.security.web.context.SecurityContextRepository;


public class JWTCookieSecurityContextRepository implements SecurityContextRepository {
    private static final Duration CONTEXT_COOKIE_EXPIRY = Duration.ofHours(1);
    private static final String CONTEXT_COOKIE_NAME = "ROC"; // Resource Owner Context
    private final JwtEncoder jwtEncoder;
    private final JwtDecoder jwtDecoder;
    private final SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder
            .getContextHolderStrategy();

    public JWTCookieSecurityContextRepository(JwtEncoder jwtEncoder, JwtDecoder jwtDecoder) {
        this.jwtEncoder = jwtEncoder;
        this.jwtDecoder = jwtDecoder;
    }

    @Override
    @Deprecated
    public SecurityContext loadContext(HttpRequestResponseHolder requestResponseHolder) {
        HttpServletRequest request = requestResponseHolder.getRequest();
        Jwt contextJwt = retrieveContextJWT(request);
        SecurityContext context = securityContextHolderStrategy.createEmptyContext();
        if (contextJwt == null) {
            //Empty context
            return context;
        }
        JwtAuthenticationToken authentication = new JwtAuthenticationToken(contextJwt, List.of(UserRole.ROLE_USER));
        authentication.setAuthenticated(true);
        context.setAuthentication(authentication);
        return context;
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

    private Jwt buildJwt(String userUUID) {
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .subject(userUUID)
                .expiresAt(Instant.now().plus(CONTEXT_COOKIE_EXPIRY))
                .build();

        return jwtEncoder.encode(JwtEncoderParameters.from(claims));
    }

    @Override
    public boolean containsContext(HttpServletRequest request) {
        return retrieveContextJWT(request) != null;
    }

    private Jwt retrieveContextJWT(HttpServletRequest request) {
        return CookieUtil.retrieve(request.getCookies(), CONTEXT_COOKIE_NAME)
                .map(jwtDecoder::decode).orElse(null);
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

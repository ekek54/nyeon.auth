package com.example.nyeon.auth.security;

import com.example.nyeon.auth.util.CookieUtil;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import org.springframework.boot.web.server.Cookie.SameSite;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

public class CustomAuthenticationSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {
    private static final String JWT_COOKIE_NAME = "ROT";
    private final RequestCache requestCache;
    private final JwtEncoder jwtEncoder;

    private static final Duration JWT_EXPIRATION = Duration.ofMinutes(1);

    public CustomAuthenticationSuccessHandler(JwtEncoder jwtEncoder, RequestCache requestCache) {
        this.jwtEncoder = jwtEncoder;
        this.requestCache = requestCache;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {
        SavedRequest savedRequest = this.requestCache.getRequest(request, response);

        if (savedRequest == null) {
            super.onAuthenticationSuccess(request, response, authentication);
            return;
        }

        UserPrincipal principal = (UserPrincipal) authentication.getPrincipal();
        String email = principal.getUser().getEmail();
        String loginProvider = principal.getUser().getLoginProvider();

        Jwt jwt = createJwt(email, loginProvider);

        attachJwtCookie(request, response, jwt);
        String targetUrl = savedRequest.getRedirectUrl();
        requestCache.removeRequest(request, response);
        System.out.println("Redirecting to: " + targetUrl);
        this.getRedirectStrategy().sendRedirect(request, response, targetUrl);
    }

    private Jwt createJwt(String email, String loginProvider) {
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .subject(email)
                .claim("loginProvider", loginProvider)
                .expiresAt(Instant.now().plus(JWT_EXPIRATION))
                .build();

        return jwtEncoder.encode(JwtEncoderParameters.from(claims));
    }

    private void attachJwtCookie(HttpServletRequest request, HttpServletResponse response, Jwt jwt) {
        Cookie jwtCookie = CookieUtil.cookieBuilder(request)
                .name(JWT_COOKIE_NAME)
                .value(jwt.getTokenValue())
                .httpOnly(true)
                .maxAge(JWT_EXPIRATION)
                .sameSite(SameSite.STRICT)
                .build();

        response.addCookie(jwtCookie);
    }
}

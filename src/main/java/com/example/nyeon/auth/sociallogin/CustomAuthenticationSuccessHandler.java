package com.example.nyeon.auth.sociallogin;

import com.example.nyeon.auth.util.CookieUtil;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import org.springframework.boot.web.server.Cookie.SameSite;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

@Deprecated
public class CustomAuthenticationSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {
    private static final String JWT_COOKIE_NAME = "ROT"; // Resource Owner Token
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
        OAuth2User principal = (OAuth2User) authentication.getPrincipal();
        String userUUID = principal.getName();

        Jwt jwt = createJwt(userUUID);

        attachJwtCookie(request, response, jwt);
        String targetUrl = savedRequest.getRedirectUrl();
        requestCache.removeRequest(request, response);
        System.out.println("Redirecting to: " + targetUrl);
        this.getRedirectStrategy().sendRedirect(request, response, targetUrl);
    }

    private Jwt createJwt(String userId) {
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .subject(userId)
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

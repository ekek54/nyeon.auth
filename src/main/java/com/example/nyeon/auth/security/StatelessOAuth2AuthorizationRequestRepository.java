package com.example.nyeon.auth.security;

import com.example.nyeon.auth.util.CookieUtil;
import com.example.nyeon.auth.util.EncryptionUtil;
import com.nimbusds.jose.shaded.gson.Gson;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.time.Duration;
import java.util.Base64;
import javax.crypto.SecretKey;
import org.springframework.http.HttpHeaders;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;

/**
 * 참고 문서: https://www.jessym.com/articles/stateless-oauth2-social-logins-with-spring-boot
 */
public class StatelessOAuth2AuthorizationRequestRepository implements
        AuthorizationRequestRepository<OAuth2AuthorizationRequest> {
    private static final Duration OAUTH_COOKIE_EXPIRY = Duration.ofMinutes(5);
    private static final String OAUTH_COOKIE_NAME = "OAUTH";
    private static final Base64.Encoder B64E = Base64.getEncoder();
    private static final Base64.Decoder B64D = Base64.getDecoder();

    /*
     * Gson is utilized for the serialization and deserialization of OAuth2AuthorizationRequest.
     * This is due to the fact that the default library, Jackson, does not support the deserialization of OAuth2AuthorizationRequest.
     */
    private static final Gson GSON = new Gson();

    private final SecretKey encryptionKey;

    public StatelessOAuth2AuthorizationRequestRepository() {
        this.encryptionKey = EncryptionUtil.generateKey();
    }

    public StatelessOAuth2AuthorizationRequestRepository(char[] encryptionPassword) {
        byte[] salt = {0}; // A static salt is OK for these short lived session cookies
        this.encryptionKey = EncryptionUtil.generateKey(encryptionPassword, salt);
    }

    @Override
    public OAuth2AuthorizationRequest loadAuthorizationRequest(HttpServletRequest request) {
        return this.retrieveCookie(request);
    }

    @Override
    public void saveAuthorizationRequest(OAuth2AuthorizationRequest authorizationRequest, HttpServletRequest request,
                                         HttpServletResponse response) {
        if (authorizationRequest == null) {
            this.removeCookie(request, response);
            return;
        }
        this.attachCookie(request, response, authorizationRequest);
    }

    @Override
    public OAuth2AuthorizationRequest removeAuthorizationRequest(HttpServletRequest request,
                                                                 HttpServletResponse response) {
        this.removeCookie(request, response);
        return this.loadAuthorizationRequest(request);
    }

    private OAuth2AuthorizationRequest retrieveCookie(HttpServletRequest request) {
        return CookieUtil.retrieve(request.getCookies(), OAUTH_COOKIE_NAME).map(this::decrypt).orElse(null);
    }

    private void attachCookie(HttpServletRequest request, HttpServletResponse response,
                              OAuth2AuthorizationRequest value) {
        String cookie = CookieUtil.cookieBuilder(request).name(OAUTH_COOKIE_NAME).value(this.encrypt(value))
                .maxAge(OAUTH_COOKIE_EXPIRY).httpOnly(true).build();
        response.setHeader(HttpHeaders.SET_COOKIE, cookie);
    }

    private void removeCookie(HttpServletRequest request, HttpServletResponse response) {
        String expiredCookie = CookieUtil.generateExpiredCookie(OAUTH_COOKIE_NAME, request);
        response.setHeader(HttpHeaders.SET_COOKIE, expiredCookie);
    }

    private String encrypt(OAuth2AuthorizationRequest authorizationRequest) {
        try {
            byte[] bytes = GSON.toJson(authorizationRequest).getBytes();
            byte[] encryptedBytes = EncryptionUtil.encrypt(this.encryptionKey, bytes);
            return B64E.encodeToString(encryptedBytes);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private OAuth2AuthorizationRequest decrypt(String encrypted) {
        try {
            System.out.println("encrypted: " + encrypted);
            byte[] encryptedBytes = B64D.decode(encrypted);
            byte[] bytes = EncryptionUtil.decrypt(this.encryptionKey, encryptedBytes);
            return GSON.fromJson(new String(bytes), OAuth2AuthorizationRequest.class);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}

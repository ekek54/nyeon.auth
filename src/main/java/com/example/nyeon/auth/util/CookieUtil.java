package com.example.nyeon.auth.util;

import static java.util.Objects.isNull;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import java.time.Duration;
import java.util.Optional;
import lombok.NonNull;
import org.apache.tomcat.util.http.Rfc6265CookieProcessor;
import org.springframework.boot.web.server.Cookie.SameSite;

public class CookieUtil {

    public static Optional<String> retrieve(Cookie[] cookies, @NonNull String name) {
        if (isNull(cookies)) {
            return Optional.empty();
        }
        for (Cookie cookie : cookies) {
            if (cookie.getName().equalsIgnoreCase(name)) {
                return Optional.ofNullable(cookie.getValue());
            }
        }
        return Optional.empty();
    }

    public static CookieBuilder cookieBuilder(HttpServletRequest request) {
        return CookieBuilder.builder(request);
    }

    public static String generateExpiredCookie(@NonNull String name, @NonNull HttpServletRequest request) {
        return CookieBuilder.builder(request).name(name).value("-").maxAge(Duration.ZERO).build();
    }

    public static class CookieBuilder {
        private static final Rfc6265CookieProcessor processor = new Rfc6265CookieProcessor();
        private String name;
        private String value;
        private Duration maxAge;
        private boolean httpOnly;
        private boolean secure;
        private SameSite sameSite;

        private final HttpServletRequest request;

        private CookieBuilder(HttpServletRequest request) {
            this.request = request;
        }

        public static CookieBuilder builder(HttpServletRequest request) {
            return new CookieBuilder(request);
        }

        public CookieBuilder name(String name) {
            this.name = name;
            return this;
        }

        public CookieBuilder value(String value) {
            this.value = value;
            return this;
        }

        public CookieBuilder maxAge(Duration maxAge) {
            this.maxAge = maxAge;
            return this;
        }

        public CookieBuilder httpOnly(boolean httpOnly) {
            this.httpOnly = httpOnly;
            return this;
        }

        public CookieBuilder secure(boolean secure) {
            this.secure = secure;
            return this;
        }

        public CookieBuilder sameSite(SameSite sameSite) {
            this.sameSite = sameSite;
            return this;
        }

        public String build() {
            Cookie cookie = new Cookie(name, value);
            cookie.setHttpOnly(httpOnly);
            cookie.setSecure(secure);
            cookie.setMaxAge((int) maxAge.toSeconds());
            cookie.setPath("/");
            if (sameSite != null) {
                cookie.setAttribute("SameSite", sameSite.toString());
            }
            return processor.generateHeader(cookie,request);
        }
    }
}

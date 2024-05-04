package com.example.nyeon.auth.security;

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.user.OAuth2User;
import com.example.nyeon.auth.user.User;

public class UserPrincipal implements OAuth2User {

    @Getter
    private final User user;
    private final List<GrantedAuthority> authorities;
    private final Map<String, Object> attributes;

    public UserPrincipal(User user, List<GrantedAuthority> authorities, Map<String, Object> attributes) {
        this.user = user;
        this.authorities = authorities;
        this.attributes = attributes;
    }

    @Override
    public Map<String, Object> getAttributes() {
        return Collections.unmodifiableMap(attributes);
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return Collections.unmodifiableList(authorities);
    }

    @Override
    public String getName() {
        return user.getEmail();
    }
}

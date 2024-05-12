package com.example.nyeon.auth.sociallogin.principal;

import com.example.nyeon.auth.sociallogin.UserRole;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;

@Getter
public class OAuth2UserPrincipal extends DefaultOAuth2User {

    private final UUID userId;

    private OAuth2UserPrincipal(UUID userId, List<GrantedAuthority> authorities, Map<String, Object> attributes) {
        super(authorities, attributes, "name");
        this.userId = userId;
    }

    public static OAuth2UserPrincipal create(UUID userId, Map<String, Object> attributes) {
        return new OAuth2UserPrincipal(userId, List.of(UserRole.ROLE_USER::name), attributes);
    }

    @Override
    public String getName() {
        return userId.toString();
    }

    @Override
    public String toString() {
        return "UserPrincipal{" +
                "user=" + userId +
                '}';
    }
}

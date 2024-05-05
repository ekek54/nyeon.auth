package com.example.nyeon.auth.security.principal;

import com.example.nyeon.auth.security.UserRole;
import java.util.List;
import java.util.Map;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import com.example.nyeon.auth.user.User;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;

@Getter
public class OAuth2UserPrincipal extends DefaultOAuth2User {

    private final User user;

    private OAuth2UserPrincipal(User user, List<GrantedAuthority> authorities, Map<String, Object> attributes) {
        super(authorities, attributes, "sub");
        this.user = user;
    }

    public static OAuth2UserPrincipal create(User user, Map<String, Object> attributes) {
        return new OAuth2UserPrincipal(user, List.of(UserRole.ROLE_USER::name), attributes);
    }

    @Override
    public String getName() {
        return user.getId().toString();
    }

    @Override
    public String toString() {
        return "UserPrincipal{" +
                "user=" + user +
                '}';
    }
}

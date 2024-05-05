package com.example.nyeon.auth.security.principal;

import com.example.nyeon.auth.security.UserRole;
import com.example.nyeon.auth.user.User;
import java.util.List;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;

@Getter
public class OidcUserPrincipal extends DefaultOidcUser {

    private final User user;

    private OidcUserPrincipal(User user, List<GrantedAuthority> authorities, OidcIdToken idToken,
                              OidcUserInfo userInfo) {
        super(authorities, idToken, userInfo);
        this.user = user;
    }

    public static OidcUserPrincipal create(User user, OidcIdToken idToken, OidcUserInfo userInfo) {
        return new OidcUserPrincipal(user, List.of(UserRole.ROLE_USER::name), idToken, userInfo);
    }


    @Override
    public String getName() {
        return user.getId().toString();
    }
}

package com.example.nyeon.auth.sociallogin.principal;

import com.example.nyeon.auth.sociallogin.UserRole;
import java.util.List;
import java.util.UUID;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;

@Getter
public class OidcUserPrincipal extends DefaultOidcUser {

    private final UUID userId;

    private OidcUserPrincipal(UUID userId, List<GrantedAuthority> authorities, OidcIdToken idToken,
                              OidcUserInfo userInfo) {
        super(authorities, idToken, userInfo);
        this.userId = userId;
    }

    public static OidcUserPrincipal create(UUID userId, OidcIdToken idToken, OidcUserInfo userInfo) {
        return new OidcUserPrincipal(userId, List.of(UserRole.ROLE_USER::name), idToken, userInfo);
    }


    @Override
    public String getName() {
        return userId.toString();
    }
}

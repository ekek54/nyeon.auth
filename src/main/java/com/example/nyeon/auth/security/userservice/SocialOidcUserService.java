package com.example.nyeon.auth.security.userservice;

import com.example.nyeon.auth.exception.BadRequestException;
import com.example.nyeon.auth.security.principal.OidcUserPrincipal;
import com.example.nyeon.auth.user.User;
import com.example.nyeon.auth.user.UserRepository;
import java.util.Map;
import java.util.Optional;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Component;

@Component
public class SocialOidcUserService extends OidcUserService {
    private final UserRepository userRepository;

    public SocialOidcUserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public OidcUser loadUser(OidcUserRequest userRequest) throws OAuth2AuthenticationException {
        String loginProvider = userRequest.getClientRegistration().getClientName();
        OidcUser oidcUser = super.loadUser(userRequest);
        validateEmail(oidcUser);
        User user = createIfNewElseGetUser(oidcUser, loginProvider);
        return OidcUserPrincipal.create(user, oidcUser.getIdToken(), oidcUser.getUserInfo());
    }

    private User createIfNewElseGetUser(OidcUser oidcUser, String loginProvider) {
        Map<String, Object> attributes = oidcUser.getAttributes();
        String email = oidcUser.getEmail();
        Optional<User> userByEmail = userRepository.findByEmailAndLoginProvider(email, loginProvider);
        if (userByEmail.isEmpty()) {
            // Create new user
            String name = oidcUser.getFullName();
            User user = User.createUser(name, email, loginProvider);
            return userRepository.save(user);
        } else {
            // Get existing user
            return userByEmail.get();
        }
    }

    private void validateEmail(OidcUser oidcUser) {
        if (oidcUser.getEmail().isEmpty()) {
            throw new BadRequestException("Email not found from social login");
        }
    }

}

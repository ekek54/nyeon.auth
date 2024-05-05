package com.example.nyeon.auth.security.userservice;

import com.example.nyeon.auth.exception.BadRequestException;
import com.example.nyeon.auth.security.principal.OAuth2UserPrincipal;
import com.example.nyeon.auth.user.UserRepository;
import java.util.Map;
import java.util.Optional;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import com.example.nyeon.auth.user.User;
import org.springframework.stereotype.Component;

@Component
public class SocialOAuth2UserService extends DefaultOAuth2UserService {
    private final UserRepository userRepository;

    public SocialOAuth2UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        String loginProvider = userRequest.getClientRegistration().getClientName();
        OAuth2User oAuth2User = super.loadUser(userRequest);
        validateEmail(oAuth2User);
        User user = createIfNewElseGetUser(oAuth2User, loginProvider);
        return OAuth2UserPrincipal.create(user, oAuth2User.getAttributes());
    }

    private User createIfNewElseGetUser(OAuth2User oAuth2User, String loginProvider) {
        Map<String, Object> attributes = oAuth2User.getAttributes();
        String email = (String) attributes.get("email");
        Optional<User> userByEmail = userRepository.findByEmailAndLoginProvider(email,loginProvider);
        if (userByEmail.isEmpty()) {
            // Create new user
            String name = (String) attributes.get("name");
            User user = User.createUser(name, email, loginProvider);
            return userRepository.save(user);
        } else {
            // Get existing user
            return userByEmail.get();
        }
    }

    private void validateEmail(OAuth2User oAuth2User) {
        if (!oAuth2User.getAttributes().containsKey("email")) {
            throw new BadRequestException("Email not found from social login");
        }
    }
}

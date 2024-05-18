package com.example.nyeon.auth.authorization.oidcuserinfo;

import com.example.nyeon.auth.exception.UserNotFoundException;
import com.example.nyeon.auth.user.User;
import com.example.nyeon.auth.user.UserRepository;
import java.util.UUID;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.stereotype.Service;

@Service
public class OidcUserInfoService {
    private final UserRepository userRepository;

    public OidcUserInfoService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    public OidcUserInfo loadUser(String userUUID) {
        User user = userRepository.findById(UUID.fromString(userUUID)).orElseThrow(UserNotFoundException::new);
        return OidcUserInfo.builder()
                .subject(user.getId().toString())
                .name(user.getName())
                .email(user.getEmail())
                .claim("provider", user.getLoginProvider())
                .build();
    }
}

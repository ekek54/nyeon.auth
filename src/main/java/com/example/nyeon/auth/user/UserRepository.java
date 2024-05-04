package com.example.nyeon.auth.user;

import jakarta.validation.constraints.NotNull;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User, Long>{
    Optional<User> findByEmailAndLoginProvider(@NotNull String email, @NotNull String loginProvider);
}

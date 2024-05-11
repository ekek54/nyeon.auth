package com.example.nyeon.auth.user;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EntityListeners;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.validation.constraints.NotNull;
import java.time.LocalDateTime;
import java.util.UUID;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

@Getter
@Setter
@Entity
@NoArgsConstructor
@EntityListeners(AuditingEntityListener.class)
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "user_id")
    private UUID id;

    @Column(name = "user_name")
    @NotNull
    private String name;

    @Column(name = "user_email")
    @NotNull
    private String email;

    @Column(name = "login_provider")
    @NotNull
    private String loginProvider;

    @CreatedDate
    @Column(name = "created_at", updatable = false)
    private LocalDateTime createdAt;

    private User(String name, String email, String loginProvider) {
        this.name = name;
        this.email = email;
        this.loginProvider = loginProvider;
    }

    public static User createUser(String name, String email, String loginProvider) {
        return new User(name, email, loginProvider);
    }

    @Override
    public String toString() {
        return "User{" +
                "id=" + id +
                ", name='" + name + '\'' +
                ", email='" + email + '\'' +
                ", loginProvider='" + loginProvider + '\'' +
                ", createdAt=" + createdAt +
                '}';
    }
}

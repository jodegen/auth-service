package de.jodegen.auth.model;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

@Entity
@Getter
@Setter
@NoArgsConstructor
public class UserAccount {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "email", unique = true)
    private String email;

    @Column(name = "password")
    private String password;

    @Column(name = "created_at")
    private LocalDateTime createdAt;

    @Column(name = "last_login")
    private LocalDateTime lastLogin;

    @Column(name = "multi_factor_enabled")
    private boolean multiFactorEnabled = false;

    @Column(name = "enabled")
    private boolean enabled = true;

    public UserAccount(@NonNull String email, @NonNull String password) {
        this.email = email;
        this.password = password;
        this.createdAt = LocalDateTime.now();
    }
}
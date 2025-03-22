package com.cuentaok.model;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import java.util.Collection;
import java.util.Collections;
import java.util.Set;

@Entity
@Table(name = "users")
@Getter
@Setter
@NoArgsConstructor
public class User implements UserDetails {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false)
    private String email;

    @Column(nullable = false)
    private String password;

    @Column(nullable = false)
    private boolean verified;

    public User(String email, String password, boolean verified) {
        this.email = email;
        this.password = password;
        this.verified = verified;
    }

    // Métodos de UserDetails

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return Collections.emptyList();
    }

    @Override
    public String getUsername() {
        return email;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true; // True (no se necesita) False (se necesita)
    }

    @Override
    public boolean isAccountNonLocked() {
        return true; // True (no se necesita) False (se necesita)
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true; // True (no se necesita) False (se necesita)
    }

    @Override
    public boolean isEnabled() {
        return verified; // Solo permite acceso si el usuario está verificado
    }

    // Roles
    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(
            name = "user_roles",
            joinColumns = @JoinColumn(name = "user_id"),
            inverseJoinColumns = @JoinColumn(name = "role_id")
    )
    private Set<Role> roles; // Esto será opcional
}

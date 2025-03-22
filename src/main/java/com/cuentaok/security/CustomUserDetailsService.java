package com.cuentaok.security;

import com.cuentaok.model.User;
import com.cuentaok.repository.UserRepository;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import java.util.Collections;
import java.util.stream.Collectors;
import java.util.Set;

@Service
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Value("${app.security.roles-enabled}")
    private boolean rolesEnabled;

    public CustomUserDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        // Si los roles están habilitados, pero el usuario no tiene roles asignados, lanzar excepción
        if (rolesEnabled && (user.getRoles() == null || user.getRoles().isEmpty())) {
            throw new UsernameNotFoundException("User has no assigned roles");
        }

        // Si los roles están habilitados y el usuario tiene roles, los convertimos a GrantedAuthority
        Set<GrantedAuthority> authorities = rolesEnabled && user.getRoles() != null
                ? user.getRoles().stream()
                    .map(role -> new SimpleGrantedAuthority(role.getName().name()))
                    .collect(Collectors.toSet())
                : Collections.emptySet(); // Si los roles están deshabilitados, devuelve un set vacío

        return new org.springframework.security.core.userdetails.User(
                user.getEmail(),
                user.getPassword(),
                authorities
        );
    }
}

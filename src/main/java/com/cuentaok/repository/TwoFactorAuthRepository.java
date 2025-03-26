package com.cuentaok.repository;


import com.cuentaok.model.TwoFactorAuth;
import com.cuentaok.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface TwoFactorAuthRepository extends JpaRepository<TwoFactorAuth, Long> {
    Optional<TwoFactorAuth> findByUser(User user);
    void deleteByUser(User user);
}


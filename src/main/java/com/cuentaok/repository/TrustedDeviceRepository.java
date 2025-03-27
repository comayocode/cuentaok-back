package com.cuentaok.repository;

import com.cuentaok.model.TrustedDevice;
import com.cuentaok.model.User;
import jakarta.transaction.Transactional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.Optional;

@Repository
public interface TrustedDeviceRepository extends JpaRepository<TrustedDevice, Long> {
    Optional<TrustedDevice> findByUserAndDeviceId(User user, String deviceId);

    @Transactional
    @Modifying
    @Query("DELETE FROM TrustedDevice td WHERE td.expiresAt < CURRENT_TIMESTAMP")
    void deleteExpiredDevices();
    // Verificar si hay un dispositivo confiable para x usuario con x deviceId y con fecha aún válida
    boolean existsByUserAndDeviceIdAndExpiresAtAfter(User user, String deviceId, LocalDateTime currentTime);

}


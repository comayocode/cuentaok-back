package com.cuentaok.service;


import com.cuentaok.model.TrustedDevice;
import com.cuentaok.model.User;
import com.cuentaok.repository.UserRepository;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import  com.cuentaok.repository.TrustedDeviceRepository;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import lombok.extern.slf4j.Slf4j;


@Slf4j
@Service
public class TrustedDeviceService {

    private final TrustedDeviceRepository trustedDeviceRepository;
    private final UserRepository userRepository;

    public TrustedDeviceService(TrustedDeviceRepository trustedDeviceRepository, UserRepository userRepository) {
        this.trustedDeviceRepository = trustedDeviceRepository;
        this.userRepository = userRepository;
    }

    public void rememberDevice(User user, String deviceId, String userAgent, String ip) {
        TrustedDevice trustedDevice = new TrustedDevice();
        trustedDevice.setUser(user);
        trustedDevice.setDeviceId(deviceId);
        trustedDevice.setUserAgent(userAgent);
        trustedDevice.setIp(ip);

        trustedDeviceRepository.save(trustedDevice);
    }


    public boolean isDeviceTrusted(User user, String deviceId) {
        return trustedDeviceRepository.existsByUserAndDeviceIdAndExpiresAtAfter(user, deviceId, LocalDateTime.now());
    }

    @Scheduled(cron = "0 0 0 * * ?") // Ejecuta todos los días a medianoche
    public void removeExpiredDevices() {
        trustedDeviceRepository.deleteExpiredDevices();
    }

    public List<TrustedDevice> getTrustedDevices(User user) {
        return trustedDeviceRepository.findByUser(user);
    }

    public boolean removeDevice(String userEmail, String deviceId) {
        Optional<TrustedDevice> device = trustedDeviceRepository.findByDeviceId(deviceId);

        if (device.isPresent()) {
            TrustedDevice trustedDevice = device.get();

            // Verificar si el dispositivo pertenece al usuario
            if (trustedDevice.getUser().getEmail().equals(userEmail)) {
                trustedDeviceRepository.delete(trustedDevice);
                return true;
            }
        }
        return false; // No se encontró el dispositivo o no pertenece al usuario
    }
}

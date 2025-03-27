package com.cuentaok.service;


import com.cuentaok.model.TrustedDevice;
import com.cuentaok.model.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import  com.cuentaok.repository.TrustedDeviceRepository;
import java.time.LocalDateTime;
import java.util.Optional;

@Service
public class TrustedDeviceService {

    private final TrustedDeviceRepository trustedDeviceRepository;

    public TrustedDeviceService(TrustedDeviceRepository trustedDeviceRepository) {
        this.trustedDeviceRepository = trustedDeviceRepository;
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
}

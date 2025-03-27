package com.cuentaok.dto;

import com.cuentaok.model.TrustedDevice;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;

@Getter
@Setter
@AllArgsConstructor
public class TrustedDeviceResponse {
    private String deviceId;
    private String ip;
    private String userAgent;
    private LocalDateTime createdAt;
    private LocalDateTime expiresAt;

    public static TrustedDeviceResponse fromEntity(TrustedDevice device) {
        return new TrustedDeviceResponse(
                device.getDeviceId(),
                device.getIp(),
                device.getUserAgent(),
                device.getCreatedAt(),
                device.getExpiresAt()
        );
    }
}


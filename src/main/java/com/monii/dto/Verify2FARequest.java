package com.monii.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class Verify2FARequest {
    @NotBlank(message = "El email es obligatorio")
    private String email;

    @NotBlank(message = "El código 2FA es obligatorio")
    private String code;
    private boolean rememberDevice;
}

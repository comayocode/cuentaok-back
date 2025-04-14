package com.monii.Exception;

import lombok.Getter;
import org.springframework.http.HttpStatus;

import java.time.LocalDateTime;
import java.util.Map;

@Getter
public class AccountNotVerifiedException extends BusinessException {
    public AccountNotVerifiedException(String message, String email, LocalDateTime expirationTime) {
        super(
                message,
                HttpStatus.FORBIDDEN.value(),
                Map.of(
                        "email", email,
                        "expiresAt", expirationTime.toString()
                )  // Esto irá en el campo "data" de ApiResponse
        );
    }
}

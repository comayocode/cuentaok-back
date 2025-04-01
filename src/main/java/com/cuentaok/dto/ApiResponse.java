package com.cuentaok.dto;
import lombok.Data;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import java.time.LocalDateTime;

@Data
public class ApiResponse<T> {
    private int status;
    private String message;
    private LocalDateTime timestamp;
    private T data;

    // Constructor principal
    private ApiResponse(int status, String message, T data) {
        this.status = status;
        this.message = message;
        this.data = data;
        this.timestamp = LocalDateTime.now();
    }

    // Métodos estáticos para éxito (con retorno de data)
    public static <T> ResponseEntity<ApiResponse<T>> ok(String message, T data) {
        return ResponseEntity.ok(new ApiResponse<>(HttpStatus.OK.value(), message, data));
    }

    // Métodos para éxito (sin retorno de data)
    public static ResponseEntity<ApiResponse<Void>> ok(String message) {
        return ok(message, null);
    }

    // Métodos para errores (opcional)
    public static <T> ApiResponse<T> error(int status, String message, T data) {
        return new ApiResponse<>(status, message, data);
    }
}

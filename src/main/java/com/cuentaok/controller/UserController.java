package com.cuentaok.controller;
import com.cuentaok.dto.UserRequest;

import com.cuentaok.model.User;
import com.cuentaok.service.JwtService;
import com.cuentaok.service.UserService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.security.Principal;

import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class UserController {

    private final UserService userService;
    private final JwtService jwtService;

    public UserController(UserService userService, JwtService jwtService) {
        this.userService = userService;
        this.jwtService = jwtService;
    }

    @PostMapping("/register")
    public ResponseEntity<String> registerUser(@RequestBody UserRequest request) {
        try {
            User user = userService.registerUser(request.getEmail(), request.getPassword());
            return ResponseEntity.ok("Usuario registrado con éxito. Verifique su correo electrónico.");
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    @GetMapping("/verify")
    public ResponseEntity<String> verifyUser(@RequestParam String token) {
        try {
            userService.verifyUser(token);
            return ResponseEntity.ok("Cuenta verificada con éxito.");
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    @PostMapping("/resend-verification")
    public ResponseEntity<String> resendVerification(@RequestBody UserRequest request) {
        try {
            userService.resendVerificationEmail(request.getEmail());
            return ResponseEntity.ok("Se ha enviado un nuevo correo de verificación.");
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    @PostMapping("/login")
    public ResponseEntity<Map<String, String>> login(@RequestBody UserRequest request) {
        return ResponseEntity.ok(userService.loginWith2FA(request.getEmail(), request.getPassword()));
    }

    @PostMapping("/refresh")
    public ResponseEntity<Map<String, String>> refreshAccessToken(@RequestBody Map<String, String> request) {
        String refreshToken = request.get("refreshToken");
        if (refreshToken == null || !jwtService.isTokenValid(refreshToken)) {
            return ResponseEntity.status(401).body(Map.of("error", "Invalid or expired refresh token"));
        }

        String email = jwtService.extractEmail(refreshToken);
        String newAccessToken = jwtService.generateToken(email);

        return ResponseEntity.ok(Map.of("accessToken", newAccessToken));
    }

    @PostMapping("/forgot-password")
    public ResponseEntity<String> forgotPassword(@RequestBody Map<String, String> request) {
        String email = request.get("email");
        userService.requestPasswordReset(email);
        return ResponseEntity.ok("Se ha enviado un enlace de recuperación a tu correo.");
    }

    @PostMapping("/reset-password")
    public ResponseEntity<String> resetPassword(@RequestBody Map<String, String> request) {
        String token = request.get("token");
        String newPassword = request.get("newPassword");
        userService.resetPassword(token, newPassword);
        return ResponseEntity.ok("Tu contraseña ha sido actualizada correctamente.");
    }

    @PutMapping("/user/2fa")
    public ResponseEntity<String> toggleTwoFactorAuthentication(
            @RequestBody Map<String, Object> request,
            Principal principal) {

        boolean enable = (boolean) request.get("enable");
        String password = (String) request.get("password"); // Puede ser null si no se envía

        userService.toggleTwoFactorAuthentication(principal.getName(), enable, password);
        return ResponseEntity.ok(enable ? "2FA activado" : "2FA desactivado");
    }



    @PostMapping("/verify-2fa")
    public ResponseEntity<Map<String, String>> verify2FA(@RequestBody Map<String, String> request) {
        String email = request.get("email");
        String code = request.get("code");

        if (email == null || code == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Email y código son requeridos.");
        }

        Map<String, String> tokens = userService.verify2FA(email, code);
        return ResponseEntity.ok(tokens);
    }


}

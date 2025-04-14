package com.monii.controller;
import com.monii.Exception.BusinessException;
import com.monii.Exception.ResourceNotFoundException;
import com.monii.dto.*;

import com.monii.model.User;
import com.monii.model.VerificationToken;
import com.monii.repository.UserRepository;
import com.monii.service.JwtService;
import com.monii.service.TrustedDeviceService;
import com.monii.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.apache.commons.codec.digest.DigestUtils;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;

import java.time.LocalDateTime;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/auth")
public class UserController {

    private final UserService userService;
    private final JwtService jwtService;
    private final TrustedDeviceService trustedDeviceService;
    private UserRepository userRepository;

    public UserController(UserService userService, JwtService jwtService, TrustedDeviceService trustedDeviceService) {
        this.userService = userService;
        this.jwtService = jwtService;
        this.trustedDeviceService = trustedDeviceService;
    }

    @PostMapping("/register")
    public ResponseEntity<ApiResponse<Void>> registerUser(@Valid @RequestBody UserRequest request) {
        try {
            User user = userService.registerUser(request.getFirstName(), request.getLastName(), request.getEmail(), request.getPassword());
            return ResponseEntity.ok(ApiResponse.ok("Usuario registrado con éxito. Verifique su correo electrónico para activar la cuenta."));
        } catch (ResourceNotFoundException ex) {
            throw ex;
        }
    }

    @PostMapping("/verify")
    public ResponseEntity<ApiResponse<Void>> verifyUser(@RequestBody VerifyAccount request) {
        try {
            userService.verifyUser(request.getToken());
            return ResponseEntity.ok(ApiResponse.ok("Cuenta verificada exitosamente"));
        } catch (BusinessException ex) {
            System.out.println("ERROR DE VERIFICACION" + ex);
            if (ex.getMessage().contains("Token inválido")) {
                throw new BusinessException("Token inválido o expirado", HttpStatus.BAD_REQUEST.value());
            }
            throw ex;
        }
    }

    @PostMapping("/resend-verification")
    public ResponseEntity<ApiResponse<Map<String, LocalDateTime>>> resendVerification(@RequestBody UserRequest request) {
        VerificationToken token = userService.resendVerificationEmail(request.getEmail());
        Map<String, LocalDateTime> responseData = Map.of("expiresAt", token.getExpiryDate());
        return ResponseEntity.ok(ApiResponse.ok("Se ha enviado un nuevo correo de verificación.", responseData));
    }

    @PostMapping("/login")
    public ResponseEntity<Map<String, String>> login(@RequestBody UserRequest request, HttpServletRequest httpRequest) {
        String deviceId = extractDeviceId(httpRequest); // Extraer deviceId desde la request
        return ResponseEntity.ok(userService.loginWith2FA(request.getEmail(), request.getPassword(), deviceId));
    }

    private String extractDeviceId(HttpServletRequest request) {
        String userAgent = request.getHeader("User-Agent"); // Obtener User-Agent
        String ip = request.getRemoteAddr(); // Obtener IP del usuario
        return DigestUtils.sha256Hex(userAgent + ip); // Generar un hash único como deviceId
    }

    @PostMapping("/refresh")
    public ResponseEntity<Map<String, String>> refreshAccessToken(@RequestBody Map<String, String> request) {
        String refreshToken = request.get("refreshToken");
        if (refreshToken == null || !jwtService.isTokenValid(refreshToken)) {
            return ResponseEntity.status(401).body(Map.of("error", "Invalid or expired refresh token"));
        }

        String email = jwtService.extractEmail(refreshToken);

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
        String newAccessToken = jwtService.generateToken(user);

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
    public ResponseEntity<Map<String, String>> verify2FA(@RequestBody Verify2FARequest request, HttpServletRequest httpRequest) {
        Map<String, String> tokens = userService.verify2FA(request.getEmail(), request.getCode(), request.isRememberDevice(), httpRequest);
        return ResponseEntity.ok(tokens);
    }

    @GetMapping("/trusted-devices")
    public ResponseEntity<List<TrustedDeviceResponse>> getTrustedDevices() {
        User user = userService.getAuthenticatedUser();
        List<TrustedDeviceResponse> devices = trustedDeviceService.getTrustedDevices(user)
                .stream()
                .map(TrustedDeviceResponse::fromEntity)
                .collect(Collectors.toList());

        return ResponseEntity.ok(devices);
    }

    @DeleteMapping("/trusted-devices/{deviceId}")
    public ResponseEntity<?> removeTrustedDevice(
            @PathVariable String deviceId,
            @AuthenticationPrincipal UserDetails userDetails) {

        boolean removed = trustedDeviceService.removeDevice(userDetails.getUsername(), deviceId);

        if (removed) {
            return ResponseEntity.ok(Collections.singletonMap("message", "Device removed successfully."));
        } else {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(Collections.singletonMap("error", "Device not found or unauthorized."));
        }
    }


}

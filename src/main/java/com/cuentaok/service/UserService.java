package com.cuentaok.service;

import com.cuentaok.Exception.AccountNotVerifiedException;
import com.cuentaok.Exception.BusinessException;
import com.cuentaok.Exception.ResourceNotFoundException;
import com.cuentaok.dto.ApiResponse;
import com.cuentaok.model.PasswordResetToken;
import com.cuentaok.model.TrustedDevice;
import com.cuentaok.repository.PasswordResetTokenRepository;
import com.cuentaok.repository.TrustedDeviceRepository;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.apache.commons.codec.digest.DigestUtils;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import com.cuentaok.model.User;
import com.cuentaok.repository.UserRepository;

import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;

import com.cuentaok.model.VerificationToken;
import com.cuentaok.repository.VerificationTokenRepository;
import org.springframework.mail.javamail.JavaMailSender;

import org.springframework.web.server.ResponseStatusException;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

import org.springframework.transaction.annotation.Transactional;

@Service
public class UserService {

    private final UserRepository userRepository;
    private final VerificationTokenRepository tokenRepository;
    private final JavaMailSender mailSender;
    private final PasswordResetTokenRepository passwordResetTokenRepository;
    private final JwtService jwtService;
    private final PasswordEncoder passwordEncoder;
    private final TwoFactorAuthService twoFactorAuthService;

    private final TrustedDeviceService trustedDeviceService;
    private final TrustedDeviceRepository trustedDeviceRepository;
    private final EmailService emailService;

    private static final int MAX_RESET_ATTEMPTS = 3;
    private static final Duration LOCK_DURATION = Duration.ofMinutes(1); // Bloqueo de 1 hora
    private static final int MAX_LOGIN_ATTEMPTS = 5; // Intentos fallidos antes del bloqueo
    private static final int LOCK_LOGIN_DURATION = 1; // Minutos bloqueado

    @Value("${frontend.url}")
    private String frontendUrl;

    public UserService(UserRepository userRepository, VerificationTokenRepository tokenRepository, JavaMailSender mailSender, JwtService jwtService, PasswordEncoder passwordEncoder, PasswordResetTokenRepository passwordResetTokenRepository, TwoFactorAuthService twoFactorAuthService, TrustedDeviceService trustedDeviceService, TrustedDeviceRepository trustedDeviceRepository, EmailService emailService) {
        this.userRepository = userRepository;
        this.tokenRepository = tokenRepository;
        this.mailSender = mailSender;
        this.jwtService = jwtService;
        this.passwordEncoder = passwordEncoder;
        this.passwordResetTokenRepository = passwordResetTokenRepository;
        this.twoFactorAuthService = twoFactorAuthService;
        this.trustedDeviceService = trustedDeviceService;
        this.trustedDeviceRepository = trustedDeviceRepository;
        this.emailService = emailService;
    }

    private User searchUser (String email) {
        return userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("Usuario no encontrado"));
    }

    public User registerUser(String firsName, String lastName, String email, String password) {
        if (userRepository.existsByEmail(email)) {
            throw new RuntimeException("El correo ya está registrado.");
        }

        User user = new User(firsName, lastName, email, passwordEncoder.encode(password), false);
        userRepository.save(user);

        // Generar y guardar el token
        String token = UUID.randomUUID().toString();
        VerificationToken verificationToken = new VerificationToken(token, user, LocalDateTime.now().plusHours(24));
        tokenRepository.save(verificationToken);

        // Enviar el email con el enlace de verificación
        sendVerificationEmail(user.getEmail(), token);

        return user;
    }

    private void sendVerificationEmail(String email, String token) {
        User user = searchUser(email);
        String url = frontendUrl + "/verify-account-pending?token=" + token;

        emailService.sendDynamicEmail(
                email,
                "Verifica tu cuenta en CuentaOk",
                user.getFirstName(), // nombre
                "Gracias por registrarte. Haz clic en el botón para completar la verificación:",
                "link", // tipo
                url, // contenidoPrincipal (URL)
                "Verificar mi cuenta", // textoBoton
                null // expiracion (no aplica)
        );
    }

    public void verifyUser(String token) {
        VerificationToken verificationToken = tokenRepository.findByToken(token)
                .orElseThrow(() -> new BusinessException("Token inválido o expirado.", HttpStatus.FORBIDDEN.value()));

        User user = verificationToken.getUser();

        // Respuesta exitosa si ya está verificado el usuario
        if (user.isVerified()) {
            tokenRepository.delete(verificationToken);
            throw new BusinessException("La cuenta fue verificada", HttpStatus.OK.value());
        }

        // Si no está verificado
        user.setVerified(true);  // Marcar al usuario como verificado
        userRepository.save(user);
        tokenRepository.delete(verificationToken);  // Eliminar el token después de la verificación
    }

    public VerificationToken resendVerificationEmail(String email) {
        // Buscar el usuario por email
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new ResourceNotFoundException("Usuario no encontrado"));

        // Verificar si ya está verificado
        if (user.isVerified()) {
            throw new BusinessException("Este usuario ya está verificado.", HttpStatus.BAD_REQUEST.value());
        }

        // Eliminar el token anterior si existe
        tokenRepository.findByUser(user).ifPresent(tokenRepository::delete);

        // Crear un nuevo token
        String newToken = UUID.randomUUID().toString();
        VerificationToken verificationToken = new VerificationToken(newToken, user, LocalDateTime.now().plusHours(24));
        tokenRepository.save(verificationToken);

        // Enviar el correo con el nuevo token
        sendVerificationEmail(user.getEmail(), newToken);

        return verificationToken;
    }

    private String extractDeviceId(HttpServletRequest request) {
        String userAgent = request.getHeader("User-Agent"); // Datos del navegador/dispositivo
        String ipAddress = request.getRemoteAddr(); // IP del usuario

        // Crear un identificador único basado en la IP y el User-Agent
        return DigestUtils.sha256Hex(userAgent + ipAddress);
    }


    public Map<String, String> loginWith2FA(String email, String password, String deviceId) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new ResourceNotFoundException("Usuario no encontrado"));



        // Verificar si la cuenta está bloqueada
        if (user.isAccountLocked()) {
            if (user.getLockUntil().isAfter(LocalDateTime.now())) {
                throw new ResponseStatusException(HttpStatus.FORBIDDEN, "La cuenta está bloqueada. Intenta nuevamente más tarde.");
            } else {
                // Si ya pasó el tiempo, desbloquear
                user.setAccountLocked(false);
                user.setFailedLoginAttempts(0);
            }
        }

        // Verificar credenciales
        if (!passwordEncoder.matches(password, user.getPassword())) {
            user.setFailedLoginAttempts(user.getFailedLoginAttempts() + 1);

            if (user.getFailedLoginAttempts() >= MAX_LOGIN_ATTEMPTS) {
                user.setAccountLocked(true);
                user.setLockUntil(LocalDateTime.now().plusMinutes(LOCK_LOGIN_DURATION));
                userRepository.save(user);
                throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Demasiados intentos fallidos, la cuenta ha sido bloqueada temporalmente.");
            }

            userRepository.save(user);
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Credenciales incorrectas, por favor, intenta nuevamente.");
        }

        if (!user.isVerified()) {
            VerificationToken verificationToken = tokenRepository.findByUser(user)
                    .orElseThrow(() -> new BusinessException(
                            "Token de verificación expirado",
                            HttpStatus.INTERNAL_SERVER_ERROR.value(),
                            Map.of(
                                    "email", email
                            )
                    ));
            throw new AccountNotVerifiedException("Cuenta no verificada, revisa tu correo para activarla.", email, verificationToken.getExpiryDate());
        }

        // Si el usuario tiene 2FA activado, generar y enviar código
        if (user.isTwoFactorEnabled()) {

            // Obtener deviceId desde los headers
            //String deviceId = extractDeviceId(request);
            boolean isTrusted = trustedDeviceService.isDeviceTrusted(user, deviceId);

            if (isTrusted) {
                return generateTokens(user); // 🔥 Si es confiable, saltamos el 2FA
            }

            LocalDateTime expiresAt = twoFactorAuthService.generateAndSend2FACode(user);
            Map<String, String> response = new HashMap<>();
            response.put("message", "Código 2FA enviado a tu correo.");
            response.put("expiresAt", expiresAt.toString());
            return response;
        }


        // Si no tiene 2FA, generar tokens directamente
        return generateTokens(user);
    }

    public Map<String, String> verify2FA(String email, String code, boolean rememberDevice, HttpServletRequest request) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("Usuario no encontrado"));

        boolean isValid = twoFactorAuthService.verifyCode(user, code);
        if (!isValid) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Código 2FA incorrecto o expirado.");
        }

        if (rememberDevice) {
            String deviceId = extractDeviceId(request);
            String userAgent = request.getHeader("User-Agent"); // Obtener el User-Agent
            String ip = request.getRemoteAddr(); // Obtener la IP del usuario

            trustedDeviceService.rememberDevice(user, deviceId, userAgent, ip);
        }

        // Si el código es válido, generar tokens
        return generateTokens(user);
    }

    private Map<String, String> generateTokens(User user) {
        String accessToken = jwtService.generateToken(user);
        String refreshToken = jwtService.generateRefreshToken(user.getEmail());

        Map<String, String> tokens = new HashMap<>();
        tokens.put("accessToken", accessToken);
        tokens.put("refreshToken", refreshToken);
        return tokens;
    }

    @Transactional
    public void toggleTwoFactorAuthentication(String email, boolean enable, String password) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("Usuario no encontrado"));

        // Si está desactivando 2FA, validar la contraseña
        if (!enable) {
            if (!passwordEncoder.matches(password, user.getPassword())) {
                throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Contraseña incorrecta");
            }
        }

        user.setTwoFactorEnabled(enable);
        userRepository.save(user);
    }

    public void requestPasswordReset(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("Usuario no encontrado"));

        // Verificar si la cuenta está bloqueada
        if (user.isAccountLocked()) {
            if (user.getLockUntil().isAfter(LocalDateTime.now())) {
                //throw new RuntimeException("Account is temporarily locked. Try again later.");
                throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Tu cuenta ha sido bloqueada temporalmente. Intenta más tarde.");
            } else {
                user.setAccountLocked(false); // Desbloquear si ya pasó el tiempo
                user.setResetAttempts(0);
            }
        }

        // Verificar intentos de recuperación
        if (user.getResetAttempts() >= MAX_RESET_ATTEMPTS) {
            user.setAccountLocked(true);
            user.setLockUntil(LocalDateTime.now().plus(LOCK_DURATION));
            userRepository.save(user);
            //throw new RuntimeException("Too many failed attempts. Account is locked for 1 hour.");
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Demasiados intentos fallidos. Tu cuenta ha sido bloqueada temporalmente.");
        }

        // Eliminar cualquier token previo del usuario
        passwordResetTokenRepository.findByUserId(user.getId()).ifPresent(passwordResetTokenRepository::delete);

        // Generar y guardar un nuevo token
        PasswordResetToken resetToken = PasswordResetToken.generate(user);
        passwordResetTokenRepository.save(resetToken);

        // Incrementar intentos
        user.setResetAttempts(user.getResetAttempts() + 1);
        userRepository.save(user);

        // Enviar email para resetear contraseña
        sendPasswordResetEmail(user.getEmail(), resetToken.getToken());
    }

    private void sendPasswordResetEmail(String email, String token) {
        User user = searchUser(email);
        String url = frontendUrl + "/reset-password?token=" + token;

        emailService.sendDynamicEmail(
                email,
                "Restablece tu contraseña en CuentaOk",
                user.getFirstName(),
                "Haz clic en el botón para crear una nueva contraseña:",
                "link", // tipo
                url, // contenidoPrincipal (URL)
                "Restablecer contraseña", // textoBoton
                null // expiracion (no aplica)
        );
    }

    public void resetPassword(String token, String newPassword) {
        PasswordResetToken resetToken = passwordResetTokenRepository.findByToken(token)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST, "Token inválido o expirado"));

        // Verificar que el token no haya expirado
        if (resetToken.isExpired()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "El token ha expirado.");
        }

        // Actualizar la contraseña del usuario
        User user = resetToken.getUser();
        user.setPassword(passwordEncoder.encode(newPassword));

        // Desbloquear cuenta y resetear intentos
        user.setAccountLocked(false);
        user.setLockUntil(null);
        user.setResetAttempts(0);

        userRepository.save(user);
        // Eliminar el token usado
        passwordResetTokenRepository.delete(resetToken);
    }

    public User getAuthenticatedUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) {
            throw new UsernameNotFoundException("Usuario no autenticado");
        }

        String email = authentication.getName(); // Obtiene el email del usuario autenticado
        return userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("Usuario no encontrado"));
    }

    public boolean removeDevice(String userEmail, String deviceId) {
        Optional<TrustedDevice> device = trustedDeviceRepository.findByDeviceId(deviceId);

        if (device.isPresent() && device.get().getUser().getEmail().equals(userEmail)) {
            trustedDeviceRepository.delete(device.get());
            return true;
        }
        return false;
    }


}

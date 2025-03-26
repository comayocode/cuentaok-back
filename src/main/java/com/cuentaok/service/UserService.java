package com.cuentaok.service;

import com.cuentaok.model.PasswordResetToken;
import com.cuentaok.repository.PasswordResetTokenRepository;
import org.springframework.http.HttpStatus;
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
import org.springframework.mail.javamail.MimeMessageHelper;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import org.springframework.web.server.ResponseStatusException;

import java.time.LocalDateTime;
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

    private static final int MAX_RESET_ATTEMPTS = 3;
    private static final Duration LOCK_DURATION = Duration.ofHours(1); // Bloqueo de 1 hora
    private static final int MAX_LOGIN_ATTEMPTS = 5; // Intentos fallidos antes del bloqueo
    private static final int LOCK_LOGIN_DURATION = 15; // Minutos bloqueado

    public UserService(UserRepository userRepository, VerificationTokenRepository tokenRepository, JavaMailSender mailSender, JwtService jwtService, PasswordEncoder passwordEncoder, PasswordResetTokenRepository passwordResetTokenRepository, TwoFactorAuthService twoFactorAuthService) {
        this.userRepository = userRepository;
        this.tokenRepository = tokenRepository;
        this.mailSender = mailSender;
        this.jwtService = jwtService;
        this.passwordEncoder = passwordEncoder;
        this.passwordResetTokenRepository = passwordResetTokenRepository;
        this.twoFactorAuthService = twoFactorAuthService;
    }

    public User registerUser(String email, String password) {
        if (userRepository.existsByEmail(email)) {
            throw new RuntimeException("El correo ya está registrado.");
        }

        User user = new User(email, passwordEncoder.encode(password), false);
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
        String url = "http://localhost:8080/api/auth/verify?token=" + token;
        String subject = "Verifica tu cuenta";
        String message = "<p>Gracias por registrarte. Haz clic en el siguiente enlace para verificar tu cuenta:</p>"
                + "<a href=\"" + url + "\">Verificar cuenta</a>";

        try {
            MimeMessage mail = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(mail, true);
            helper.setTo(email);
            helper.setSubject(subject);
            helper.setText(message, true);
            mailSender.send(mail);
        } catch (MessagingException e) {
            throw new RuntimeException("Error al enviar el email");
        }
    }

    public void verifyUser(String token) {
        VerificationToken verificationToken = tokenRepository.findByToken(token)
                .orElseThrow(() -> new RuntimeException("Token inválido o expirado"));

        User user = verificationToken.getUser();
        user.setVerified(true);  // Marcar al usuario como verificado
        userRepository.save(user);

        tokenRepository.delete(verificationToken);  // Eliminar el token después de la verificación
    }

    public void resendVerificationEmail(String email) {
        // Buscar el usuario por email
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("Usuario no encontrado"));

        // Verificar si ya está verificado
        if (user.isVerified()) {
            throw new RuntimeException("Este usuario ya está verificado.");
        }

        // Eliminar el token anterior si existe
        tokenRepository.findByUser(user).ifPresent(tokenRepository::delete);

        // Crear un nuevo token
        String newToken = UUID.randomUUID().toString();
        VerificationToken verificationToken = new VerificationToken(newToken, user, LocalDateTime.now().plusHours(24));
        tokenRepository.save(verificationToken);

        // Enviar el correo con el nuevo token
        sendVerificationEmail(user.getEmail(), newToken);
    }

    public Map<String, String> loginWith2FA(String email, String password) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("Usuario no encontrado"));

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
            throw new RuntimeException("Cuenta no verificada");
        }

        // Si el usuario tiene 2FA activado, generar y enviar código
        if (user.isTwoFactorEnabled()) {
            twoFactorAuthService.generateAndSend2FACode(user);
            Map<String, String> response = new HashMap<>();
            response.put("message", "Código 2FA enviado a tu correo.");
            return response;
        }

        // Si no tiene 2FA, generar tokens directamente
        return generateTokens(user);
    }

    public Map<String, String> verify2FA(String email, String code) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("Usuario no encontrado"));

        boolean isValid = twoFactorAuthService.verifyCode(user, code);
        if (!isValid) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Código 2FA incorrecto o expirado.");
        }

        // Si el código es válido, generar tokens
        return generateTokens(user);
    }

    private Map<String, String> generateTokens(User user) {
        String accessToken = jwtService.generateToken(user.getEmail());
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
        String url = "http://localhost:8080/api/auth/reset-password?token=" + token;
        String subject = "Restablecer contraseña";
        String message = "<p>Haz clic en el siguiente enlace para restablecer tu contraseña:</p>"
                + "<a href=\"" + url + "\">Restablecer contraseña</a>";

        try {
            MimeMessage mail = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(mail, true);
            helper.setTo(email);
            helper.setSubject(subject);
            helper.setText(message, true);
            mailSender.send(mail);
        } catch (MessagingException e) {
            throw new RuntimeException("Error al enviar el email");
        }
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


}

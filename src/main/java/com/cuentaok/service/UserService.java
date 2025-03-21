package com.cuentaok.service;

import org.springframework.security.crypto.password.PasswordEncoder;
import com.cuentaok.model.User;
import com.cuentaok.repository.UserRepository;

import org.springframework.stereotype.Service;
import java.util.HashMap;
import java.util.Map;

import com.cuentaok.model.VerificationToken;
import com.cuentaok.repository.VerificationTokenRepository;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import java.time.LocalDateTime;
import java.util.UUID;

@Service
public class UserService {

    private final UserRepository userRepository;
    private final VerificationTokenRepository tokenRepository;
    private final JavaMailSender mailSender;

    private final JwtService jwtService;
    private final PasswordEncoder passwordEncoder;

    public UserService(UserRepository userRepository, VerificationTokenRepository tokenRepository, JavaMailSender mailSender, JwtService jwtService, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.tokenRepository = tokenRepository;
        this.mailSender = mailSender;
        this.jwtService = jwtService;
        this.passwordEncoder = passwordEncoder;
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
        String url = "http://localhost:8080/api/users/verify?token=" + token;
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

    public Map<String, String> login(String email, String password) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("Usuario no encontrado"));

        if (!passwordEncoder.matches(password, user.getPassword())) {
            throw new RuntimeException("Credenciales incorrectas");
        }

        if (!user.isVerified()) {
            throw new RuntimeException("Cuenta no verificada");
        }

        String accessToken = jwtService.generateToken(email);
        String refreshToken = jwtService.generateRefreshToken(email);

        Map<String, String> tokens = new HashMap<>();
        tokens.put("accessToken", accessToken);
        tokens.put("refreshToken", refreshToken);
        return tokens;
    }

}

package com.cuentaok.service;

import com.cuentaok.model.TwoFactorAuth;
import com.cuentaok.model.User;
import com.cuentaok.repository.TwoFactorAuthRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.Random;

@Service
@RequiredArgsConstructor
public class TwoFactorAuthService {

    private final TwoFactorAuthRepository twoFactorAuthRepository;
    private final EmailService emailService;


    @Transactional
    public void generateAndSend2FACode(User user) {
        // Generar código de 6 dígitos
        String code = String.format("%06d", new Random().nextInt(1000000));

        // Buscar si el usuario ya tiene un código previo
        Optional<TwoFactorAuth> existingAuth = twoFactorAuthRepository.findByUser(user);

        TwoFactorAuth twoFactorAuth = existingAuth.orElseGet(() -> new TwoFactorAuth());
        twoFactorAuth.setUser(user);
        twoFactorAuth.setCode(code);
        twoFactorAuth.setExpiresAt(LocalDateTime.now().plusMinutes(5));

        // Guardar código en la base de datos
        twoFactorAuthRepository.save(twoFactorAuth);

        // Enviar código por email
        try {
            emailService.sendEmail(user.getEmail(), "Your 2FA Code", user.getUsername(), "Your verification code is: " + code);
        } catch (Exception e) {
            throw new RuntimeException("Failed to send 2FA email", e);
        }
    }

    public boolean verifyCode(User user, String code) {
        Optional<TwoFactorAuth> authOpt = twoFactorAuthRepository.findByUser(user);

        if (authOpt.isPresent()) {
            TwoFactorAuth auth = authOpt.get();
            if (auth.getCode().equals(code) && auth.getExpiresAt().isAfter(LocalDateTime.now())) {
                // Eliminar el código después de validarlo correctamente
                twoFactorAuthRepository.delete(auth);
                return true;
            }
        }
        return false;
    }

}

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
    public LocalDateTime generateAndSend2FACode(User user) {
        // Generar código de 6 dígitos
        String code = String.format("%06d", new Random().nextInt(1000000));

        // Buscar si el usuario ya tiene un código previo
        Optional<TwoFactorAuth> existingAuth = twoFactorAuthRepository.findByUser(user);
        TwoFactorAuth twoFactorAuth = existingAuth.orElseGet(TwoFactorAuth::new);
        twoFactorAuth.setUser(user);
        twoFactorAuth.setCode(code);

        twoFactorAuth.setExpiresAt(LocalDateTime.now().plusMinutes(5));

        // Guardar código en la base de datos
        twoFactorAuthRepository.save(twoFactorAuth);

        // Enviar código por email
        try {
            emailService.sendDynamicEmail(
                    user.getEmail(),
                    "Tu código de verificación en CuentaOk",
                    user.getFirstName(),
                    "Usa este código para iniciar sesión:",
                    "codigo", // tipo
                    code, // contenidoPrincipal (código)
                    null, // textoBoton (no aplica)
                    "5 Minutos" // expiracion
            );
        } catch (Exception e) {
            throw new RuntimeException("Failed to send 2FA email", e);
        }

        return twoFactorAuth.getExpiresAt();
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

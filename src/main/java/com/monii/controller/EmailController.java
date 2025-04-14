package com.monii.controller;

import com.monii.service.EmailService;
import jakarta.mail.MessagingException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/email")
public class EmailController {

    @Autowired
    private EmailService emailService;

    @PostMapping("/send")
    public String sendEmail(@RequestParam String to, @RequestParam String subject,
                            @RequestParam String nombre, @RequestParam String mensaje) {
        try {
            emailService.sendEmail(to, subject, nombre, mensaje);
            return "Correo enviado correctamente.";
        } catch (MessagingException e) {
            return "Error enviando el correo: " + e.getMessage();
        }
    }
}

package com.cuentaok.service;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;

@Service
public class EmailService {

    @Autowired
    private JavaMailSender mailSender;

    @Autowired
    private TemplateEngine templateEngine;

    public void sendEmail(String to, String subject, String nombre, String mensajeTexto) throws MessagingException {
        MimeMessage message = mailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

        // Cargar plantilla y reemplazar variables
        Context context = new Context();
        context.setVariable("nombre", nombre);
        context.setVariable("mensaje", mensajeTexto);
        String contenidoHtml = templateEngine.process("email-template", context);

        // Configurar email
        helper.setTo(to);
        helper.setSubject(subject);
        helper.setText(contenidoHtml, true); // true = enviar como HTML

        mailSender.send(message);
    }
}

package com.cuentaok.service;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import lombok.RequiredArgsConstructor;
import org.springframework.lang.Nullable;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class EmailService {
    private final JavaMailSender mailSender;
    private final TemplateEngine templateEngine;
    private static final Logger log = LoggerFactory.getLogger(EmailService.class);

    @Async
    public void sendDynamicEmail(String to, String subject, String username, String message,
                                 String emailType, String mainContent,
                                 @Nullable String textoBoton, @Nullable String expiracion) {
        try {
            Map<String, Object> variables = new HashMap<>();
            variables.put("nombre", username);
            variables.put("mensaje", message);
            variables.put("tipo", emailType);
            variables.put("contenidoPrincipal", mainContent);

            if ("link".equals(emailType)) {
                variables.put("textoBoton", textoBoton);
            } else if ("codigo".equals(emailType)) {
                variables.put("expiracion", expiracion);
            }

            sendHtmlEmail(to, subject, "email-template", variables); // Reutiliza el método interno
        } catch (Exception e) {
            log.error("Error enviando email dinámico a {}", to, e);
        }
    }
    @Async
    public void sendHtmlEmail(String to, String subject, String templateName, Map<String, Object> variables) {
        try {
            Context context = new Context();
            variables.forEach(context::setVariable);

            String contenidoHtml = templateEngine.process(templateName, context);

            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");
            helper.setTo(to);
            helper.setSubject(subject);
            helper.setText(contenidoHtml, true);
            mailSender.send(message);
        } catch (MessagingException e) {
            log.error("Error enviando email a {}", to, e);
        }
    }

    // Método SÍNCRONO
    public void sendEmail(String to, String subject, String username, String textMessage) throws MessagingException {
        MimeMessage message = mailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

        Context context = new Context();
        context.setVariable("nombre", username);
        context.setVariable("mensaje", textMessage);
        String contenidoHtml = templateEngine.process("email-template", context);

        helper.setTo(to);
        helper.setSubject(subject);
        helper.setText(contenidoHtml, true);
        mailSender.send(message);
    }
}
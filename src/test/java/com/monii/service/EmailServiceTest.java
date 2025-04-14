package com.monii.service;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
class EmailServiceTest {

    @Autowired
    private EmailService emailService;

    @Test
    void testSendEmail() {
        // Datos de prueba
        String destinatario = "email@email.com";
        String asunto = "Prueba de Envío de Correo 2";
        String nombre = "Manuelito Rodriguez";
        String mensaje = "¡Hola! Este es un correo de prueba enviado desde Spring Boot.";

        // Enviar correo y verificar que no hay errores
        assertDoesNotThrow(() -> emailService.sendEmail(destinatario, asunto, nombre, mensaje));
    }
}

package com.cuentaok.controller;
import com.cuentaok.dto.UserRequest;

import com.cuentaok.model.User;
import com.cuentaok.service.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/users")
public class UserController {

    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @PostMapping("/register")
    public ResponseEntity<String> registerUser(@RequestBody UserRequest request) {
        try {
            User user = userService.registerUser(request.getEmail(), request.getPassword());
            return ResponseEntity.ok("Usuario registrado con éxito. Verifique su correo electrónico.");
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    @GetMapping("/verify")
    public ResponseEntity<String> verifyUser(@RequestParam String token) {
        try {
            userService.verifyUser(token);
            return ResponseEntity.ok("Cuenta verificada con éxito.");
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    @PostMapping("/resend-verification")
    public ResponseEntity<String> resendVerification(@RequestBody UserRequest request) {
        try {
            userService.resendVerificationEmail(request.getEmail());
            return ResponseEntity.ok("Se ha enviado un nuevo correo de verificación.");
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    @PostMapping("/login")
    public ResponseEntity<Map<String, String>> login(@RequestBody UserRequest request) {
        return ResponseEntity.ok(userService.login(request.getEmail(), request.getPassword()));
    }
}

package com.example.demo.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import com.example.demo.model.AuthUser;
import com.example.demo.repository.AuthUserRepository;
import com.example.demo.service.TokenService;

/**
 * REST controller so the frontend (and JSON service) can interact with the
 * authentication service using plain JSON / HTTP instead of raw SOAP XML.
 *
 * Endpoints:
 *   POST /register  { "username": "...", "password": "..." }  -> "User registered"
 *   POST /login     { "username": "...", "password": "..." }  -> token string
 *   POST /validate  (plain text body = token)                 -> "true" | "false"
 */
@RestController
@CrossOrigin(origins = "*")
public class AuthRestController {

    @Autowired
    AuthUserRepository repo;

    @Autowired
    TokenService tokenService;

    // DTO for register / login requests
    public static class AuthRequest {
        private String username;
        private String password;
        public String getUsername() { return username; }
        public void setUsername(String u) { this.username = u; }
        public String getPassword() { return password; }
        public void setPassword(String p) { this.password = p; }
    }

    // ── Health — tests DB connectivity ───────────────────────────────────
    @GetMapping("/health")
    public ResponseEntity<String> health() {
        try {
            long count = repo.count(); // throws if DB is down
            return ResponseEntity.ok("SOAP Service OK | DB connected | users: " + count);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
                .body("SOAP Service ERROR | DB connection failed: " + e.getMessage());
        }
    }

    // ── Register ─────────────────────────────────────────────────────────
    @PostMapping("/register")
    public ResponseEntity<String> register(@RequestBody AuthRequest req) {
        if (req.getUsername() == null || req.getUsername().isBlank() ||
            req.getPassword() == null || req.getPassword().isBlank()) {
            return ResponseEntity.badRequest().body("Username and password are required");
        }
        if (repo.findByUsername(req.getUsername()) != null) {
            return ResponseEntity.status(HttpStatus.CONFLICT).body("Username already exists");
        }
        AuthUser user = new AuthUser();
        user.setUsername(req.getUsername());
        user.setPassword(req.getPassword());
        repo.save(user);
        return ResponseEntity.ok("User registered successfully");
    }

    // ── Login ─────────────────────────────────────────────────────────────
    @PostMapping("/login")
    public ResponseEntity<String> login(@RequestBody AuthRequest req) {
        if (req.getUsername() == null || req.getPassword() == null) {
            return ResponseEntity.badRequest().body("Username and password are required");
        }
        AuthUser user = repo.findByUsername(req.getUsername());
        if (user == null || !user.getPassword().equals(req.getPassword())) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid username or password");
        }
        String token = tokenService.generateToken(req.getUsername());
        return ResponseEntity.ok(token);
    }

    // ── Validate token ────────────────────────────────────────────────────
    @PostMapping("/validate")
    public ResponseEntity<String> validate(@RequestBody String token) {
        String clean = token.trim().replace("\"", "");
        boolean valid = tokenService.validateToken(clean);
        if (valid) {
            return ResponseEntity.ok("true");
        } else {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("false");
        }
    }
}
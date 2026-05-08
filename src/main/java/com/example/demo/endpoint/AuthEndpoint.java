package com.example.demo.endpoint;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.ws.server.endpoint.annotation.*;

import com.example.demo.model.AuthUser;
import com.example.demo.repository.AuthUserRepository;
import com.example.demo.service.TokenService;

@Endpoint
public class AuthEndpoint {

    private static final String NAMESPACE = "http://auth";

    @Autowired
    AuthUserRepository repo;

    @Autowired
    TokenService tokenService;

    // --- Inner request/response classes for SOAP payload mapping ---

    public static class RegisterUserRequest {
        private String username;
        private String password;
        public String getUsername() { return username; }
        public void setUsername(String username) { this.username = username; }
        public String getPassword() { return password; }
        public void setPassword(String password) { this.password = password; }
    }

    public static class LoginUserRequest {
        private String username;
        private String password;
        public String getUsername() { return username; }
        public void setUsername(String username) { this.username = username; }
        public String getPassword() { return password; }
        public void setPassword(String password) { this.password = password; }
    }

    public static class ValidateTokenRequest {
        private String token;
        public String getToken() { return token; }
        public void setToken(String token) { this.token = token; }
    }

    // --- SOAP operations ---

    @PayloadRoot(namespace = NAMESPACE, localPart = "RegisterUserRequest")
    @ResponsePayload
    public String register(@RequestPayload RegisterUserRequest request) {
        AuthUser user = new AuthUser();
        user.setUsername(request.getUsername());
        user.setPassword(request.getPassword());
        repo.save(user);
        return "User registered";
    }

    @PayloadRoot(namespace = NAMESPACE, localPart = "LoginUserRequest")
    @ResponsePayload
    public String login(@RequestPayload LoginUserRequest request) {
        AuthUser user = repo.findByUsername(request.getUsername());
        if (user != null && user.getPassword().equals(request.getPassword())) {
            return tokenService.generateToken(request.getUsername());
        }
        return "Invalid credentials";
    }

    @PayloadRoot(namespace = NAMESPACE, localPart = "ValidateTokenRequest")
    @ResponsePayload
    public String validateToken(@RequestPayload ValidateTokenRequest request) {
        boolean valid = tokenService.validateToken(request.getToken());
        return String.valueOf(valid);
    }
}
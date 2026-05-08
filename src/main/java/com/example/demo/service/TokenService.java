package com.example.demo.service;

import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.example.demo.model.AuthUser;
import com.example.demo.repository.AuthUserRepository;

@Service
public class TokenService {

    @Autowired
    private AuthUserRepository repo;

    public String generateToken(String username) {
        AuthUser user = repo.findByUsername(username);
        if (user == null) return null;
        String token = UUID.randomUUID().toString();
        user.setToken(token);
        repo.save(user);
        return token;
    }

    public boolean validateToken(String token) {
        if (token == null || token.isBlank()) return false;
        // strip surrounding quotes or whitespace that HTTP body may include
        String clean = token.trim().replace("\"", "");
        return repo.findByToken(clean) != null;
    }
}
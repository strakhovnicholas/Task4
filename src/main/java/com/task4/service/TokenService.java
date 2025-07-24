package com.task4.service;

import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class TokenService {
    private final Set<String> blacklistedTokens = Collections.synchronizedSet(new HashSet<>());
    private final Map<String, String> refreshTokenStore = new ConcurrentHashMap<>();

    public void blacklistToken(String token) {
        blacklistedTokens.add(token);
    }

    public boolean isTokenBlacklisted(String token) {
        return blacklistedTokens.contains(token);
    }

    public void storeRefreshToken(String username, String refreshToken) {
        refreshTokenStore.put(username, refreshToken);
    }

    public String getRefreshToken(String username) {
        return refreshTokenStore.get(username);
    }

    public void invalidateRefreshToken(String username) {
        refreshTokenStore.remove(username);
    }
}

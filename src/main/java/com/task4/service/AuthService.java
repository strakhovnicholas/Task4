package com.task4.service;

import com.task4.dto.JwtResponse;
import com.task4.dto.LoginRequest;
import com.task4.dto.RefreshTokenRequest;
import com.task4.dto.SignupRequest;
import com.task4.model.Role;
import com.task4.model.User;
import com.task4.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Set;

@Service
public class AuthService {
    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JwtUtils jwtUtils;

    @Autowired
    private TokenService tokenService;

    public User registerUser(SignupRequest request) {
        User user = new User();
        user.setUsername(request.getUsername());
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.setEmail(request.getEmail());
        user.setRoles(Set.of(Role.GUEST)); // Роль по умолчанию
        return userRepository.save(user);
    }

    public JwtResponse authenticateUser(LoginRequest request) {
        User user = userRepository.findByUsername(request.getUsername())
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            throw new BadCredentialsException("Invalid password");
        }

        String jwtToken = jwtUtils.generateJwtToken(user.getUsername(), user.getRoles());
        String refreshToken = jwtUtils.generateRefreshToken(user.getUsername());
        tokenService.storeRefreshToken(user.getUsername(), refreshToken);

        return new JwtResponse(jwtToken, refreshToken);
    }

    public JwtResponse refreshToken(RefreshTokenRequest request) {
        String refreshToken = request.getRefreshToken();
        if (!jwtUtils.validateToken(refreshToken)) {
            throw new IllegalArgumentException("Invalid refresh token");
        }

        String username = jwtUtils.getUsernameFromToken(refreshToken);
        String storedRefreshToken = tokenService.getRefreshToken(username);

        if (storedRefreshToken == null || !storedRefreshToken.equals(refreshToken)) {
            throw new IllegalArgumentException("Refresh token is invalid or expired");
        }

        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        String newJwtToken = jwtUtils.generateJwtToken(user.getUsername(), user.getRoles());
        return new JwtResponse(newJwtToken, refreshToken); // Возвращаем тот же refreshToken
    }

    public void logout(String jwtToken, String username) {
        tokenService.blacklistToken(jwtToken);
        tokenService.invalidateRefreshToken(username);
    }
}

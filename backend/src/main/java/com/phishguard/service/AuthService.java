package com.phishguard.service;

import com.phishguard.dto.AuthRequest;
import com.phishguard.dto.AuthResponse;
import com.phishguard.dto.RegisterRequest;
import com.phishguard.dto.UserDto;
import com.phishguard.entity.User;
import com.phishguard.repository.UserRepository;
import com.phishguard.security.JwtTokenProvider;
import com.phishguard.security.UserPrincipal;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider tokenProvider;

    public AuthService(UserRepository userRepository,
                       PasswordEncoder passwordEncoder,
                       JwtTokenProvider tokenProvider) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.tokenProvider = tokenProvider;
    }

    @Transactional
    public AuthResponse register(RegisterRequest request) {
        if (userRepository.existsByEmail(request.getEmail().toLowerCase().trim())) {
            throw new IllegalArgumentException("An account with this email address already exists.");
        }

        String passwordHash = passwordEncoder.encode(request.getPassword());
        User user = new User(
                request.getName().trim(),
                request.getEmail().toLowerCase().trim(),
                passwordHash,
                "ROLE_ANALYST"
        );

        User saved = userRepository.save(user);
        UserPrincipal principal = UserPrincipal.create(saved);
        String token = tokenProvider.generateToken(principal);

        return new AuthResponse(token, mapToDto(saved));
    }

    @Transactional(readOnly = true)
    public AuthResponse login(AuthRequest request) {
        User user = userRepository.findByEmail(request.getEmail().toLowerCase().trim())
                .orElseThrow(() -> new BadCredentialsException("Invalid email or password."));

        if (!passwordEncoder.matches(request.getPassword(), user.getPasswordHash())) {
            throw new BadCredentialsException("Invalid email or password.");
        }

        UserPrincipal principal = UserPrincipal.create(user);
        String token = tokenProvider.generateToken(principal);

        return new AuthResponse(token, mapToDto(user));
    }

    @Transactional(readOnly = true)
    public UserDto getCurrentUserDto(UserPrincipal principal) {
        if (principal == null) return null;
        User user = userRepository.findById(principal.getId())
                .orElseThrow(() -> new IllegalArgumentException("User not found"));
        return mapToDto(user);
    }

    @Transactional(readOnly = true)
    public User getCurrentUserEntity(UserPrincipal principal) {
        if (principal == null) return null;
        return userRepository.findById(principal.getId()).orElse(null);
    }

    public UserDto mapToDto(User user) {
        return new UserDto(
                user.getId(),
                user.getName(),
                user.getEmail(),
                user.getRole(),
                user.getCreatedAt()
        );
    }
}

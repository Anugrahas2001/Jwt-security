package com.security.jwtsecurity.service;

import com.security.jwtsecurity.entity.RefreshToken;
import com.security.jwtsecurity.repository.RefreshTokenRepository;
import com.security.jwtsecurity.repository.UserRepository;
import com.security.jwtsecurity.security.JWTService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {

    private final UserRepository userRepository;

    private final RefreshTokenRepository refreshTokenRepository;
    
    private final JWTService jwtService;


    public RefreshToken createRefreshToken(String userName) {

        RefreshToken refreshToken = RefreshToken.builder()
                .user(userRepository.findByEmail(userName).get())
                .refreshToken(jwtService.generateRefreshToken(userRepository.findByEmail(userName).get()))
                .expiresIn(Instant.now().plusMillis(60000))
                .build();
        return refreshTokenRepository.save(refreshToken);
    }

    public Optional<RefreshToken> findByToken(String token)
    {
        return refreshTokenRepository.findByRefreshToken(token);
    }



    public RefreshToken verifyExpiration(RefreshToken token)
    {
        if(token.getExpiresIn().compareTo(Instant.now())<0)
        {
            refreshTokenRepository.delete(token);
            throw new RuntimeException(token.getRefreshToken()+" Refresh token was expired.");
        }
        return token;
    }
}

package com.security.jwtsecurity.repository;

import com.security.jwtsecurity.entity.RefreshToken;
import org.springframework.data.mongodb.repository.MongoRepository;

import java.util.Optional;

public interface RefreshTokenRepository extends MongoRepository<RefreshToken,String> {
    Optional<RefreshToken> findByRefreshToken(String token);
}

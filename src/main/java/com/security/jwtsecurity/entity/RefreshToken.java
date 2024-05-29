package com.security.jwtsecurity.entity;

import lombok.Builder;
import lombok.Data;

import java.time.Instant;

@Data
@Builder
public class RefreshToken {
    private String id;
    private String refreshToken;
    private Instant expiresIn;
    private Users user;

}

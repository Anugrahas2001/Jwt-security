package com.security.jwtsecurity.dto;

import com.security.jwtsecurity.util.Roles;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class UserRegisterDto {

    private String name;
    private String email;
    private String password;
    private Roles roles;
}

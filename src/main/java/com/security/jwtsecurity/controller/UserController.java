package com.security.jwtsecurity.controller;

import com.security.jwtsecurity.dto.RefreshTokenDto;
import com.security.jwtsecurity.entity.RefreshToken;
import com.security.jwtsecurity.service.RefreshTokenService;
import com.security.jwtsecurity.service.UserService;
import com.security.jwtsecurity.dto.LoginDto;
import com.security.jwtsecurity.dto.JwtResponse;
import com.security.jwtsecurity.dto.UserRegisterDto;
import com.security.jwtsecurity.entity.Users;
import com.security.jwtsecurity.security.JWTService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RequestMapping("/auth")
@RestController
@RequiredArgsConstructor

public class UserController {

    private final JWTService jwtService;

    private final UserService userService;

    private final RefreshTokenService refreshTokenService;


    @PostMapping("/signup")
    public ResponseEntity<Users> register(@RequestBody UserRegisterDto registerUserDto) {
        Users registeredUser = userService.signup(registerUserDto);

        return ResponseEntity.ok(registeredUser);
    }

    @PostMapping("/login")
    public JwtResponse authenticate(@RequestBody LoginDto loginUserDto) {
        Users authenticatedUser =userService.Login(loginUserDto) ;
        String jwtToken = jwtService.generateAccessToken(authenticatedUser);
        String refreshToken=jwtService.generateRefreshToken(authenticatedUser);

       return JwtResponse.builder().accessToken(jwtToken).refreshToken(refreshToken).build();


    }

    @GetMapping("/me")
    public ResponseEntity<Users> authenticatedUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        Users currentUser = (Users) authentication.getPrincipal();
        return ResponseEntity.ok(currentUser);
    }

    @GetMapping("/")
    public ResponseEntity<List<Users>> allUsers() {
        List<Users> users = userService.allUsers();

        return ResponseEntity.ok(users);
    }

//    @PostMapping("/refreshToken")
//    public JwtResponse refreshToken(@RequestBody RefreshTokenDto refreshDto) {
//        return refreshTokenService.findByToken(refreshDto.getRefreshToken())
//                .map(refreshTokenService::verifyExpiration)
//                .map(RefreshToken::getUser)
//                .map(users -> {
//                    String accessToken = jwtService.generateAccessToken(users);
//
//                    return JwtResponse.builder()
//                            .accessToken(accessToken)
//                            .refreshToken(refreshDto.getRefreshToken()).build();
//                }).orElseThrow(() -> new RuntimeException("Refresh token is not in database"));
//
//    }
    @PostMapping("/refreshToken")
    public ResponseEntity refreshToken(HttpServletRequest request, HttpServletResponse response)
    {
        return ResponseEntity.ok(userService.refreshToken(request,response));
    }
}

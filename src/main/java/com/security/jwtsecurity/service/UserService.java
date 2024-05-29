package com.security.jwtsecurity.service;

import com.security.jwtsecurity.dto.JwtResponse;
import com.security.jwtsecurity.dto.LoginDto;
import com.security.jwtsecurity.dto.UserRegisterDto;
import com.security.jwtsecurity.entity.Users;
import com.security.jwtsecurity.repository.UserRepository;
import com.security.jwtsecurity.security.JWTService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.net.http.HttpHeaders;
import java.util.ArrayList;
import java.util.List;
@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;

    private final PasswordEncoder passwordEncoder;

    private final AuthenticationManager authenticationManager;

    private final JWTService jwtService;


    public Users signup(UserRegisterDto input) {
        Users user = Users.builder()
                .name(input.getName())
                .email(input.getEmail())
                .role(input.getRoles().name())
                .password(passwordEncoder.encode(input.getPassword()))
                .build();

 return userRepository.save(user);
//       String accessToken=jwtService.generateAccessToken(users);
//       String refreshToken=jwtService.generateRefreshToken(users);
//       saveUserToken(accessToken,users);
//       return users;
    }

    private void saveUserToken(String accessToken, Users users) {

    }

    public Users Login(LoginDto input) {
        var manager = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        input.getEmail(),
                        input.getPassword()
                )
        );
        return userRepository.findByEmail(input.getEmail()).orElseThrow(()->new RuntimeException("User not found"));
//        String accessToken=jwtService.generateAccessToken(user);
//        String refreshToken=jwtService.generateRefreshToken(user);
//
//        saveUserToken(accessToken,user);
//        return new JwtResponse(accessToken,refreshToken);

    }


    public List<Users> allUsers() {
        List<Users> users = new ArrayList<>();

        userRepository.findAll().forEach(users::add);

        return users;
    }


    public ResponseEntity refreshToken(HttpServletRequest request,
                                    HttpServletResponse response)
    {
        String authHeader=request.getHeader("Authorization");
        if(authHeader==null || !authHeader.startsWith("Bearer"))
        {
            return new ResponseEntity(HttpStatus.UNAUTHORIZED);
        }
        String token=authHeader.substring(7);

        String userName=jwtService.extractUsername(token);

        Users user=userRepository.findByEmail(userName).orElseThrow(()->new UsernameNotFoundException("User not found"));
        if(jwtService.isTokenValid(token,user))
        {
            String accessToken=jwtService.generateAccessToken(user);
            String refreshToken=jwtService.generateRefreshToken(user);

            return new ResponseEntity(new JwtResponse(accessToken,refreshToken),HttpStatus.OK);
        }

        return new ResponseEntity(HttpStatus.UNAUTHORIZED);
    }
}

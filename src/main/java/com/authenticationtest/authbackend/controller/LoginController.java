package com.authenticationtest.authbackend.controller;

import com.authenticationtest.authbackend.Repository.UserRepository;
import com.authenticationtest.authbackend.jwttoken.JwtTokenUtil;
import com.authenticationtest.authbackend.securityconfig.UserDetailsRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;
import com.authenticationtest.authbackend.Entity.User;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


@RestController
public class LoginController {

    @Autowired
    JwtTokenUtil jwtTokenUtil;

    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    UserDetailsRepository userDetailsRepository;

    @Autowired
    UserRepository userRepository;

    @Autowired
    PasswordEncoder passwordEncoder;

    @GetMapping(value = "/getuser")
    @CrossOrigin(origins = "http://localhost:5050/", allowCredentials = "true")
    public ResponseEntity<?> getuser(HttpServletRequest request) throws Exception {
        System.out.println("in control");
        return ResponseEntity.ok(request.getHeader("AUTHORIZATION"));



    }
    @PostMapping(value = "/signup")
    public ResponseEntity<?> signup(@RequestBody User user) throws Exception{
        try {
            User user1=User.builder()
                    .username(user.getUsername())
                    .password(passwordEncoder.encode(user.getPassword()))
                    .build();
            userRepository.save(user1);
            return ResponseEntity.ok(user1);
        }catch (Exception e){
            return ResponseEntity.ok(e.getLocalizedMessage());
        }

    }

    @PostMapping(value="/login",consumes ="application/json",produces = "application/json")
    public ResponseEntity<?> login(@RequestBody User user, HttpServletResponse response) throws
            Exception,
            NullPointerException,
            AuthenticationException {
        try{
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword()));
            //UserDetails userDetails= userDetailsRepository.loadUserByUsername(user.getUsername());
            String token=jwtTokenUtil.generateToken(user);
            //Cookie cookie=new Cookie("access_token",token);
            //cookie.setMaxAge(1);
            //cookie.setSecure(true);
            //response.addCookie(cookie);
            response.addHeader("AUTHORIZATION","access_token="+token);
            return ResponseEntity.ok(token);
        }catch (DisabledException e){
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }catch (NullPointerException e){
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }catch (AuthenticationException e){
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

    }
}

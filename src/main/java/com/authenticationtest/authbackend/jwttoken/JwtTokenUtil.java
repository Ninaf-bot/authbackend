package com.authenticationtest.authbackend.jwttoken;


import com.authenticationtest.authbackend.Entity.User;
import io.jsonwebtoken.*;
import io.jsonwebtoken.impl.crypto.JwtSignatureValidator;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.security.Key;
import java.util.*;

import org.springframework.stereotype.Component;

import javax.crypto.spec.SecretKeySpec;


@Component
public class JwtTokenUtil{

    private String secret;
    private int jwtExpirationInMs;

    @Value("${jwt.secret}")
    public void setSecret(String secret) {
        this.secret = secret;
    }

    @Value("${jwt.expirationDateInMs}")
    public void setJwtExpirationInMs(int jwtExpirationInMs) {
        this.jwtExpirationInMs = jwtExpirationInMs;
    }


    public String generateToken(User userDetails){
        Map<String, Object> claims = new HashMap<>();
        /*Collection<? extends GrantedAuthority> roles = userDetails.getAuthorities();
        if (roles.contains(new SimpleGrantedAuthority("ROLE_ADMIN"))) {
            claims.put("isAdmin", true);
        }
        if(roles.contains(new SimpleGrantedAuthority("ROLE_USER"))){
            claims.put("isUser",true);
        }*/
        return doGenerateToken(claims, userDetails.getUsername());
    }

    private String doGenerateToken(Map<String, Object> claims, String subject) {
        Key hmacKey = new SecretKeySpec(Base64.getDecoder().decode(secret),
                SignatureAlgorithm.HS256.getJcaName());

        return Jwts.builder()
                .setClaims(claims)
                .setSubject(subject)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + jwtExpirationInMs))
                .signWith(SignatureAlgorithm.HS256, hmacKey).compact();
    }

    public Jws<Claims> validate(String jwtString)
    {

            Key hmacKey = new SecretKeySpec(Base64.getDecoder().decode(secret),
                    SignatureAlgorithm.HS256.getJcaName());
            Jws<Claims> jwt = Jwts.parser()
                    .setSigningKey(hmacKey)
                    .parseClaimsJws(jwtString);
            return jwt;

    }
}

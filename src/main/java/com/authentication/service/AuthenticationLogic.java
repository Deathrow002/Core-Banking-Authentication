package com.authentication.service;

import java.util.concurrent.TimeUnit;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import com.authentication.config.JWT.JwtUtils;
import com.authentication.models.response.JwtResponse;

import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class AuthenticationLogic {
    private final AuthenticationManager authenticationManager;
    private final JwtUtils jwtUtils;
    private final RedisTemplate<String, Object> redisTemplate;

    @Value("${jwt.expiration}")
    private long jwtExpirationMs;

    public JwtResponse authenticateUser(String email, String password) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(email, password));
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        String jwt = jwtUtils.generateJwtToken(authentication);

        saveTokenToRedis(userDetails.getUsername(), jwt);

        return new JwtResponse(jwt, userDetails.getUsername(), userDetails.getAuthorities());
    }

    public boolean SignOut(String token) {
        if (jwtUtils.validateJwtToken(token)) {
            String username = jwtUtils.getUserNameFromJwtToken(token);
            String redisKey = "auth:token:" + username;
            redisTemplate.delete(redisKey);
            return true;
        }
        return false;
    }

    private void saveTokenToRedis(String username, String token) {
        redisTemplate.opsForValue().set(username, token, jwtExpirationMs, TimeUnit.MILLISECONDS);
    }
}

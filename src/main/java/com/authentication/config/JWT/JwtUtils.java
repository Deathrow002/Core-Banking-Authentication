package com.authentication.config.JWT;

import java.util.Date;

import javax.crypto.SecretKey;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import com.authentication.models.UserAuth;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class JwtUtils {
    private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);

    private final JwtConfig jwtConfig;
    private final RedisTemplate<String, Object> redisTemplate;

    public String generateJwtToken(Authentication authentication) {
        UserAuth userPrincipal = (UserAuth) authentication.getPrincipal();
        String role = userPrincipal.getRole() != null ? userPrincipal.getRole().name() : null;
        // Ensure the role is prefixed with "ROLE_"
        if (role != null && !role.startsWith("ROLE_")) {
            role = "ROLE_" + role;
        }
        return Jwts.builder()
                .subject(userPrincipal.getUsername())
                .claim("customerId", userPrincipal.getCustomerId() != null ? userPrincipal.getCustomerId().toString() : null)
                .claim("role", role)
                .issuedAt(new Date())
                .expiration(new Date((new Date()).getTime() + jwtConfig.getExpiration()))
                .signWith(key())
                .compact();
    }

    private SecretKey key() {
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtConfig.getSecretKey()));
    }

    public String getUserNameFromJwtToken(String token) {
        return Jwts.parser().verifyWith(key()).build()
                .parseSignedClaims(token).getPayload().getSubject();
    }

    public boolean validateJwtToken(String authToken) {
        try {
            Jwts.parser().verifyWith(key()).build().parseSignedClaims(authToken);
            
            // Validate against Redis cache to ensure the token hasn't been logged out
            String username = getUserNameFromJwtToken(authToken);
            String redisKey = "auth:token:" + username;
            Object tokenInRedis = redisTemplate.opsForValue().get(redisKey);
            
            if (tokenInRedis == null || !tokenInRedis.equals(authToken)) {
                logger.error("JWT token is revoked or missing in Redis.");
                return false;
            }
            
            return true;
        } catch (MalformedJwtException e) {
            logger.error("Invalid JWT token: {}", e.getMessage());
        } catch (ExpiredJwtException e) {
            logger.error("JWT token is expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            logger.error("JWT token is unsupported: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            logger.error("JWT claims string is empty: {}", e.getMessage());
        }

        return false;
    }
}

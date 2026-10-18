package com.authentication.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.authentication.models.request.UserRegisPayload;
import com.authentication.models.response.SessionUserResponse;
import com.authentication.service.SessionAuthService;
import com.authentication.service.UserAuthService;
import com.authentication.service.UserRegisService;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

/**
 * Session-based authentication API. Logout ({@code POST /api/v1/auth/logout}) is handled by the
 * Spring Security filter chain, see {@link com.authentication.config.WebSecurityConfig}.
 */
@RestController
@RequiredArgsConstructor
public class AuthController {

    private static final Logger log = LoggerFactory.getLogger(AuthController.class);
    private final UserRegisService userRegisService;
    private final UserAuthService userAuthService;
    private final SessionAuthService sessionAuthService;

    /** Issues the XSRF-TOKEN cookie; call once before the first state-changing request (e.g. login). */
    @GetMapping("/api/v1/auth/csrf")
    public ResponseEntity<Void> csrf(CsrfToken csrfToken) {
        // Reading the token forces Spring Security to write the deferred XSRF-TOKEN cookie.
        csrfToken.getToken();
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/api/v1/auth/login")
    public ResponseEntity<?> login(@RequestParam String email, @RequestParam String password,
            HttpServletRequest request, HttpServletResponse response) {
        try {
            return ResponseEntity.ok(sessionAuthService.login(email, password, request, response));
        } catch (AuthenticationException e) {
            log.warn("Login failed for {}: {}", email, e.getMessage());
            return ResponseEntity.badRequest().body("Invalid email or password");
        }
    }

    @GetMapping({"/api/v1/auth/me", "/api/mobile/api/v1/auth/me"})
    public ResponseEntity<SessionUserResponse> me(Authentication authentication) {
        return ResponseEntity.ok(sessionAuthService.toResponse(authentication));
    }

    @PostMapping({"/api/v1/auth/register", "/api/mobile/api/v1/auth/register"})
    public ResponseEntity<?> register(@RequestBody UserRegisPayload user) {
        try {
            UserDetails registeredUser = userRegisService.registerUser(user);
            log.info("User registered successfully: {}", registeredUser.getUsername());
            return ResponseEntity.ok().body(registeredUser);
        } catch (RuntimeException e) {
            log.error("Registration failed: {}", e.getMessage());
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping({"/api/v1/auth/getAllUsers", "/api/mobile/api/v1/auth/getAllUsers"})
    public ResponseEntity<?> getAllUsers() {
        try {
            return ResponseEntity.ok(userAuthService.loadAllUsers());
        } catch (Exception e) {
            log.error("Error fetching users: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Internal Server Error");
        }
    }
}

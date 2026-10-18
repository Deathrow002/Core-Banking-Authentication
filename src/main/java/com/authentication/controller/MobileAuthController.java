package com.authentication.controller;

import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/api/mobile/api/v1/auth")
@RequiredArgsConstructor
public class MobileAuthController {

    private final OAuth2AuthorizationService authorizations;

    @PostMapping("/logout")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void logout(JwtAuthenticationToken authentication) {
        var authorization = authorizations.findByToken(authentication.getToken().getTokenValue(),
                OAuth2TokenType.ACCESS_TOKEN);
        if (authorization != null) {
            authorizations.remove(authorization);
        }
    }
}

package com.authentication.service;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.stereotype.Service;

import com.authentication.config.security.SessionAuthentication;
import com.authentication.models.UserAuth;
import com.authentication.models.response.SessionUserResponse;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class SessionAuthService {

    private final AuthenticationManager authenticationManager;
    private final SecurityContextRepository securityContextRepository;
    private final SecurityContextHolderStrategy securityContextHolderStrategy =
            SecurityContextHolder.getContextHolderStrategy();

    /**
     * Verifies credentials and stores a portable {@link SecurityContext} in the (Redis-backed)
     * HTTP session. Throws {@link org.springframework.security.core.AuthenticationException} on
     * bad credentials.
     */
    public SessionUserResponse login(String email, String password,
            HttpServletRequest request, HttpServletResponse response) {
        Authentication verified = authenticationManager.authenticate(
                UsernamePasswordAuthenticationToken.unauthenticated(email, password));
        Authentication sessionAuthentication = SessionAuthentication.from((UserAuth) verified.getPrincipal());

        // Prevent session fixation: never reuse a session id that existed before login.
        if (request.getSession(false) != null) {
            request.changeSessionId();
        }

        SecurityContext context = securityContextHolderStrategy.createEmptyContext();
        context.setAuthentication(sessionAuthentication);
        securityContextHolderStrategy.setContext(context);
        securityContextRepository.saveContext(context, request, response);

        return toResponse(sessionAuthentication);
    }

    public SessionUserResponse toResponse(Authentication authentication) {
        return new SessionUserResponse(
                authentication.getName(),
                SessionAuthentication.detail(authentication, SessionAuthentication.DETAIL_CUSTOMER_ID),
                authentication.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList());
    }
}

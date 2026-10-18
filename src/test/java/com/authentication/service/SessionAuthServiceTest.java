package com.authentication.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.UUID;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;

import com.authentication.models.Role;
import com.authentication.models.UserAuth;
import com.authentication.models.response.SessionUserResponse;

class SessionAuthServiceTest {

    private final AuthenticationManager authenticationManager = mock(AuthenticationManager.class);
    private final SessionAuthService service =
            new SessionAuthService(authenticationManager, new HttpSessionSecurityContextRepository());

    @AfterEach
    void clear() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void storesPortableSecurityContextInSessionAndRotatesSessionId() {
        UUID customerId = UUID.randomUUID();
        UserAuth user = UserAuth.builder().email("jane@bank.com").password("hash")
                .customerId(customerId).role(Role.USER).build();
        when(authenticationManager.authenticate(any()))
                .thenReturn(UsernamePasswordAuthenticationToken.authenticated(user, null, user.getAuthorities()));

        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpSession preLoginSession = new MockHttpSession();
        request.setSession(preLoginSession);
        String preLoginId = preLoginSession.getId();

        SessionUserResponse response = service.login("jane@bank.com", "secret", request, new MockHttpServletResponse());

        assertThat(response).isEqualTo(new SessionUserResponse("jane@bank.com", customerId.toString(), java.util.List.of("ROLE_USER")));
        assertThat(request.getSession().getId()).isNotEqualTo(preLoginId);

        SecurityContext stored = (SecurityContext) request.getSession()
                .getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);
        assertThat(stored.getAuthentication().getPrincipal()).isEqualTo("jane@bank.com");
    }

    @Test
    void propagatesBadCredentialsWithoutCreatingSession() {
        when(authenticationManager.authenticate(any())).thenThrow(new BadCredentialsException("bad"));
        MockHttpServletRequest request = new MockHttpServletRequest();

        assertThatThrownBy(() -> service.login("jane@bank.com", "wrong", request, new MockHttpServletResponse()))
                .isInstanceOf(BadCredentialsException.class);
        assertThat(request.getSession(false)).isNull();
    }
}

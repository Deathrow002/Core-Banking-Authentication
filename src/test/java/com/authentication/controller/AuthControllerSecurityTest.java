package com.authentication.controller;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.cookie;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.List;
import java.util.UUID;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.test.context.junit.jupiter.web.SpringJUnitWebConfig;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import com.authentication.TestRoles;
import com.authentication.config.WebSecurityConfig;
import com.authentication.config.security.RestAuthenticationEntryPoint;
import com.authentication.config.security.SessionAuthentication;
import com.authentication.models.Role;
import com.authentication.models.RoleNames;
import com.authentication.models.UserAuth;
import com.authentication.models.response.SessionUserResponse;
import com.authentication.service.SessionAuthService;
import com.authentication.service.UserAuthService;
import com.authentication.service.UserRegisService;

/** Exercises the real security filter chain (CSRF, 401, logout) without Redis or a database. */
@SpringJUnitWebConfig(AuthControllerSecurityTest.TestConfig.class)
// with(csrf()) swaps the CsrfTokenRepository inside the shared filter chain, so isolate each test.
@org.springframework.test.annotation.DirtiesContext(classMode = org.springframework.test.annotation.DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
class AuthControllerSecurityTest {

    @Configuration
    @EnableWebMvc
    @Import({WebSecurityConfig.class, AuthController.class, RestAuthenticationEntryPoint.class})
    static class TestConfig {
        @Bean SecurityContextRepository securityContextRepository() { return new HttpSessionSecurityContextRepository(); }
        @Bean UserAuthService userAuthService() { return mock(UserAuthService.class); }
        @Bean UserRegisService userRegisService() { return mock(UserRegisService.class); }
        @Bean SessionAuthService sessionAuthService() { return mock(SessionAuthService.class); }
    }

    @Autowired WebApplicationContext context;
    @Autowired SessionAuthService sessionAuthService;
    @Autowired UserRegisService userRegisService;
    MockMvc mvc;

    @BeforeEach
    void setUp() {
        org.mockito.Mockito.reset(sessionAuthService, userRegisService);
        mvc = MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).build();
    }

    private static UserAuth user(String roleName) {
        return UserAuth.builder().email("jane@bank.com").password("x").customerId(UUID.randomUUID()).role(TestRoles.seeded(roleName)).build();
    }

    @Test
    void csrfEndpointIssuesReadableXsrfCookie() throws Exception {
        mvc.perform(get("/api/v1/auth/csrf"))
                .andExpect(status().isNoContent())
                .andExpect(cookie().exists("XSRF-TOKEN"))
                .andExpect(cookie().httpOnly("XSRF-TOKEN", false));
    }

    @Test
    void loginWithoutCsrfTokenIsRejected() throws Exception {
        mvc.perform(post("/api/v1/auth/login").param("email", "a@b.com").param("password", "x"))
                .andExpect(status().isForbidden());
    }

    @Test
    void loginWithCsrfReturnsUserWithoutToken() throws Exception {
        when(sessionAuthService.login(eq("jane@bank.com"), eq("secret"), any(), any()))
                .thenReturn(new SessionUserResponse("jane@bank.com", "c-1", List.of("ROLE_CUSTOMER"), List.of()));

        mvc.perform(post("/api/v1/auth/login").with(csrf()).param("email", "jane@bank.com").param("password", "secret"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("jane@bank.com"))
                .andExpect(jsonPath("$.roles[0]").value("ROLE_CUSTOMER"))
                .andExpect(jsonPath("$.permissions").isEmpty())
                .andExpect(jsonPath("$.token").doesNotExist());
    }

    @Test
    void loginWithBadCredentialsReturns400() throws Exception {
        when(sessionAuthService.login(any(), any(), any(), any())).thenThrow(new BadCredentialsException("bad"));

        mvc.perform(post("/api/v1/auth/login").with(csrf()).param("email", "jane@bank.com").param("password", "nope"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void meRequiresSession() throws Exception {
        mvc.perform(get("/api/v1/auth/me")).andExpect(status().isUnauthorized());
    }

    @Test
    void meReturnsCurrentUser() throws Exception {
        var auth = SessionAuthentication.from(user(RoleNames.CUSTOMER));
        when(sessionAuthService.toResponse(any()))
                .thenReturn(new SessionUserResponse("jane@bank.com", "c-1", List.of("ROLE_CUSTOMER"), List.of()));

        mvc.perform(get("/api/v1/auth/me").with(authentication(auth)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("jane@bank.com"));
    }

    @Test
    void getAllUsersRequiresAdmin() throws Exception {
        mvc.perform(get("/api/v1/auth/getAllUsers").with(authentication(SessionAuthentication.from(user(RoleNames.CUSTOMER)))))
                .andExpect(status().isForbidden());
        mvc.perform(get("/api/v1/auth/getAllUsers").with(authentication(SessionAuthentication.from(user(RoleNames.ADMIN)))))
                .andExpect(status().isOk());
    }

    @Test
    void registerRequiresSession() throws Exception {
        mvc.perform(post("/api/v1/auth/register").with(csrf()).contentType("application/json").content("{}"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void registerIsForbiddenForUserRole() throws Exception {
        mvc.perform(post("/api/v1/auth/register").with(csrf())
                        .with(authentication(SessionAuthentication.from(user(RoleNames.CUSTOMER))))
                        .contentType("application/json").content(validRegisterJson()))
                .andExpect(status().isForbidden());
    }

    @Test
    void registerIsForbiddenForStaffWithoutAddPermission() throws Exception {
        UserAuth manager = user(RoleNames.MANAGER);
        manager.setRole(new Role(RoleNames.MANAGER, false, true, true));

        mvc.perform(post("/api/v1/auth/register").with(csrf())
                        .with(authentication(SessionAuthentication.from(manager)))
                        .contentType("application/json").content(validRegisterJson()))
                .andExpect(status().isForbidden());

        org.mockito.Mockito.verifyNoInteractions(userRegisService);
    }

    @Test
    void registerByManagerReturnsCreatedLoginWithoutPasswordHash() throws Exception {
        UUID customerId = UUID.randomUUID();
        when(userRegisService.registerUser(any())).thenReturn(UserAuth.builder()
                .email("new@bank.com").password("$2a$10$hash").customerId(customerId).role(new Role(RoleNames.CUSTOMER)).build());

        mvc.perform(post("/api/v1/auth/register").with(csrf())
                        .with(authentication(SessionAuthentication.from(user(RoleNames.MANAGER))))
                        .contentType("application/json").content(validRegisterJson()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").value("new@bank.com"))
                .andExpect(jsonPath("$.customerId").value(customerId.toString()))
                .andExpect(jsonPath("$.role").value("CUSTOMER"))
                .andExpect(jsonPath("$.password").doesNotExist());
    }

    @Test
    void registerRejectsInvalidPayloadBeforeCallingService() throws Exception {
        mvc.perform(post("/api/v1/auth/register").with(csrf())
                        .with(authentication(SessionAuthentication.from(user(RoleNames.ADMIN))))
                        .contentType("application/json")
                        .content("{\"customerId\":\"" + UUID.randomUUID() + "\",\"email\":\"not-an-email\",\"password\":\"short\"}"))
                .andExpect(status().isBadRequest());

        org.mockito.Mockito.verifyNoInteractions(userRegisService);
    }

    private static String validRegisterJson() {
        return "{\"customerId\":\"" + UUID.randomUUID() + "\",\"email\":\"new@bank.com\",\"password\":\"longenough\"}";
    }

    @Test
    void logoutInvalidatesSessionAndRequiresCsrf() throws Exception {
        var auth = authentication(SessionAuthentication.from(user(RoleNames.CUSTOMER)));

        mvc.perform(post("/api/v1/auth/logout").with(auth)).andExpect(status().isForbidden());
        mvc.perform(post("/api/v1/auth/logout").with(auth).with(csrf()))
                .andExpect(status().isNoContent())
                .andExpect(cookie().maxAge("SESSION", 0));
    }
}

package com.authentication.controller;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpStatus;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.test.annotation.DirtiesContext;
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
import com.authentication.models.response.PageResponse;
import com.authentication.models.response.UserResponse;
import com.authentication.service.SessionAuthService;
import com.authentication.service.UserAuthService;
import com.authentication.service.UserManagementException;
import com.authentication.service.UserManagementService;
import com.authentication.service.UserRegisService;

@SpringJUnitWebConfig(UserManagementControllerTest.TestConfig.class)
// with(csrf()) swaps the CsrfTokenRepository inside the shared filter chain, so isolate each test.
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
class UserManagementControllerTest {

    @Configuration
    @EnableWebMvc
    @Import({WebSecurityConfig.class, UserManagementController.class, RestAuthenticationEntryPoint.class})
    static class TestConfig {
        @Bean SecurityContextRepository securityContextRepository() { return new HttpSessionSecurityContextRepository(); }
        @Bean UserManagementService userManagementService() { return mock(UserManagementService.class); }
        @Bean UserAuthService userAuthService() { return mock(UserAuthService.class); }
        @Bean UserRegisService userRegisService() { return mock(UserRegisService.class); }
        @Bean SessionAuthService sessionAuthService() { return mock(SessionAuthService.class); }
    }

    @Autowired WebApplicationContext context;
    @Autowired UserManagementService service;
    MockMvc mvc;

    @BeforeEach
    void setUp() {
        org.mockito.Mockito.reset(service);
        mvc = MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).build();
    }

    private static UserAuth user(String roleName) {
        return UserAuth.builder().email("jane@bank.com").password("x").customerId(UUID.randomUUID()).role(TestRoles.seeded(roleName)).build();
    }

    private static UserAuth user(Role role) {
        return UserAuth.builder().email("jane@bank.com").password("x").customerId(UUID.randomUUID()).role(role).build();
    }

    private static UserResponse response(UUID id, String roleName) {
        return new UserResponse(id, UUID.randomUUID(), "jane@bank.com", roleName, true, LocalDateTime.now());
    }

    private static String validCreateJson() {
        return "{\"customerId\":\"" + UUID.randomUUID() + "\",\"email\":\"new@bank.com\",\"password\":\"longenough\"}";
    }

    @Test
    void everyEndpointRequiresSession() throws Exception {
        UUID id = UUID.randomUUID();
        mvc.perform(get("/api/v1/auth/users")).andExpect(status().isUnauthorized());
        mvc.perform(get("/api/v1/auth/users/" + id)).andExpect(status().isUnauthorized());
        mvc.perform(post("/api/v1/auth/users").with(csrf()).contentType("application/json").content(validCreateJson()))
                .andExpect(status().isUnauthorized());
        mvc.perform(put("/api/v1/auth/users/" + id).with(csrf()).contentType("application/json").content("{}"))
                .andExpect(status().isUnauthorized());
        mvc.perform(delete("/api/v1/auth/users/" + id).with(csrf())).andExpect(status().isUnauthorized());
    }

    @Test
    void userRoleIsForbiddenFromManagement() throws Exception {
        var user = authentication(SessionAuthentication.from(user(RoleNames.CUSTOMER)));
        UUID id = UUID.randomUUID();

        mvc.perform(get("/api/v1/auth/users").with(user)).andExpect(status().isForbidden());
        mvc.perform(get("/api/v1/auth/users/" + id).with(user)).andExpect(status().isForbidden());
        mvc.perform(post("/api/v1/auth/users").with(csrf()).with(user)
                .contentType("application/json").content(validCreateJson())).andExpect(status().isForbidden());
        mvc.perform(delete("/api/v1/auth/users/" + id).with(csrf()).with(user)).andExpect(status().isForbidden());

        verifyNoInteractions(service);
    }

    @Test
    void managerListsUsersInPageEnvelopeWithoutPasswordHash() throws Exception {
        UUID id = UUID.randomUUID();
        when(service.list(any(), eq(1), eq(5))).thenReturn(new PageResponse<>(
                List.of(response(id, RoleNames.CUSTOMER)), 1, 5, 6L, 2));

        mvc.perform(get("/api/v1/auth/users").param("page", "1").param("size", "5")
                        .with(authentication(SessionAuthentication.from(user(RoleNames.MANAGER)))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content[0].id").value(id.toString()))
                .andExpect(jsonPath("$.content[0].role").value("CUSTOMER"))
                .andExpect(jsonPath("$.content[0].password").doesNotExist())
                .andExpect(jsonPath("$.page").value(1))
                .andExpect(jsonPath("$.size").value(5))
                .andExpect(jsonPath("$.totalElements").value(6))
                .andExpect(jsonPath("$.totalPages").value(2));
    }

    @Test
    void listUsesDefaultPagingWhenParamsOmitted() throws Exception {
        when(service.list(any(), anyInt(), anyInt())).thenReturn(new PageResponse<>(List.of(), 0, 20, 0L, 0));

        mvc.perform(get("/api/v1/auth/users").with(authentication(SessionAuthentication.from(user(RoleNames.ADMIN)))))
                .andExpect(status().isOk());

        verify(service).list(any(), eq(0), eq(20));
    }

    @Test
    void rolesEndpointReturnsRoleNamesFromDatabase() throws Exception {
        when(service.roleNames()).thenReturn(List.of("ADMIN", "CUSTOMER", "MANAGER"));

        mvc.perform(get("/api/v1/auth/users/roles")
                        .with(authentication(SessionAuthentication.from(user(RoleNames.MANAGER)))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0]").value("ADMIN"))
                .andExpect(jsonPath("$[1]").value("CUSTOMER"))
                .andExpect(jsonPath("$[2]").value("MANAGER"));
    }

    @Test
    void managerGettingAdminAccountGets403WithReason() throws Exception {
        UUID id = UUID.randomUUID();
        when(service.get(any(), eq(id))).thenThrow(
                new UserManagementException(HttpStatus.FORBIDDEN, "Managers cannot manage ADMIN accounts"));

        mvc.perform(get("/api/v1/auth/users/" + id)
                        .with(authentication(SessionAuthentication.from(user(RoleNames.MANAGER)))))
                .andExpect(status().isForbidden());
    }

    @Test
    void unknownUserReturns404() throws Exception {
        UUID id = UUID.randomUUID();
        when(service.get(any(), eq(id))).thenThrow(
                new UserManagementException(HttpStatus.NOT_FOUND, "User not found: " + id));

        mvc.perform(get("/api/v1/auth/users/" + id)
                        .with(authentication(SessionAuthentication.from(user(RoleNames.ADMIN)))))
                .andExpect(status().isNotFound());
    }

    @Test
    void createReturns201WithoutPasswordHash() throws Exception {
        UUID id = UUID.randomUUID();
        when(service.create(any(), any())).thenReturn(response(id, RoleNames.CUSTOMER));

        mvc.perform(post("/api/v1/auth/users").with(csrf())
                        .with(authentication(SessionAuthentication.from(user(RoleNames.ADMIN))))
                        .contentType("application/json").content(validCreateJson()))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.id").value(id.toString()))
                .andExpect(jsonPath("$.password").doesNotExist());
    }

    @Test
    void createRejectsInvalidPayloadBeforeCallingService() throws Exception {
        mvc.perform(post("/api/v1/auth/users").with(csrf())
                        .with(authentication(SessionAuthentication.from(user(RoleNames.ADMIN))))
                        .contentType("application/json")
                        .content("{\"customerId\":\"" + UUID.randomUUID() + "\",\"email\":\"not-an-email\",\"password\":\"short\"}"))
                .andExpect(status().isBadRequest());

        verify(service, never()).create(any(), any());
    }

    @Test
    void createRejectionReasonIsReturnedAsBadRequest() throws Exception {
        when(service.create(any(), any())).thenThrow(
                new UserManagementException(HttpStatus.BAD_REQUEST, "User already exists with email: new@bank.com"));

        mvc.perform(post("/api/v1/auth/users").with(csrf())
                        .with(authentication(SessionAuthentication.from(user(RoleNames.ADMIN))))
                        .contentType("application/json").content(validCreateJson()))
                .andExpect(status().isBadRequest());
    }

    @Test
    void updateAcceptsPartialPayload() throws Exception {
        UUID id = UUID.randomUUID();
        when(service.update(any(), eq(id), any())).thenReturn(response(id, RoleNames.MANAGER));

        mvc.perform(put("/api/v1/auth/users/" + id).with(csrf())
                        .with(authentication(SessionAuthentication.from(user(RoleNames.ADMIN))))
                        .contentType("application/json").content("{\"role\":\"MANAGER\",\"enabled\":false}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.role").value("MANAGER"));
    }

    @Test
    void updateRejectsMalformedEmailBeforeCallingService() throws Exception {
        UUID id = UUID.randomUUID();

        mvc.perform(put("/api/v1/auth/users/" + id).with(csrf())
                        .with(authentication(SessionAuthentication.from(user(RoleNames.ADMIN))))
                        .contentType("application/json").content("{\"email\":\"not-an-email\"}"))
                .andExpect(status().isBadRequest());

        verify(service, never()).update(any(), any(), any());
    }

    @Test
    void deleteReturns204() throws Exception {
        UUID id = UUID.randomUUID();

        mvc.perform(delete("/api/v1/auth/users/" + id).with(csrf())
                        .with(authentication(SessionAuthentication.from(user(RoleNames.ADMIN)))))
                .andExpect(status().isNoContent());

        verify(service).delete(any(), eq(id));
    }

    @Test
    void managerWithoutDeletePermissionCannotDelete() throws Exception {
        UUID id = UUID.randomUUID();

        mvc.perform(delete("/api/v1/auth/users/" + id).with(csrf())
                        .with(authentication(SessionAuthentication.from(user(RoleNames.MANAGER)))))
                .andExpect(status().isForbidden());

        verify(service, never()).delete(any(), any());
    }

    @Test
    void staffWithoutPermissionsCanOnlyRead() throws Exception {
        var readOnly = authentication(SessionAuthentication.from(user(new Role(RoleNames.MANAGER))));
        UUID id = UUID.randomUUID();
        when(service.list(any(), anyInt(), anyInt())).thenReturn(new PageResponse<>(List.of(), 0, 20, 0L, 0));

        mvc.perform(get("/api/v1/auth/users").with(readOnly)).andExpect(status().isOk());
        mvc.perform(post("/api/v1/auth/users").with(csrf()).with(readOnly)
                .contentType("application/json").content(validCreateJson())).andExpect(status().isForbidden());
        mvc.perform(put("/api/v1/auth/users/" + id).with(csrf()).with(readOnly)
                .contentType("application/json").content("{\"enabled\":false}")).andExpect(status().isForbidden());
        mvc.perform(delete("/api/v1/auth/users/" + id).with(csrf()).with(readOnly)).andExpect(status().isForbidden());

        verify(service, never()).create(any(), any());
        verify(service, never()).update(any(), any(), any());
        verify(service, never()).delete(any(), any());
    }

    @Test
    void permissionWithoutStaffRoleIsNotEnough() throws Exception {
        var customer = authentication(SessionAuthentication.from(user(new Role(RoleNames.CUSTOMER, true, true, true))));

        mvc.perform(post("/api/v1/auth/users").with(csrf()).with(customer)
                .contentType("application/json").content(validCreateJson())).andExpect(status().isForbidden());

        verifyNoInteractions(service);
    }

    @Test
    void selfDeleteRuleViolationReturnsBadRequest() throws Exception {
        UUID id = UUID.randomUUID();
        org.mockito.Mockito.doThrow(new UserManagementException(HttpStatus.BAD_REQUEST, "You cannot delete your own login"))
                .when(service).delete(any(), eq(id));

        mvc.perform(delete("/api/v1/auth/users/" + id).with(csrf())
                        .with(authentication(SessionAuthentication.from(user(RoleNames.ADMIN)))))
                .andExpect(status().isBadRequest());
    }
}

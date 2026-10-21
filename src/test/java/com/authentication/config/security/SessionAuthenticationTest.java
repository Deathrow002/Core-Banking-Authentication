package com.authentication.config.security;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.UUID;

import org.junit.jupiter.api.Test;
import org.springframework.data.redis.serializer.JdkSerializationRedisSerializer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextImpl;

import com.authentication.models.Role;
import com.authentication.models.RoleNames;
import com.authentication.models.UserAuth;

class SessionAuthenticationTest {

    private final UUID customerId = UUID.randomUUID();

    private UserAuth user(String roleName) {
        return UserAuth.builder()
                .email("jane@bank.com")
                .password("{bcrypt}hash")
                .customerId(customerId)
                .role(new Role(roleName))
                .build();
    }

    @Test
    void buildsPortableAuthenticationFromUser() {
        Authentication authentication = SessionAuthentication.from(user(RoleNames.MANAGER));

        assertThat(authentication.isAuthenticated()).isTrue();
        assertThat(authentication.getPrincipal()).isEqualTo("jane@bank.com");
        assertThat(authentication.getCredentials()).isNull();
        assertThat(authentication.getAuthorities()).extracting(GrantedAuthority::getAuthority)
                .containsExactly("ROLE_MANAGER");
        assertThat(authentication.getDetails()).isEqualTo(Map.of(
                "username", "jane@bank.com",
                "customerId", customerId.toString(),
                "role", "ROLE_MANAGER"));
    }

    @Test
    void addsRolePermissionsAsAuthorities() {
        UserAuth admin = user(RoleNames.ADMIN);
        admin.setRole(new Role(RoleNames.ADMIN, true, true, true));

        assertThat(SessionAuthentication.from(admin).getAuthorities()).extracting(GrantedAuthority::getAuthority)
                .containsExactly("ROLE_ADMIN", "PERM_ADD", "PERM_EDIT", "PERM_DELETE");

        admin.setRole(new Role(RoleNames.MANAGER, true, false, false));
        assertThat(SessionAuthentication.from(admin).getAuthorities()).extracting(GrantedAuthority::getAuthority)
                .containsExactly("ROLE_MANAGER", "PERM_ADD");
    }

    @Test
    void sessionPayloadContainsNoServiceSpecificClassesOrSecrets() {
        UserAuth admin = user(RoleNames.ADMIN);
        admin.setRole(new Role(RoleNames.ADMIN, true, true, true));
        SecurityContext context = new SecurityContextImpl(SessionAuthentication.from(admin));
        JdkSerializationRedisSerializer serializer = new JdkSerializationRedisSerializer();

        byte[] bytes = serializer.serialize(context);
        String raw = new String(bytes, StandardCharsets.ISO_8859_1);

        // Other services cannot deserialize classes that only exist in this module.
        assertThat(raw).doesNotContain("com.authentication");
        assertThat(raw).doesNotContain("{bcrypt}hash");

        SecurityContext restored = (SecurityContext) serializer.deserialize(bytes);
        assertThat(restored.getAuthentication().getName()).isEqualTo("jane@bank.com");
        assertThat(SessionAuthentication.detail(restored.getAuthentication(), SessionAuthentication.DETAIL_CUSTOMER_ID))
                .isEqualTo(customerId.toString());
        assertThat(restored.getAuthentication().getAuthorities()).extracting(GrantedAuthority::getAuthority)
                .containsExactly("ROLE_ADMIN", "PERM_ADD", "PERM_EDIT", "PERM_DELETE");
    }

    @Test
    void handlesUserWithoutCustomerId() {
        UserAuth admin = user(RoleNames.ADMIN);
        admin.setCustomerId(null);

        Authentication authentication = SessionAuthentication.from(admin);

        assertThat(SessionAuthentication.detail(authentication, SessionAuthentication.DETAIL_CUSTOMER_ID)).isNull();
        assertThat(SessionAuthentication.detail(null, SessionAuthentication.DETAIL_ROLE)).isNull();
    }
}

package com.authentication;

import com.authentication.models.Role;
import com.authentication.models.RoleNames;

/** Roles with the permissions {@code schema.sql} seeds for them. */
public final class TestRoles {

    private TestRoles() {
    }

    public static Role seeded(String name) {
        return switch (name) {
            case RoleNames.ADMIN -> new Role(name, true, true, true);
            case RoleNames.MANAGER -> new Role(name, true, true, false);
            default -> new Role(name);
        };
    }
}

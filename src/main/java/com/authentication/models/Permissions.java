package com.authentication.models;

import java.util.List;

/**
 * Authorities granted from the permission flags on {@link Role}. They are published next to the
 * {@code ROLE_*} authority in the shared session (and in the mobile access token's
 * {@code permissions} claim), so every service can check them with {@code hasAuthority(...)}.
 */
public final class Permissions {

    public static final String PREFIX = "PERM_";
    public static final String ADD = PREFIX + "ADD";
    public static final String EDIT = PREFIX + "EDIT";
    public static final String DELETE = PREFIX + "DELETE";

    public static final List<String> ALL = List.of(ADD, EDIT, DELETE);

    private Permissions() {
    }
}

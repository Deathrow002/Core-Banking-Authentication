package com.authentication.models.response;

import java.util.List;

/**
 * Current user as exposed to clients. Contains no credentials or tokens.
 * {@code permissions} holds the {@code PERM_*} authorities and {@code roles} every other authority.
 */
public record SessionUserResponse(String username, String customerId, List<String> roles, List<String> permissions) {
}

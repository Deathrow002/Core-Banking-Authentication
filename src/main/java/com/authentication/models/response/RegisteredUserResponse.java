package com.authentication.models.response;

import java.util.UUID;

/** Result of a sign-up. Never includes the password hash. */
public record RegisteredUserResponse(String email, UUID customerId, String role) {
}

package com.authentication.models.response;

import java.time.LocalDateTime;
import java.util.UUID;

import com.authentication.models.UserAuth;

/** Login account as shown to staff. Deliberately omits the password hash. */
public record UserResponse(
        UUID id,
        UUID customerId,
        String email,
        String role,
        boolean enabled,
        LocalDateTime createdAt) {

    public static UserResponse from(UserAuth user) {
        return new UserResponse(user.getId(), user.getCustomerId(), user.getEmail(),
                user.getRoleName(), user.isEnabled(), user.getCreatedAt());
    }
}

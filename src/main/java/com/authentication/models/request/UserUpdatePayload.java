package com.authentication.models.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Partial update: a null field means "leave unchanged". customerId is not updatable,
 * so it is not part of this payload.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserUpdatePayload {

    @Email
    private String email;

    @Size(min = UserRegisPayload.PASSWORD_MIN_LENGTH, max = UserRegisPayload.PASSWORD_MAX_LENGTH)
    private String password;

    /** Role name from the roles table. Null leaves the role unchanged. */
    private String role;

    private Boolean enabled;
}

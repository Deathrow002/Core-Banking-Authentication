package com.authentication.models.request;

import java.util.UUID;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserCreatePayload {

    @NotNull
    private UUID customerId;

    @NotBlank
    @Email
    private String email;

    @NotBlank
    @Size(min = UserRegisPayload.PASSWORD_MIN_LENGTH, max = UserRegisPayload.PASSWORD_MAX_LENGTH)
    private String password;

    /** Role name from the roles table. Optional; defaults to CUSTOMER when omitted. */
    private String role;
}

package com.authentication.models.request;

import java.util.UUID;

import com.fasterxml.jackson.annotation.JsonProperty;

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
public class UserRegisPayload {

    /** BCrypt only uses the first 72 bytes, so longer passwords are rejected instead of silently truncated. */
    public static final int PASSWORD_MIN_LENGTH = 8;
    public static final int PASSWORD_MAX_LENGTH = 72;

    @NotNull
    @JsonProperty("customerId")
    private UUID customerId;

    @NotBlank
    @Email
    @JsonProperty("email")
    private String email;

    @NotBlank
    @Size(min = PASSWORD_MIN_LENGTH, max = PASSWORD_MAX_LENGTH)
    @JsonProperty("password")
    private String password;
}

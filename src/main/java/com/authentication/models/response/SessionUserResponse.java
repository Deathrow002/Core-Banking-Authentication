package com.authentication.models.response;

import java.util.List;

/** Current user as exposed to clients. Contains no credentials or tokens. */
public record SessionUserResponse(String username, String customerId, List<String> roles) {
}

package com.authentication.service;

import org.springframework.http.HttpStatus;

/** Business-rule failure with the HTTP status the controller should answer with. */
public class UserManagementException extends RuntimeException {

    private final HttpStatus status;

    public UserManagementException(HttpStatus status, String message) {
        super(message);
        this.status = status;
    }

    public HttpStatus getStatus() {
        return status;
    }
}

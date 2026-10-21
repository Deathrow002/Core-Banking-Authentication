package com.authentication.controller;

import java.util.List;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.authentication.models.request.UserCreatePayload;
import com.authentication.models.request.UserUpdatePayload;
import com.authentication.models.response.PageResponse;
import com.authentication.models.response.UserResponse;
import com.authentication.service.UserManagementException;
import com.authentication.service.UserManagementService;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;

/**
 * Staff-only management of login accounts. Session-based; ADMIN and MANAGER are allowed, and
 * creating, editing and deleting also need the role's PERM_ADD, PERM_EDIT and PERM_DELETE permission.
 * The per-account rules (MANAGER vs ADMIN, self-protection) live in {@link UserManagementService}.
 */
@RestController
@RequestMapping("/api/v1/auth/users")
@RequiredArgsConstructor
@PreAuthorize(UserManagementController.STAFF)
public class UserManagementController {

    static final String STAFF = "hasRole('ADMIN') or hasRole('MANAGER')";

    private static final Logger log = LoggerFactory.getLogger(UserManagementController.class);
    private static final String DEFAULT_PAGE_SIZE = "20";

    private final UserManagementService userManagementService;

    @GetMapping
    public PageResponse<UserResponse> list(Authentication actor,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = DEFAULT_PAGE_SIZE) int size) {
        return userManagementService.list(actor, page, size);
    }

    @GetMapping("/roles")
    public List<String> roles() {
        return userManagementService.roleNames();
    }

    @GetMapping("/{id}")
    public UserResponse get(Authentication actor, @PathVariable UUID id) {
        return userManagementService.get(actor, id);
    }

    @PreAuthorize("(" + STAFF + ") and hasAuthority('PERM_ADD')")
    @PostMapping
    public ResponseEntity<UserResponse> create(Authentication actor, @Valid @RequestBody UserCreatePayload payload) {
        UserResponse created = userManagementService.create(actor, payload);
        log.info("Login created by {} for {} with role {}", actor.getName(), created.email(), created.role());
        return ResponseEntity.status(HttpStatus.CREATED).body(created);
    }

    @PreAuthorize("(" + STAFF + ") and hasAuthority('PERM_EDIT')")
    @PutMapping("/{id}")
    public UserResponse update(Authentication actor, @PathVariable UUID id,
            @Valid @RequestBody UserUpdatePayload payload) {
        UserResponse updated = userManagementService.update(actor, id, payload);
        log.info("Login {} updated by {}", updated.id(), actor.getName());
        return updated;
    }

    @PreAuthorize("(" + STAFF + ") and hasAuthority('PERM_DELETE')")
    @DeleteMapping("/{id}")
    public ResponseEntity<Void> delete(Authentication actor, @PathVariable UUID id) {
        userManagementService.delete(actor, id);
        log.info("Login {} deleted by {}", id, actor.getName());
        return ResponseEntity.noContent().build();
    }

    @ExceptionHandler(UserManagementException.class)
    public ResponseEntity<String> handleRuleViolation(UserManagementException e) {
        return ResponseEntity.status(e.getStatus()).body(e.getMessage());
    }
}

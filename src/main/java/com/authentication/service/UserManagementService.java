package com.authentication.service;

import java.util.List;
import java.util.Objects;
import java.util.UUID;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import com.authentication.config.security.SessionAuthentication;
import com.authentication.models.Role;
import com.authentication.models.RoleNames;
import com.authentication.models.UserAuth;
import com.authentication.models.request.UserCreatePayload;
import com.authentication.models.request.UserRegisPayload;
import com.authentication.models.request.UserUpdatePayload;
import com.authentication.models.response.PageResponse;
import com.authentication.models.response.UserResponse;
import com.authentication.repository.UserAuthRepository;

import lombok.RequiredArgsConstructor;

/**
 * Staff management of login accounts. Rules, enforced here rather than in the controller:
 * <ul>
 *   <li>MANAGER cannot view, change, disable, delete or create/assign ADMIN accounts.</li>
 *   <li>A caller cannot delete, disable or change the role of their own login.</li>
 *   <li>At least one enabled ADMIN must always remain.</li>
 * </ul>
 * Self is identified by customerId, which is unique and immutable, so an email change does not break it.
 */
@Service
@RequiredArgsConstructor
public class UserManagementService {

    static final int MAX_PAGE_SIZE = 100;

    private final UserAuthRepository userAuthRepository;
    private final UserRegisService userRegisService;
    private final RoleService roleService;
    private final PasswordEncoder encoder;

    public PageResponse<UserResponse> list(Authentication actor, int page, int size) {
        Pageable pageable = PageRequest.of(Math.max(page, 0), clampSize(size), Sort.by("email").ascending());
        Page<UserAuth> users = isAdmin(actor)
                ? userAuthRepository.findAll(pageable)
                : userAuthRepository.findByRole_NameNot(RoleNames.ADMIN, pageable);
        return PageResponse.from(users, UserResponse::from);
    }

    public List<String> roleNames() {
        return roleService.list().stream().map(Role::getName).toList();
    }

    public UserResponse get(Authentication actor, UUID id) {
        UserAuth target = load(id);
        requireCanManage(actor, target);
        return UserResponse.from(target);
    }

    public UserResponse create(Authentication actor, UserCreatePayload payload) {
        Role role = roleService.require(StringUtils.hasText(payload.getRole()) ? payload.getRole() : RoleNames.CUSTOMER);
        requireCanAssign(actor, role);

        UserRegisPayload registration = UserRegisPayload.builder()
                .customerId(payload.getCustomerId())
                .email(payload.getEmail())
                .password(payload.getPassword())
                .build();
        try {
            return UserResponse.from(userRegisService.createLogin(registration, role));
        } catch (RuntimeException e) {
            // Duplicate email/customer and customer-validation failures are client errors, as on /register.
            throw new UserManagementException(HttpStatus.BAD_REQUEST, e.getMessage());
        }
    }

    @Transactional
    public UserResponse update(Authentication actor, UUID id, UserUpdatePayload payload) {
        UserAuth target = load(id);
        requireCanManage(actor, target);
        boolean self = isSelf(actor, target);

        if (payload.getEmail() != null) {
            changeEmail(target, payload.getEmail());
        }
        if (payload.getPassword() != null) {
            target.setPassword(encoder.encode(payload.getPassword()));
        }
        if (payload.getRole() != null && !payload.getRole().equals(target.getRoleName())) {
            Role role = roleService.require(payload.getRole());
            requireCanAssign(actor, role);
            if (self) {
                throw new UserManagementException(HttpStatus.BAD_REQUEST, "You cannot change your own role");
            }
            if (isAdminAccount(target)) {
                requireAnotherActiveAdmin(target);
            }
            target.setRole(role);
        }
        if (payload.getEnabled() != null && payload.getEnabled() != target.isEnabled()) {
            if (!payload.getEnabled()) {
                if (self) {
                    throw new UserManagementException(HttpStatus.BAD_REQUEST, "You cannot disable your own login");
                }
                if (isAdminAccount(target)) {
                    requireAnotherActiveAdmin(target);
                }
            }
            target.setEnabled(payload.getEnabled());
        }
        return UserResponse.from(userAuthRepository.save(target));
    }

    @Transactional
    public void delete(Authentication actor, UUID id) {
        UserAuth target = load(id);
        requireCanManage(actor, target);
        if (isSelf(actor, target)) {
            throw new UserManagementException(HttpStatus.BAD_REQUEST, "You cannot delete your own login");
        }
        if (isAdminAccount(target)) {
            requireAnotherActiveAdmin(target);
        }
        userAuthRepository.delete(target);
    }

    private void changeEmail(UserAuth target, String email) {
        if (!StringUtils.hasText(email)) {
            throw new UserManagementException(HttpStatus.BAD_REQUEST, "Email must not be blank");
        }
        if (email.equals(target.getEmail())) {
            return;
        }
        if (userAuthRepository.findByEmail(email).isPresent()) {
            throw new UserManagementException(HttpStatus.BAD_REQUEST, "User already exists with email: " + email);
        }
        target.setEmail(email);
    }

    /** Blocks removing the last enabled ADMIN by demotion, disable or delete. Disabled admins are not counted. */
    private void requireAnotherActiveAdmin(UserAuth target) {
        if (!target.isEnabled()) {
            return;
        }
        if (userAuthRepository.countByRole_NameAndEnabled(RoleNames.ADMIN, true) <= 1) {
            throw new UserManagementException(HttpStatus.BAD_REQUEST, "At least one active ADMIN account must remain");
        }
    }

    private UserAuth load(UUID id) {
        return userAuthRepository.findById(id)
                .orElseThrow(() -> new UserManagementException(HttpStatus.NOT_FOUND, "User not found: " + id));
    }

    /** MANAGER may only act on non-ADMIN accounts. Reported as 403 so the rule is explicit. */
    private void requireCanManage(Authentication actor, UserAuth target) {
        if (isAdminAccount(target) && !isAdmin(actor)) {
            throw new UserManagementException(HttpStatus.FORBIDDEN, "Managers cannot manage ADMIN accounts");
        }
    }

    private void requireCanAssign(Authentication actor, Role role) {
        if (RoleNames.ADMIN.equals(role.getName()) && !isAdmin(actor)) {
            throw new UserManagementException(HttpStatus.FORBIDDEN, "Managers cannot assign the ADMIN role");
        }
    }

    private static boolean isAdminAccount(UserAuth user) {
        return RoleNames.ADMIN.equals(user.getRoleName());
    }

    private static boolean isAdmin(Authentication actor) {
        return actor.getAuthorities().stream().anyMatch(a -> "ROLE_ADMIN".equals(a.getAuthority()));
    }

    private static boolean isSelf(Authentication actor, UserAuth target) {
        return target.getCustomerId() != null
                && Objects.equals(SessionAuthentication.detail(actor, SessionAuthentication.DETAIL_CUSTOMER_ID),
                        target.getCustomerId().toString());
    }

    private static int clampSize(int size) {
        return Math.min(Math.max(size, 1), MAX_PAGE_SIZE);
    }
}

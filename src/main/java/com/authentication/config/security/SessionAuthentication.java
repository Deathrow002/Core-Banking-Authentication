package com.authentication.config.security;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import com.authentication.models.UserAuth;

/**
 * Builds the {@link Authentication} stored in the shared Redis session.
 *
 * <p>Every Core Banking service deserializes this object from Redis with JDK serialization, so it
 * must contain only Spring Security / JDK types: the principal is the username {@link String} and
 * the details are a {@link HashMap} with {@code username}, {@code customerId} and {@code role}.
 * Never store {@link UserAuth} (or any other service-specific class) in the session.
 */
public final class SessionAuthentication {

    public static final String DETAIL_USERNAME = "username";
    public static final String DETAIL_CUSTOMER_ID = "customerId";
    public static final String DETAIL_ROLE = "role";

    private SessionAuthentication() {
    }

    public static Authentication from(UserAuth user) {
        String role = "ROLE_" + user.getRole().name();
        List<GrantedAuthority> authorities = List.of(new SimpleGrantedAuthority(role));

        UsernamePasswordAuthenticationToken token =
                UsernamePasswordAuthenticationToken.authenticated(user.getUsername(), null, authorities);

        Map<String, Object> details = new HashMap<>();
        details.put(DETAIL_USERNAME, user.getUsername());
        details.put(DETAIL_CUSTOMER_ID, user.getCustomerId() != null ? user.getCustomerId().toString() : null);
        details.put(DETAIL_ROLE, role);
        token.setDetails(details);
        return token;
    }

    @SuppressWarnings("unchecked")
    public static String detail(Authentication authentication, String key) {
        if (authentication != null && authentication.getDetails() instanceof Map<?, ?> details) {
            Object value = ((Map<String, Object>) details).get(key);
            return value != null ? value.toString() : null;
        }
        return null;
    }
}

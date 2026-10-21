package com.authentication.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import com.authentication.models.Role;
import com.authentication.models.RoleNames;
import com.authentication.models.UserAuth;
import com.authentication.models.request.UserRegisPayload;
import com.authentication.repository.UserAuthRepository;

import io.github.resilience4j.circuitbreaker.annotation.CircuitBreaker;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class UserRegisService implements UserDetailsService{

    private final Logger log = LoggerFactory.getLogger(UserRegisService.class);

    private final String CUSTOMER_SERVICE_URL = "http://CUSTOMER-SERVICE/customers/";

    private final UserAuthRepository userAuthRepository;

    private final PasswordEncoder encoder;

    private final RestTemplate restTemplate;

    private final RoleService roleService;

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        return userAuthRepository.findByEmail(email)
            .orElseThrow(() -> new UsernameNotFoundException("User not found with email: " + email));
    }

    @CircuitBreaker(name = "customerService", fallbackMethod = "customerServiceFallback")
    public UserAuth registerUser(UserRegisPayload user) {
        return saveLogin(user, roleService.require(RoleNames.CUSTOMER));
    }

    /** Staff create path: same checks as {@link #registerUser}, with a role chosen by the caller. */
    @CircuitBreaker(name = "customerService", fallbackMethod = "createLoginFallback")
    public UserAuth createLogin(UserRegisPayload user, Role role) {
        return saveLogin(user, role);
    }

    private UserAuth saveLogin(UserRegisPayload user, Role role) {
        try {
            UserAuth userAuth = new UserAuth();

            // Check if user already exists
            if (userAuthRepository.findByEmail(user.getEmail()).isPresent()) {
                log.error("User already exists with email: {}", user.getEmail());
                throw new RuntimeException("User already exists with email: " + user.getEmail());
            }

            // customer_id is unique, so one customer can only have one login
            if (userAuthRepository.existsByCustomerId(user.getCustomerId())) {
                log.error("Login already exists for customer: {}", user.getCustomerId());
                throw new RuntimeException("A login already exists for customer: " + user.getCustomerId());
            }

            // Check if customer exists
            String url = UriComponentsBuilder
                .fromUriString(CUSTOMER_SERVICE_URL + "validateByData")
                .queryParam("customerId", user.getCustomerId())
                .queryParam("email", user.getEmail())
                .toUriString();

            // The caller's SESSION cookie is forwarded by SessionForwardingInterceptor.
            ResponseEntity<Boolean> response = restTemplate.getForEntity(url, Boolean.class);

            Boolean customerExists = response.getBody();
            if (customerExists == null || !customerExists) {
                log.error("Customer not found with id: {}", user.getCustomerId());
                throw new RuntimeException("Customer not found with id: " + user.getCustomerId());
            }

            userAuth.setEmail(user.getEmail());
            userAuth.setPassword(encoder.encode(user.getPassword()));
            userAuth.setCustomerId(user.getCustomerId());
            userAuth.setRole(role);
            userAuth.setAccountNonExpired(true);
            userAuth.setAccountNonLocked(true);
            userAuth.setCredentialsNonExpired(true);

            UserAuth saved = userAuthRepository.save(userAuth);
            log.info("Saved user: {} for customer {}", saved.getEmail(), saved.getCustomerId());
            return saved;
        } catch (DataIntegrityViolationException e) {
            throw new RuntimeException("Database error while registering user: " + e.getMessage());
        } catch (RestClientException e) {
            throw new RuntimeException("Error validating customer: " + e.getMessage());
        } catch (IllegalArgumentException e) {
            throw new RuntimeException("Invalid data provided: " + e.getMessage());
        }
    }

    public UserAuth customerServiceFallback(UserRegisPayload user, Throwable t) {
        log.error("Fallback triggered for registerUser: Customer service unavailable. customerId={}, error={}", user.getCustomerId(), t.getMessage());
        throw new RuntimeException("Customer service unavailable, please try again later");
    }

    public UserAuth createLoginFallback(UserRegisPayload user, Role role, Throwable t) {
        return customerServiceFallback(user, t);
    }
}

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

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        return userAuthRepository.findByEmail(email)
            .orElseThrow(() -> new UsernameNotFoundException("User not found with email: " + email));
    }

    @CircuitBreaker(name = "customerService", fallbackMethod = "customerServiceFallback")
    public UserDetails registerUser(UserRegisPayload user) {
        try {
            UserAuth userAuth = new UserAuth();

            // Check if user already exists
            if (userAuthRepository.findByEmail(user.getEmail()).isPresent()) {
                log.error("User already exists with email: {}", user.getEmail());
                throw new RuntimeException("User already exists with email: " + user.getEmail());
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
            userAuth.setRole(Role.USER);
            userAuth.setAccountNonExpired(true);
            userAuth.setAccountNonLocked(true);
            userAuth.setCredentialsNonExpired(true);

            // Save user
            log.info("Saving user: {}", userAuth);
            return userAuthRepository.save(userAuth);
        } catch (DataIntegrityViolationException e) {
            throw new RuntimeException("Database error while registering user: " + e.getMessage());
        } catch (RestClientException e) {
            throw new RuntimeException("Error validating customer: " + e.getMessage());
        } catch (IllegalArgumentException e) {
            throw new RuntimeException("Invalid data provided: " + e.getMessage());
        }
    }

    public UserDetails customerServiceFallback(UserRegisPayload user, Throwable t) {
        log.error("Fallback triggered for registerUser: Customer service unavailable. customerId={}, error={}", user.getCustomerId(), t.getMessage());
        throw new RuntimeException("Customer service unavailable, please try again later");
    }
}

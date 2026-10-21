package com.authentication.config.oauth;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidationException;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.context.NullSecurityContextRepository;
import org.springframework.security.web.savedrequest.NullRequestCache;

import com.authentication.models.Permissions;

@Configuration
public class MobileResourceConfig {

    @Bean
    @Order(3)
    SecurityFilterChain mobileSecurity(HttpSecurity http,
            @Qualifier("authorizationJwtDecoder") JwtDecoder signatureDecoder,
            @Value("${app.oauth.issuer}") String issuer) throws Exception {
        OAuth2TokenValidator<Jwt> audience = jwt -> jwt.getAudience().contains("core-banking-api")
                ? OAuth2TokenValidatorResult.success()
                : OAuth2TokenValidatorResult.failure(new OAuth2Error("invalid_token", "Invalid audience", null));
        var validator = new DelegatingOAuth2TokenValidator<>(JwtValidators.createDefaultWithIssuer(issuer), audience);
        JwtDecoder decoder = token -> {
            Jwt jwt = signatureDecoder.decode(token);
            var result = validator.validate(jwt);
            if (result.hasErrors()) {
                throw new JwtValidationException("Invalid mobile access token", result.getErrors());
            }
            return jwt;
        };
        return http.securityMatcher("/api/mobile/**")
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .securityContext(context -> context.securityContextRepository(new NullSecurityContextRepository()))
                .requestCache(cache -> cache.requestCache(new NullRequestCache()))
                .csrf(csrf -> csrf.disable())
                .formLogin(login -> login.disable())
                .httpBasic(basic -> basic.disable())
                .logout(logout -> logout.disable())
                .authorizeHttpRequests(requests -> requests.anyRequest().hasAuthority("SCOPE_banking"))
                .oauth2ResourceServer(resource -> resource.jwt(jwt -> jwt.decoder(decoder)
                        .jwtAuthenticationConverter(MobileResourceConfig::authentication)))
                .build();
    }

    static JwtAuthenticationToken authentication(Jwt jwt) {
        var authorities = new ArrayList<>(new JwtGrantedAuthoritiesConverter().convert(jwt));
        String role = jwt.getClaimAsString("role");
        if (role != null && role.matches("ROLE_(ADMIN|MANAGER|CUSTOMER)")) {
            authorities.add(new SimpleGrantedAuthority(role));
        }
        List<String> permissions = jwt.getClaimAsStringList("permissions");
        if (permissions != null) {
            permissions.stream().filter(Permissions.ALL::contains).distinct()
                    .forEach(permission -> authorities.add(new SimpleGrantedAuthority(permission)));
        }
        var authentication = new JwtAuthenticationToken(jwt, authorities, jwt.getSubject());
        Map<String, Object> details = new HashMap<>();
        details.put("username", jwt.getSubject());
        details.put("customerId", jwt.getClaimAsString("customerId"));
        details.put("role", role);
        authentication.setDetails(details);
        return authentication;
    }
}

package com.authentication.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.HttpStatusReturningLogoutSuccessHandler;
import org.springframework.security.web.context.SecurityContextRepository;

import com.authentication.config.security.RestAuthenticationEntryPoint;
import com.authentication.config.security.SessionConfig;
import com.authentication.service.UserAuthService;

import lombok.RequiredArgsConstructor;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true) // Enable method-level security (e.g., @PreAuthorize)
@RequiredArgsConstructor
public class WebSecurityConfig {

    public static final String LOGIN_URL = "/api/v1/auth/login";
    public static final String LOGOUT_URL = "/api/v1/auth/logout";
    public static final String CSRF_URL = "/api/v1/auth/csrf";

    @Lazy
    private final UserAuthService userAuthService;

    private final RestAuthenticationEntryPoint unauthorizedHandler;

    private final SecurityContextRepository securityContextRepository;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
            // Session cookies are sent automatically by browsers, so CSRF protection is required.
            // spa() = XSRF-TOKEN cookie readable by the SPA, echoed back in the X-XSRF-TOKEN header.
            .csrf(csrf -> csrf.spa())
            .exceptionHandling(exception -> exception.authenticationEntryPoint(unauthorizedHandler))
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED))
            .securityContext(context -> context.securityContextRepository(securityContextRepository))
            .authorizeHttpRequests(auth -> auth
                .requestMatchers(HttpMethod.POST, LOGIN_URL).permitAll()
                .requestMatchers(HttpMethod.GET, CSRF_URL).permitAll()
                .requestMatchers("/actuator/health", "/actuator/prometheus", "/actuator/info").permitAll()
                .anyRequest().authenticated()
            )
            .logout(logout -> logout
                .logoutUrl(LOGOUT_URL)
                .invalidateHttpSession(true)
                .clearAuthentication(true)
                .deleteCookies(SessionConfig.SESSION_COOKIE_NAME)
                .logoutSuccessHandler(new HttpStatusReturningLogoutSuccessHandler(HttpStatus.NO_CONTENT))
            )
            .formLogin(form -> form.disable())
            .httpBasic(basic -> basic.disable())
            .authenticationProvider(authenticationProvider())
            .build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider(userAuthService);
        authProvider.setPasswordEncoder(passwordEncoder());
        return authProvider;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }
}

package com.authentication.config.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.session.web.http.CookieSerializer;
import org.springframework.session.web.http.DefaultCookieSerializer;

/**
 * Shared session cookie settings. All Core Banking services (servlet and WebFlux) must agree on
 * these so that one {@code SESSION} cookie authenticates the user everywhere.
 */
@Configuration
public class SessionConfig {

    public static final String SESSION_COOKIE_NAME = "SESSION";

    @Bean
    public CookieSerializer cookieSerializer(
            @Value("${app.session.cookie.secure:false}") boolean secure,
            @Value("${app.session.cookie.same-site:Lax}") String sameSite) {
        DefaultCookieSerializer serializer = new DefaultCookieSerializer();
        serializer.setCookieName(SESSION_COOKIE_NAME);
        serializer.setCookiePath("/");
        serializer.setUseHttpOnlyCookie(true);
        serializer.setUseSecureCookie(secure);
        serializer.setSameSite(sameSite);
        // WebFlux services read the raw session id, so the servlet default (Base64) must be disabled.
        serializer.setUseBase64Encoding(false);
        return serializer;
    }

    @Bean
    public SecurityContextRepository securityContextRepository() {
        return new HttpSessionSecurityContextRepository();
    }
}

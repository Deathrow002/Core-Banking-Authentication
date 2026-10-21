package com.authentication.config.oauth;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.List;
import java.util.ArrayList;
import java.util.UUID;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.ClassPathResource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.context.SecurityContextRepository;

import com.authentication.config.security.SessionAuthentication;
import com.authentication.models.UserAuth;
import com.authentication.service.UserAuthService;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

@Configuration
public class AuthorizationServerConfig {

    @Bean
    @Order(1)
    SecurityFilterChain authorizationEndpoints(HttpSecurity http, SecurityContextRepository contextRepository)
            throws Exception {
        var authorizationServer = new OAuth2AuthorizationServerConfigurer();
        return http
                .securityMatcher(authorizationServer.getEndpointsMatcher())
                .with(authorizationServer, server -> server.oidc(Customizer.withDefaults()))
                .requestCache(cache -> cache.requestCache(new PortableAuthorizationRequestCache()))
                .securityContext(context -> context.securityContextRepository(contextRepository))
                .authorizeHttpRequests(requests -> requests.anyRequest().authenticated())
                .exceptionHandling(exceptions -> exceptions.authenticationEntryPoint(
                        new LoginUrlAuthenticationEntryPoint("/oauth/login")))
                .oauth2ResourceServer(resource -> resource.jwt(Customizer.withDefaults()))
                .build();
    }

    @Bean
    @Order(2)
    SecurityFilterChain authorizationLogin(HttpSecurity http, UserAuthService users, PasswordEncoder encoder,
            SecurityContextRepository contextRepository) throws Exception {
        var delegate = new DaoAuthenticationProvider(users);
        delegate.setPasswordEncoder(encoder);
        // Only portable Spring/JDK values may enter the shared Redis security context.
        AuthenticationProvider portableProvider = new AuthenticationProvider() {
            @Override
            public Authentication authenticate(Authentication authentication) throws AuthenticationException {
                Authentication verified = delegate.authenticate(authentication);
                return SessionAuthentication.from((UserAuth) verified.getPrincipal());
            }

            @Override
            public boolean supports(Class<?> authentication) {
                return delegate.supports(authentication);
            }
        };
        return http.securityMatcher("/oauth/login")
                .requestCache(cache -> cache.requestCache(new PortableAuthorizationRequestCache()))
                .securityContext(context -> context.securityContextRepository(contextRepository))
                .authorizeHttpRequests(requests -> requests.anyRequest().permitAll())
                .authenticationProvider(portableProvider)
                .formLogin(login -> login.loginPage("/oauth/login").loginProcessingUrl("/oauth/login"))
                .build();
    }

    @Bean
    JdbcTemplate oauthJdbcTemplate(DataSource dataSource) throws Exception {
        var jdbc = new JdbcTemplate(dataSource);
        String base = "org/springframework/security/oauth2/server/authorization/";
        for (String resource : List.of("client/oauth2-registered-client-schema.sql",
                "oauth2-authorization-schema.sql", "oauth2-authorization-consent-schema.sql")) {
            String sql = new ClassPathResource(base + resource).getContentAsString(StandardCharsets.UTF_8)
                    .replaceAll("(?s)/\\*.*?\\*/", "")
                    .replace("CREATE TABLE ", "CREATE TABLE IF NOT EXISTS ")
                    .replace(" blob", " text").replace(" timestamp", " timestamptz");
            jdbc.execute(sql);
        }
        jdbc.execute("""
                CREATE TABLE IF NOT EXISTS oauth2_signing_key (
                    id varchar(100) PRIMARY KEY,
                    jwk text NOT NULL
                )
                """);
        return jdbc;
    }

    @Bean
    RegisteredClientRepository registeredClientRepository(
            @Qualifier("oauthJdbcTemplate") JdbcTemplate jdbc,
            @Value("${app.oauth.mobile.redirect-uri}") String redirectUri) {
        var repository = new JdbcRegisteredClientRepository(jdbc);
        RegisteredClient mobile = RegisteredClient.withId("core-banking-mobile")
                .clientId("core-banking-mobile")
                .clientName("Core Banking Mobile")
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri(redirectUri)
                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.PROFILE)
                .scope("banking")
                .scope("transactions.write")
                .clientSettings(ClientSettings.builder().requireProofKey(true)
                        .requireAuthorizationConsent(false).build())
                .tokenSettings(TokenSettings.builder().accessTokenTimeToLive(Duration.ofMinutes(5))
                        .authorizationCodeTimeToLive(Duration.ofMinutes(2)).build())
                .build();
        repository.save(mobile);
        return repository;
    }

    @Bean
    OAuth2AuthorizationService authorizationService(@Qualifier("oauthJdbcTemplate") JdbcTemplate jdbc,
            RegisteredClientRepository clients) {
        return new JdbcOAuth2AuthorizationService(jdbc, clients);
    }

    @Bean
    OAuth2AuthorizationConsentService consentService(@Qualifier("oauthJdbcTemplate") JdbcTemplate jdbc,
            RegisteredClientRepository clients) {
        return new JdbcOAuth2AuthorizationConsentService(jdbc, clients);
    }

    @Bean
    JWKSource<SecurityContext> jwkSource(@Qualifier("oauthJdbcTemplate") JdbcTemplate jdbc) throws Exception {
        List<String> existing = jdbc.queryForList(
                "SELECT jwk FROM oauth2_signing_key WHERE id = 'active'", String.class);
        if (existing.isEmpty()) {
            var generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(3072);
            KeyPair pair = generator.generateKeyPair();
            var key = new RSAKey.Builder((RSAPublicKey) pair.getPublic())
                    .privateKey((RSAPrivateKey) pair.getPrivate()).keyID(UUID.randomUUID().toString()).build();
            // A second starting replica must use the winner's key, not its own generated key.
            jdbc.update("INSERT INTO oauth2_signing_key (id, jwk) VALUES ('active', ?) ON CONFLICT DO NOTHING",
                    key.toJSONString());
        }
        var keySet = new JWKSet(RSAKey.parse(jdbc.queryForObject(
                "SELECT jwk FROM oauth2_signing_key WHERE id = 'active'", String.class)));
        return (selector, context) -> selector.select(keySet);
    }

    @Bean
    JwtDecoder authorizationJwtDecoder(JWKSource<SecurityContext> source) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(source);
    }

    @Bean
    AuthorizationServerSettings authorizationServerSettings(@Value("${app.oauth.issuer}") String issuer) {
        return AuthorizationServerSettings.builder().issuer(issuer).build();
    }

    @Bean
    OAuth2TokenCustomizer<JwtEncodingContext> identityClaims(UserAuthService users) {
        return context -> {
            UserAuth user = (UserAuth) users.loadUserByUsername(context.getPrincipal().getName());
            if (!user.isEnabled() || !user.isAccountNonLocked() || !user.isAccountNonExpired()
                    || !user.isCredentialsNonExpired()) {
                throw new OAuth2AuthenticationException(new OAuth2Error("access_denied"));
            }
            context.getClaims().subject(user.getUsername());
            context.getClaims().claim("role", "ROLE_" + user.getRoleName());
            context.getClaims().claim("permissions", user.getRole().permissionAuthorities());
            if (user.getCustomerId() != null) {
                context.getClaims().claim("customerId", user.getCustomerId().toString());
            }
            if ("access_token".equals(context.getTokenType().getValue())) {
                context.getClaims().audience(new ArrayList<>(List.of("core-banking-api")));
            }
        };
    }
}

package com.authentication.config.oauth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.core.annotation.Order;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit.jupiter.web.SpringJUnitWebConfig;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.util.UriComponentsBuilder;

import com.authentication.config.WebSecurityConfig;
import com.authentication.config.security.RestAuthenticationEntryPoint;
import com.authentication.config.security.SessionAuthentication;
import com.authentication.controller.AuthController;
import com.authentication.controller.MobileAuthController;
import com.authentication.controller.OAuthLoginController;
import com.authentication.models.Role;
import com.authentication.models.RoleNames;
import com.authentication.models.UserAuth;
import com.authentication.service.SessionAuthService;
import com.authentication.service.UserAuthService;
import com.authentication.service.UserRegisService;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

@SpringJUnitWebConfig(DualAuthenticationTest.TestConfig.class)
@TestPropertySource(properties = "app.oauth.issuer=http://localhost:8080")
class DualAuthenticationTest {

    private static final String ISSUER = "http://localhost:8080";
    private static final String CALLBACK = "com.corebanking.mobile:/oauth2/callback";
    private static final String VERIFIER = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~";
    private static final UserAuth USER = UserAuth.builder().email("mobile@example.com")
            .password(new BCryptPasswordEncoder().encode("test-password"))
            .customerId(UUID.randomUUID()).role(new Role(RoleNames.ADMIN, true, true, true)).build();

    @Configuration
    @EnableWebMvc
    @Import({WebSecurityConfig.class, MobileResourceConfig.class, RestAuthenticationEntryPoint.class,
            AuthController.class, MobileAuthController.class, OAuthLoginController.class, SessionAuthService.class})
    static class TestConfig {
        private final AuthorizationServerConfig server = new AuthorizationServerConfig();

        @Bean SecurityContextRepository securityContextRepository() {
            return new HttpSessionSecurityContextRepository();
        }
        @Bean UserAuthService userAuthService() {
            var users = org.mockito.Mockito.mock(UserAuthService.class);
            org.mockito.Mockito.when(users.loadUserByUsername(USER.getUsername())).thenReturn(USER);
            return users;
        }
        @Bean UserRegisService userRegisService() { return org.mockito.Mockito.mock(UserRegisService.class); }
        @Bean @Order(1) SecurityFilterChain authorizationEndpoints(HttpSecurity http,
                SecurityContextRepository repository) throws Exception {
            return server.authorizationEndpoints(http, repository);
        }
        @Bean @Order(2) SecurityFilterChain authorizationLogin(HttpSecurity http, UserAuthService users,
                PasswordEncoder encoder, SecurityContextRepository repository) throws Exception {
            return server.authorizationLogin(http, users, encoder, repository);
        }
        @Bean RegisteredClientRepository clients() {
            return new InMemoryRegisteredClientRepository(RegisteredClient.withId("mobile")
                    .clientId("core-banking-mobile").clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE).redirectUri(CALLBACK)
                    .scope("openid").scope("profile").scope("banking").scope("transactions.write")
                    .clientSettings(ClientSettings.builder().requireProofKey(true).build()).build());
        }
        @Bean OAuth2AuthorizationService authorizations() { return new InMemoryOAuth2AuthorizationService(); }
        @Bean OAuth2AuthorizationConsentService consents() { return new InMemoryOAuth2AuthorizationConsentService(); }
        @Bean AuthorizationServerSettings settings() { return server.authorizationServerSettings(ISSUER); }
        @Bean JWKSource<SecurityContext> keys() throws Exception {
            var generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            var pair = generator.generateKeyPair();
            var keys = new JWKSet(new RSAKey.Builder((RSAPublicKey) pair.getPublic())
                    .privateKey((RSAPrivateKey) pair.getPrivate()).keyID("test-key").build());
            return (selector, context) -> selector.select(keys);
        }
        @Bean JwtDecoder authorizationJwtDecoder(JWKSource<SecurityContext> keys) {
            return server.authorizationJwtDecoder(keys);
        }
        @Bean OAuth2TokenCustomizer<JwtEncodingContext> claims(UserAuthService users) {
            return server.identityClaims(users);
        }
    }

    @Autowired WebApplicationContext context;
    @Autowired JwtDecoder authorizationJwtDecoder;
    @Autowired JWKSource<SecurityContext> keys;
    @Autowired OAuth2AuthorizationService authorizations;
    private MockMvc mvc;

    @BeforeEach void setUp() {
        mvc = MockMvcBuilders.webAppContextSetup(context)
                .apply(org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity())
                .build();
    }

    private MockHttpSession session() {
        var session = new MockHttpSession();
        session.setAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY,
                new SecurityContextImpl(SessionAuthentication.from(USER)));
        return session;
    }

    private String authorize(MockHttpSession session, String challenge) throws Exception {
        MvcResult result = mvc.perform(get("/oauth2/authorize").session(session)
                .queryParam("response_type", "code").queryParam("client_id", "core-banking-mobile")
                .queryParam("redirect_uri", CALLBACK).queryParam("scope", "openid banking transactions.write")
                .queryParam("state", UUID.randomUUID().toString())
                .queryParam("code_challenge", challenge).queryParam("code_challenge_method", "S256"))
                .andExpect(status().is3xxRedirection()).andReturn();
        return UriComponentsBuilder.fromUriString(result.getResponse().getRedirectedUrl())
                .build().getQueryParams().getFirst("code");
    }

    private String challenge() throws Exception {
        return Base64.getUrlEncoder().withoutPadding()
                .encodeToString(MessageDigest.getInstance("SHA-256").digest(VERIFIER.getBytes(StandardCharsets.US_ASCII)));
    }

    @Test void pkceIssuesIdentityTokenAndCodeCannotBeReplayed() throws Exception {
        String code = authorize(session(), challenge());
        assertThat(code).isNotBlank();
        MvcResult result = mvc.perform(post("/oauth2/token")
                .param("grant_type", "authorization_code").param("client_id", "core-banking-mobile")
                .param("code", code).param("redirect_uri", CALLBACK).param("code_verifier", VERIFIER))
                .andExpect(status().isOk()).andReturn();
        var json = tools.jackson.databind.json.JsonMapper.builder().build().readTree(result.getResponse().getContentAsString());
        assertThat(json.has("refresh_token")).isFalse();
        var jwt = authorizationJwtDecoder.decode(json.get("access_token").asText());
        assertThat(jwt.getSubject()).isEqualTo(USER.getUsername());
        assertThat(jwt.getAudience()).containsExactly("core-banking-api");
        assertThat(jwt.getClaimAsString("role")).isEqualTo("ROLE_ADMIN");
        assertThat(jwt.getClaimAsStringList("permissions")).containsExactly("PERM_ADD", "PERM_EDIT", "PERM_DELETE");
        assertThat(jwt.getClaimAsString("customerId")).isEqualTo(USER.getCustomerId().toString());
        assertThat(jwt.getClaimAsStringList("scope")).contains("transactions.write");
        mvc.perform(get("/api/mobile/api/v1/auth/me")
                .header("Authorization", "Bearer " + json.get("access_token").asText()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.roles").value(org.hamcrest.Matchers.hasItem("ROLE_ADMIN")))
                .andExpect(jsonPath("$.permissions").value(
                        org.hamcrest.Matchers.containsInAnyOrder("PERM_ADD", "PERM_EDIT", "PERM_DELETE")));
        mvc.perform(post("/oauth2/token").param("grant_type", "authorization_code")
                .param("client_id", "core-banking-mobile").param("code", code)
                .param("redirect_uri", CALLBACK).param("code_verifier", VERIFIER))
                .andExpect(status().isBadRequest());
    }

    @Test void incorrectPkceVerifierIsRejected() throws Exception {
        String code = authorize(session(), challenge());
        mvc.perform(post("/oauth2/token").param("grant_type", "authorization_code")
                .param("client_id", "core-banking-mobile").param("code", code)
                .param("redirect_uri", CALLBACK).param("code_verifier", VERIFIER + "wrong"))
                .andExpect(status().isBadRequest());
    }

    @Test void mobileLogoutRemovesGrantButDoesNotPretendToImmediatelyRevokeSelfContainedJwt() throws Exception {
        String code = authorize(session(), challenge());
        MvcResult result = mvc.perform(post("/oauth2/token")
                .param("grant_type", "authorization_code").param("client_id", "core-banking-mobile")
                .param("code", code).param("redirect_uri", CALLBACK).param("code_verifier", VERIFIER))
                .andExpect(status().isOk()).andReturn();
        String accessToken = tools.jackson.databind.json.JsonMapper.builder().build()
                .readTree(result.getResponse().getContentAsString()).get("access_token").asText();
        assertThat(authorizations.findByToken(accessToken,
                org.springframework.security.oauth2.server.authorization.OAuth2TokenType.ACCESS_TOKEN)).isNotNull();
        mvc.perform(post("/api/mobile/api/v1/auth/logout").header("Authorization", "Bearer " + accessToken))
                .andExpect(status().isNoContent());
        assertThat(authorizations.findByToken(accessToken,
                org.springframework.security.oauth2.server.authorization.OAuth2TokenType.ACCESS_TOKEN)).isNull();
        mvc.perform(get("/api/mobile/api/v1/auth/me").header("Authorization", "Bearer " + accessToken))
                .andExpect(status().isOk());
    }

    @Test void missingPkceChallengeIsRejected() throws Exception {
        MvcResult result = mvc.perform(get("/oauth2/authorize").session(session())
                .queryParam("response_type", "code").queryParam("client_id", "core-banking-mobile")
                .queryParam("redirect_uri", CALLBACK).queryParam("scope", "openid banking"))
                .andExpect(status().is3xxRedirection()).andReturn();
        assertThat(result.getResponse().getRedirectedUrl()).contains("error=invalid_request");
    }

    @Test void plainPkceAndUnregisteredRedirectAreRejected() throws Exception {
        MvcResult plain = mvc.perform(get("/oauth2/authorize").session(session())
                .queryParam("response_type", "code").queryParam("client_id", "core-banking-mobile")
                .queryParam("redirect_uri", CALLBACK).queryParam("scope", "openid banking")
                .queryParam("code_challenge", VERIFIER).queryParam("code_challenge_method", "plain"))
                .andExpect(status().is3xxRedirection()).andReturn();
        assertThat(plain.getResponse().getRedirectedUrl()).contains("error=invalid_request");
        MvcResult wrongCallback = mvc.perform(get("/oauth2/authorize").session(session())
                .queryParam("response_type", "code").queryParam("client_id", "core-banking-mobile")
                .queryParam("redirect_uri", "com.attacker:/callback").queryParam("scope", "openid banking")
                .queryParam("code_challenge", challenge()).queryParam("code_challenge_method", "S256"))
                .andExpect(status().isBadRequest()).andReturn();
        assertThat(wrongCallback.getResponse().getRedirectedUrl()).isNull();
    }

    @Test void browserLoginUsesExistingPasswordAndStoresPortablePrincipal() throws Exception {
        MvcResult page = mvc.perform(get("/oauth/login")).andExpect(status().isOk()).andReturn();
        CsrfToken csrf = (CsrfToken) page.getRequest().getAttribute(CsrfToken.class.getName());
        MockHttpSession beforeLogin = (MockHttpSession) page.getRequest().getSession();
        String originalId = beforeLogin.getId();
        MvcResult login = mvc.perform(post("/oauth/login").session(beforeLogin)
                .param("username", USER.getUsername()).param("password", "test-password")
                .param(csrf.getParameterName(), csrf.getToken()))
                .andExpect(status().is3xxRedirection()).andReturn();
        var current = (MockHttpSession) login.getRequest().getSession(false);
        assertThat(current.getId()).isNotEqualTo(originalId);
        var stored = (org.springframework.security.core.context.SecurityContext) current.getAttribute(
                HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);
        assertThat(stored.getAuthentication().getPrincipal()).isEqualTo(USER.getUsername());
        mvc.perform(get("/api/v1/auth/me").session(current)).andExpect(status().isOk());
    }

    @Test void cookiesCannotAuthenticateMobileAndBearerCannotAuthenticateWeb() throws Exception {
        mvc.perform(get("/api/mobile/api/v1/auth/me").session(session())).andExpect(status().isUnauthorized());
        String bearer = token(ISSUER, "core-banking-api", Instant.now().plusSeconds(300), "banking");
        mvc.perform(get("/api/v1/auth/me").header("Authorization", "Bearer " + bearer))
                .andExpect(status().isUnauthorized());
        mvc.perform(post("/api/v1/auth/logout").session(session()).header("Authorization", "Bearer " + bearer))
                .andExpect(status().isForbidden());
    }

    @Test void jwtExpiryIssuerAudienceAndScopeAreEnforced() throws Exception {
        for (String invalid : List.of(
                token(ISSUER, "core-banking-api", Instant.now().minusSeconds(120), "banking"),
                token("https://wrong-issuer", "core-banking-api", Instant.now().plusSeconds(300), "banking"),
                token(ISSUER, "wrong-audience", Instant.now().plusSeconds(300), "banking"))) {
            mvc.perform(get("/api/mobile/api/v1/auth/me").header("Authorization", "Bearer " + invalid))
                    .andExpect(status().isUnauthorized());
        }
        mvc.perform(get("/api/mobile/api/v1/auth/me").header("Authorization", "Bearer " +
                token(ISSUER, "core-banking-api", Instant.now().plusSeconds(300), "profile")))
                .andExpect(status().isForbidden());
    }

    @Test void lostOrExpiredSessionDoesNotRestoreAuthentication() throws Exception {
        mvc.perform(get("/api/v1/auth/me").cookie(new jakarta.servlet.http.Cookie("SESSION", "expired-id")))
                .andExpect(status().isUnauthorized());
        mvc.perform(get("/api/mobile/api/v1/auth/me")).andExpect(status().isUnauthorized());
    }

    private String token(String issuer, String audience, Instant expiry, String scope) {
        var claims = JwtClaimsSet.builder().issuer(issuer).subject(USER.getUsername())
                .audience(List.of(audience)).issuedAt(Instant.now().minusSeconds(180)).expiresAt(expiry)
                .claim("role", "ROLE_ADMIN").claim("customerId", USER.getCustomerId().toString())
                .claim("scope", scope).build();
        return new NimbusJwtEncoder(keys).encode(JwtEncoderParameters.from(claims)).getTokenValue();
    }
}

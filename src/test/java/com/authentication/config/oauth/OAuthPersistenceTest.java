package com.authentication.config.oauth;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import org.h2.jdbcx.JdbcDataSource;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;

import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;

class OAuthPersistenceTest {

    @Test
    void repositoriesAndSigningKeySurviveRecreationAndTokenMetadataCanBeDeserialized() throws Exception {
        var source = new JdbcDataSource();
        source.setURL("jdbc:h2:mem:" + UUID.randomUUID() + ";MODE=PostgreSQL;DB_CLOSE_DELAY=-1");
        new JdbcTemplate(source).execute("CREATE DOMAIN TIMESTAMPTZ AS TIMESTAMP WITH TIME ZONE");
        var config = new AuthorizationServerConfig();
        var jdbc = config.oauthJdbcTemplate(source);
        var clients = config.registeredClientRepository(jdbc, "com.corebanking.mobile:/oauth2/callback");
        var client = clients.findByClientId("core-banking-mobile");
        assertThat(client.getScopes()).contains("banking", "transactions.write", "openid");
        assertThat(client.getClientSettings().isRequireProofKey()).isTrue();
        assertThat(client.getAuthorizationGrantTypes()).containsExactly(AuthorizationGrantType.AUTHORIZATION_CODE);

        var first = config.jwkSource(jdbc);
        var selector = new JWKSelector(new JWKMatcher.Builder().build());
        String kid = first.get(selector, null).getFirst().getKeyID();
        assertThat(config.jwkSource(jdbc).get(selector, null).getFirst().getKeyID()).isEqualTo(kid);
        var repository = config.authorizationService(jdbc, clients);
        var token = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "opaque-test-token",
                Instant.now(), Instant.now().plusSeconds(300), Set.of("banking"));
        Map<String, Object> claims = new HashMap<>();
        claims.put("aud", new ArrayList<>(List.of("core-banking-api")));
        claims.put("sub", "user@example.com");
        var authorization = OAuth2Authorization.withRegisteredClient(client)
                .principalName("user@example.com").authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizedScopes(Set.of("banking"))
                .token(token, metadata -> metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, claims))
                .build();
        repository.save(authorization);

        var restartedJdbc = config.oauthJdbcTemplate(source);
        var restartedClients = config.registeredClientRepository(restartedJdbc, "com.corebanking.mobile:/oauth2/callback");
        var restarted = config.authorizationService(restartedJdbc, restartedClients);
        var restored = restarted.findByToken(token.getTokenValue(), OAuth2TokenType.ACCESS_TOKEN);
        assertThat(restored.getPrincipalName()).isEqualTo("user@example.com");
        assertThat(restored.getAccessToken().getClaims().get("aud")).isEqualTo(claims.get("aud"));
        restarted.remove(restored);
        assertThat(restarted.findByToken(token.getTokenValue(), OAuth2TokenType.ACCESS_TOKEN)).isNull();
    }
}

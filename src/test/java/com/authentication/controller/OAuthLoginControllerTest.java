package com.authentication.controller;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.security.web.csrf.DefaultCsrfToken;

class OAuthLoginControllerTest {

    private final OAuthLoginController controller = new OAuthLoginController();

    @Test
    void formUsesDedicatedLoginRouteAndEscapesCsrfValues() {
        String html = controller.login(new DefaultCsrfToken("X-CSRF-TOKEN", "_csrf", "test\"<token>"), null);

        assertThat(html).contains("action=\"/oauth/login\"", "name=\"username\"", "name=\"password\"",
                "name=\"_csrf\"", "value=\"test&quot;&lt;token&gt;\"");
        assertThat(html).doesNotContain("role=\"alert\"");
    }

    @Test
    void failedLoginShowsGenericMessageWithoutReflectingUntrustedInput() {
        String html = controller.login(new DefaultCsrfToken("X-CSRF-TOKEN", "_csrf", "test"), "<script>bad</script>");

        assertThat(html).contains("Invalid email or password.", "role=\"alert\"");
        assertThat(html).doesNotContain("<script>");
    }
}

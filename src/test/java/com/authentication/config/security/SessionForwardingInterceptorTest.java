package com.authentication.config.security;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.URI;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.mock.http.client.MockClientHttpRequest;
import org.springframework.mock.http.client.MockClientHttpResponse;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

class SessionForwardingInterceptorTest {

    private final SessionForwardingInterceptor interceptor = new SessionForwardingInterceptor();

    @AfterEach
    void reset() {
        RequestContextHolder.resetRequestAttributes();
        org.springframework.security.core.context.SecurityContextHolder.clearContext();
    }

    private MockClientHttpRequest execute() throws Exception {
        MockClientHttpRequest outbound = new MockClientHttpRequest(HttpMethod.GET, URI.create("http://CUSTOMER-SERVICE/x"));
        interceptor.intercept(outbound, new byte[0], (req, body) -> new MockClientHttpResponse());
        return outbound;
    }

    @Test
    void forwardsSessionCookieAndCsrfHeader() throws Exception {
        MockHttpServletRequest inbound = new MockHttpServletRequest();
        inbound.addHeader(HttpHeaders.COOKIE, "SESSION=abc; XSRF-TOKEN=t1");
        inbound.addHeader("X-XSRF-TOKEN", "t1");
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(inbound));

        MockClientHttpRequest outbound = execute();

        assertThat(outbound.getHeaders().getFirst(HttpHeaders.COOKIE)).isEqualTo("SESSION=abc; XSRF-TOKEN=t1");
        assertThat(outbound.getHeaders().getFirst("X-XSRF-TOKEN")).isEqualTo("t1");
        assertThat(outbound.getHeaders().containsHeader(HttpHeaders.AUTHORIZATION)).isFalse();
    }

    @Test
    void doesNothingOutsideAnHttpRequest() throws Exception {
        MockClientHttpRequest outbound = execute();

        assertThat(outbound.getHeaders().containsHeader(HttpHeaders.COOKIE)).isFalse();
    }

    @Test
    void mobileRegistrationForwardsOnlyValidatedBearerAndPrefixesDownstreamPath() throws Exception {
        var inbound = new MockHttpServletRequest("POST", "/api/mobile/api/v1/auth/register");
        inbound.addHeader(HttpHeaders.COOKIE, "SESSION=browser");
        inbound.addHeader("X-XSRF-TOKEN", "browser-csrf");
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(inbound));
        var jwt = org.springframework.security.oauth2.jwt.Jwt.withTokenValue("validated-test-token")
                .header("alg", "RS256").subject("user@example.com").build();
        org.springframework.security.core.context.SecurityContextHolder.getContext().setAuthentication(
                new org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken(jwt));
        var outbound = new MockClientHttpRequest(HttpMethod.GET,
                URI.create("http://CUSTOMER-SERVICE/customers/validateById?customerId=a%2Bb"));
        interceptor.intercept(outbound, new byte[0], (request, body) -> {
            assertThat(request.getURI().toString())
                    .isEqualTo("http://CUSTOMER-SERVICE/api/mobile/customers/validateById?customerId=a%2Bb");
            assertThat(request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION))
                    .isEqualTo("Bearer validated-test-token");
            assertThat(request.getHeaders().containsHeader(HttpHeaders.COOKIE)).isFalse();
            assertThat(request.getHeaders().containsHeader("X-XSRF-TOKEN")).isFalse();
            return new MockClientHttpResponse();
        });
    }
}

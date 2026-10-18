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
}

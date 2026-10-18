package com.authentication.config.security;

import java.io.IOException;
import java.util.List;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpRequest;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import jakarta.servlet.http.HttpServletRequest;

/**
 * Propagates the caller's session (and CSRF token) to downstream services so they resolve the
 * same user from the shared Redis session.
 */
public class SessionForwardingInterceptor implements ClientHttpRequestInterceptor {

    static final String CSRF_HEADER = "X-XSRF-TOKEN";
    private static final List<String> FORWARDED_HEADERS = List.of(HttpHeaders.COOKIE, CSRF_HEADER);

    @Override
    public ClientHttpResponse intercept(HttpRequest request, byte[] body, ClientHttpRequestExecution execution)
            throws IOException {
        RequestAttributes attributes = RequestContextHolder.getRequestAttributes();
        if (attributes instanceof ServletRequestAttributes servletAttributes) {
            HttpServletRequest inbound = servletAttributes.getRequest();
            for (String name : FORWARDED_HEADERS) {
                String value = inbound.getHeader(name);
                if (value != null && !request.getHeaders().containsHeader(name)) {
                    request.getHeaders().set(name, value);
                }
            }
        }
        return execution.execute(request, body);
    }
}

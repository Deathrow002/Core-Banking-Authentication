package com.authentication.config.security;

import java.io.IOException;
import java.util.List;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpRequest;
import org.springframework.http.client.support.HttpRequestWrapper;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
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
            if (inbound.getRequestURI().startsWith("/api/mobile/")
                    && SecurityContextHolder.getContext().getAuthentication() instanceof JwtAuthenticationToken jwt) {
                String path = request.getURI().getRawPath();
                String mobilePath = path.startsWith("/api/mobile/") ? path : "/api/mobile" + path;
                String query = request.getURI().getRawQuery();
                var target = java.net.URI.create(request.getURI().getScheme() + "://"
                        + request.getURI().getRawAuthority() + mobilePath + (query == null ? "" : "?" + query));
                HttpRequest forwarded = new HttpRequestWrapper(request) {
                    @Override
                    public java.net.URI getURI() {
                        return target;
                    }
                };
                forwarded.getHeaders().remove(HttpHeaders.COOKIE);
                forwarded.getHeaders().remove(CSRF_HEADER);
                forwarded.getHeaders().setBearerAuth(jwt.getToken().getTokenValue());
                return execution.execute(forwarded, body);
            }
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

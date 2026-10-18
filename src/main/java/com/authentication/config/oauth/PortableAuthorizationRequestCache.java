package com.authentication.config.oauth;

import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.security.web.savedrequest.SimpleSavedRequest;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Only a relative URL string enters Redis: DefaultSavedRequest can contain servlet cookies
 * that a WebFlux service cannot deserialize.
 */
public class PortableAuthorizationRequestCache implements RequestCache {

    static final String ATTRIBUTE = "OAUTH_AUTHORIZATION_REDIRECT";

    @Override
    public void saveRequest(HttpServletRequest request, HttpServletResponse response) {
        if ("GET".equals(request.getMethod())
                && (request.getContextPath() + "/oauth2/authorize").equals(request.getRequestURI())) {
            request.getSession().setAttribute(ATTRIBUTE, relativeUrl(request));
        }
    }

    @Override
    public SavedRequest getRequest(HttpServletRequest request, HttpServletResponse response) {
        var session = request.getSession(false);
        String redirect = session == null ? null : (String) session.getAttribute(ATTRIBUTE);
        return redirect == null ? null : new SimpleSavedRequest(redirect);
    }

    @Override
    public HttpServletRequest getMatchingRequest(HttpServletRequest request, HttpServletResponse response) {
        SavedRequest saved = getRequest(request, response);
        if (saved != null && saved.getRedirectUrl().equals(relativeUrl(request))) {
            removeRequest(request, response);
            return request;
        }
        return null;
    }

    @Override
    public void removeRequest(HttpServletRequest request, HttpServletResponse response) {
        var session = request.getSession(false);
        if (session != null) {
            session.removeAttribute(ATTRIBUTE);
        }
    }

    private String relativeUrl(HttpServletRequest request) {
        return request.getRequestURI() + (request.getQueryString() == null ? "" : "?" + request.getQueryString());
    }
}

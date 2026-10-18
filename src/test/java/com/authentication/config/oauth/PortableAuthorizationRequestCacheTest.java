package com.authentication.config.oauth;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.web.savedrequest.SavedRequest;

class PortableAuthorizationRequestCacheTest {

    @Test
    void onlyRelativeUrlStringIsSavedAndRemovedWhenAuthorizationResumes() {
        var cache = new PortableAuthorizationRequestCache();
        var request = new MockHttpServletRequest("GET", "/oauth2/authorize");
        request.setQueryString("response_type=code&state=test%2Bstate");
        request.setCookies(new jakarta.servlet.http.Cookie("SESSION", "browser"));
        var response = new MockHttpServletResponse();

        cache.saveRequest(request, response);

        assertThat(request.getSession().getAttribute(PortableAuthorizationRequestCache.ATTRIBUTE))
                .isEqualTo("/oauth2/authorize?response_type=code&state=test%2Bstate").isInstanceOf(String.class);
        SavedRequest saved = cache.getRequest(request, response);
        assertThat(saved.getRedirectUrl()).isEqualTo("/oauth2/authorize?response_type=code&state=test%2Bstate");
        assertThat(cache.getMatchingRequest(request, response)).isSameAs(request);
        assertThat(cache.getRequest(request, response)).isNull();
    }

    @Test
    void arbitraryRequestsDoNotCreateSessionsOrOpenRedirects() {
        var cache = new PortableAuthorizationRequestCache();
        var request = new MockHttpServletRequest("GET", "//untrusted.example");

        cache.saveRequest(request, new MockHttpServletResponse());

        assertThat(request.getSession(false)).isNull();
    }
}

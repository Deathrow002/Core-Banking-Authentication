package com.authentication.controller;

import org.springframework.http.MediaType;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.HtmlUtils;

@RestController
public class OAuthLoginController {

    @GetMapping(value = "/oauth/login", produces = MediaType.TEXT_HTML_VALUE)
    public String login(CsrfToken csrf, @RequestParam(required = false) String error) {
        return """
                <!doctype html>
                <html lang="en"><head><meta charset="utf-8">
                <meta name="viewport" content="width=device-width, initial-scale=1">
                <title>Core Banking Mobile Authorization</title></head>
                <body><main><h1>Sign in to Core Banking</h1>
                <p>Authorize the Core Banking mobile application using your existing account.</p>
                %s
                <form method="post" action="/oauth/login">
                <label>Email <input type="email" name="username" autocomplete="username" required></label>
                <label>Password <input type="password" name="password" autocomplete="current-password" required></label>
                <input type="hidden" name="%s" value="%s">
                <button type="submit">Sign in</button>
                </form></main></body></html>
                """.formatted(error == null ? "" : "<p role=\"alert\">Invalid email or password.</p>",
                HtmlUtils.htmlEscape(csrf.getParameterName()), HtmlUtils.htmlEscape(csrf.getToken()));
    }
}

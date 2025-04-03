package ru.manannikov.oauth2authorizationserver.config;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.test.context.support.WithSecurityContextFactory;

import java.util.Collections;

public class CustomSecurityContextFactory implements WithSecurityContextFactory<WithCustomUser> {
    @Override public SecurityContext createSecurityContext (WithCustomUser annotation) {
        SecurityContext context = SecurityContextHolder.createEmptyContext();

        Authentication authentication = new UsernamePasswordAuthenticationToken(
            annotation.userId(), null, Collections.emptyList());
        context.setAuthentication(authentication);

        return context;
    }
}

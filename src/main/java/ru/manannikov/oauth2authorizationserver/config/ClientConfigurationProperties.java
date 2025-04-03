package ru.manannikov.oauth2authorizationserver.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties("app.client")
public record ClientConfigurationProperties(
    String secret,
    String clientId,
    String port,
    String host
) {}

package ru.manannikov.oauth2authorizationserver.config;

import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;

import java.util.Objects;
import java.util.UUID;

@Log4j2
@Configuration
@RequiredArgsConstructor
public class InitClient {
    private final RegisteredClientRepository registeredClientRepository;
    private final ClientConfigurationProperties clientProperties;

    @Bean
    public ApplicationRunner runner() {
        return args -> {
            if (Objects.isNull(clientProperties.clientId())) {
                logger.warn("client id is null");
                return;
            }

            var publicClient = registeredClientRepository.findByClientId(clientProperties.clientId());
            if (!Objects.isNull(publicClient)) {
                logger.info("a client with the id `{}` has already been registered", clientProperties.clientId());
                return;
            }

            logger.debug("registering client ...\n\tclientId: {}, clientHost: {}, clientPort: {}\n\tclientSecret: {}", clientProperties.clientId(), clientProperties.host(), clientProperties.port(), clientProperties.secret());
            publicClient = RegisteredClient
                .withId(UUID.randomUUID().toString())
                .clientId(clientProperties.clientId())
                .clientSecret(clientProperties.secret())
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri(String.format(
                    "http://%s:%s/login/oauth2/code/%s",
                    clientProperties.host(), clientProperties.port(), clientProperties.clientId()
                ))
                .postLogoutRedirectUri(String.format("http://%s:%s/",
                    clientProperties.host(), clientProperties.port()
                ))
                .scope("read")
                .scope(OidcScopes.OPENID)
                .clientSettings(ClientSettings
                    .builder()
                        .requireAuthorizationConsent(false)
                    .build()
                )
                .build()
            ;

            registeredClientRepository.save(publicClient);
        };
    }
}
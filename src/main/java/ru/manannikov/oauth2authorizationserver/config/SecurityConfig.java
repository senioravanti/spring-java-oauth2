package ru.manannikov.oauth2authorizationserver.config;


import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.encrypt.KeyStoreKeyFactory;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.*;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.header.HeaderWriterFilter;
import org.springframework.security.web.session.HttpSessionEventPublisher;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;

/**
 *
 * Запросы на токен доступа
 * curl -sS http://localhost:8001/.well-known/openid-configuration
 * http://localhost:8001/oauth2/authorize?response_type=code&client_id=filesharingservice&scope=openid&redirect_uri=http://127.0.0.1:8003/callback&code_challenge=T_bX83gie-g4STsJ61amTJWJ_--Adw4W_KYZFObjvh8&code_challenge_method=S256&state=0FO23MjktgldOuqk
 *
 */

@Log4j2
@Configuration
@EnableWebSecurity(debug = true)
@EnableMethodSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private static String[] URL_WHITELIST = {
        "/v3/api-docs/**", "/swagger-ui/**",
    };

    @Value("${app.security.keystore-password}")
    private final String keystorePassword;
    @Value("${app.security.keystore-location}")
    private final String keystoreLocation;
    @Value("${app.security.keystore-alias}")
    private final String keystoreAlias;

    @Order(1)
    @Bean
    // Нужно использовать только если в контексте настроено несколько бинов того же типа.
    // Настраиваем стандартную аутентификацию и авторизацию по протоколу OIDC
    public SecurityFilterChain asFilterChain (HttpSecurity http)
        throws Exception
    {
        // Применяет стандартные настройки фильтра безопасности, настр. HttpSecurity.
        // Приложение дает доступ к роутам только пользователям, прошедшим аутентификацию
        final var authorizationServerConfigurer = OAuth2AuthorizationServerConfigurer.authorizationServer();

        // Включаем OpenID Connect
        http
            .securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())
            .with(
                authorizationServerConfigurer,
                authorizationServer -> authorizationServer
                    .oidc(Customizer.withDefaults())
            )
            .authorizeHttpRequests(
                authorize -> authorize
                    .anyRequest().authenticated()
            )
        ;

        http
            .exceptionHandling(
                ex -> ex
                    .defaultAuthenticationEntryPointFor(
                        new LoginUrlAuthenticationEntryPoint("/login"),
                        new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
                    )
            )
            // Теперь сможем обрабатывать на сервере запросы на регистрацию новых пользователей. Реализуем, так сказать, функционал администратора.
            .oauth2ResourceServer(
                resourceServer -> resourceServer
                    .jwt(Customizer.withDefaults())
            )
        ;

        return http.build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();
        config.addAllowedOrigin("http://127.0.0.1:8081");
        config.addAllowedHeader("*");
        config.addAllowedMethod("GET");
        config.addAllowedMethod("POST");

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);

        return source;
    }
    /**
     * Настраиваем поведение auth server в том случае, когда он будет использоваться администратором как resourceserver
     */
    @Order(2)
    @Bean
    public SecurityFilterChain defaultSecurityFilterChain (HttpSecurity http)
        throws Exception
    {
        http
            .cors(c -> c.configurationSource(corsConfigurationSource()))
            .csrf(AbstractHttpConfigurer::disable)

            .authorizeHttpRequests(
                authorize -> authorize
                    .anyRequest().authenticated()
            )
            .formLogin(
                Customizer.withDefaults()
            )
        ;

        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder () {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository(JdbcTemplate jdbcTemplate) {
        return new JdbcRegisteredClientRepository(jdbcTemplate);
    }

    private KeyPair keyPairFromKeystore() {
       ClassPathResource keystore = new ClassPathResource(keystoreLocation);
        KeyStoreKeyFactory keyStoreKeyFactory = new KeyStoreKeyFactory(keystore, keystorePassword.toCharArray());

        return keyStoreKeyFactory.getKeyPair(keystoreAlias);
    }

    @Bean
    public JWKSource <SecurityContext> jwkSource() {
        KeyPair keyPair = keyPairFromKeystore();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

        RSAKey rsaKey = new RSAKey.Builder(publicKey)
            .algorithm(JWSAlgorithm.RS256)
            .keyID(UUID.randomUUID().toString())
            .keyUse(KeyUse.SIGNATURE)
            .privateKey(privateKey)
            .build();

        JWKSet jwkSet = new JWKSet(rsaKey);
        return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
    }


    /**
     * Если мы используем authorization server в качестве resource server, например, для управления пользователями, то необходим этот бин.
     * @param jwkSource :: пара ключей, используемая resource server для проверки полученного токена на подлинность.
     */
    @Bean
    public JwtDecoder jwtDecoder(JWKSource <SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder()
//            .tokenEndpoint("/Authentication/SignIn")
//            .oidcUserInfoEndpoint("/Accounts/Me")
//            .oidcLogoutEndpoint("/Authentication/SignOut")
//            .tokenIntrospectionEndpoint("/Authentication/Validate")
        .build();
    }

    /**
     * Добавляем информацию о полномочиях пользователя только в id token
     */
    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer() {
        return context -> {
            if (context.getTokenType().equals(OAuth2TokenType.ACCESS_TOKEN)) {
                Authentication principal = context.getPrincipal();

                Set<String> authorities = new HashSet<>();
                    principal.getAuthorities().forEach(
                        a -> authorities.add(a.getAuthority())
                );

                    context.getClaims().claim("authorities", authorities);
            }
        };
    }

    /**
     * Генераторы токенов можно использовать и с настройками по умолчанию.
     */
    @Bean
    public OAuth2TokenGenerator<OAuth2Token> tokenGenerator() {
        JwtGenerator jwtGenerator = new JwtGenerator(new NimbusJwtEncoder(jwkSource()));
        jwtGenerator.setJwtCustomizer(jwtCustomizer());

        OAuth2RefreshTokenGenerator refreshTokenGenerator = new OAuth2RefreshTokenGenerator();

        return new DelegatingOAuth2TokenGenerator(jwtGenerator, refreshTokenGenerator);
    }
}
package ru.manannikov.oauth2authorizationserver.config;


import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;


@Configuration
public class SwaggerConfig {
    private static final String API_INFO_TITLE = "Security Service";
    private static final String API_INFO_DESCRIPTION = "REST-API сервера аутентификации & авторизации";
    @Value("${app.api-info-version}")
    private String apiInfoVersion;

    public Info apiInfo() {
        return new Info()
            .title(API_INFO_TITLE)
            .description(API_INFO_DESCRIPTION)
            .license(new License().url("http://unlicense.org"))
            .contact(new Contact().email("").name("").url(""))
            .version(apiInfoVersion)
            ;
    }

    @Bean
    public OpenAPI openApi() {
        return new OpenAPI()
            .info(apiInfo())
            ;
    }
}

package ru.manannikov.oauth2authorizationserver;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import ru.manannikov.oauth2authorizationserver.config.ClientConfigurationProperties;

@EnableConfigurationProperties(
	value = { ClientConfigurationProperties.class }
)
@SpringBootApplication
public class Oauth2authorizationserverApplication {

	public static void main(String[] args) {
		SpringApplication.run(Oauth2authorizationserverApplication.class, args);
	}

}

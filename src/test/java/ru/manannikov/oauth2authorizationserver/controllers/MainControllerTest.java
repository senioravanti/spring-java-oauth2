package ru.manannikov.oauth2authorizationserver.controllers;


import lombok.extern.log4j.Log4j2;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.test.context.support.WithUserDetails;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.test.web.servlet.MockMvc;
import ru.manannikov.learnsecurity.config.WithCustomUser;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;


@Log4j2
@WebMvcTest(
    controllers = {MainController.class},
    properties = {
        "logging.level.ru.manannikov.learnsecurity.controllers=DEBUG",
    }
)
@AutoConfigureMockMvc
public class MainControllerTest {
    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ApplicationContext applicationContext;

    @TestConfiguration
    @EnableWebSecurity(debug = true)
    @EnableMethodSecurity
    public static class TestSecurityConfig {
        @Bean
        public SecurityFilterChain testSecurityFilterChain(HttpSecurity http)
            throws Exception
        {
            http
                .authorizeHttpRequests(
                    authorize -> authorize
                        .anyRequest().authenticated()
                )
                .httpBasic(
                    Customizer.withDefaults()
                )
            ;

            return http.build();
        }

        @Bean
        public PasswordEncoder testPasswordEncoder () {
            return new BCryptPasswordEncoder();
        }

        @Bean
        public UserDetailsService testUserDetailsService () {
            var user1 = User
                .builder()
                .username("antonio")
                .password(testPasswordEncoder().encode("12345"))
                .authorities("ROLE_USER")
                .build()
                ;

            var user2 = User
                .builder()
                .username("maxick")
                .password(testPasswordEncoder().encode("54321"))
                .authorities("ROLE_USER", "ROLE_ADMIN")
                .build()
                ;

            return new InMemoryUserDetailsManager(user1, user2);
        }
    }

    @Test
    @DisplayName("status unauthorized")
    public void helloUnauthorized()
        throws Exception
    {
        mockMvc.perform(get("/hello"))
            .andExpect(status().isUnauthorized())
        ;
    }

    @Test
    @DisplayName("status ok")
    @WithCustomUser(userId = 1L)
    public void helloAuthenticated()
        throws Exception
    {

        var res = mockMvc
            .perform(
                get("/hello")
            )
            .andExpect(status().isOk())
            .andExpect(content().string("hello"))
            .andReturn();
    }

    @Test
    @WithUserDetails(value = "antonio", userDetailsServiceBeanName = "testUserDetailsService")
    public void helloForbidden()
        throws Exception
    {
        log.info("Application context:");
        for (String name : applicationContext.getBeanDefinitionNames()) {
            log.info(name);
        }
        log.info("------");
        
        mockMvc.perform(get("/hello"))
            .andExpect(status().isForbidden())
        ;
    }

    @Test
    @WithUserDetails(value = "maxick", userDetailsServiceBeanName = "testUserDetailsService")
    public void helloAuthorized()
        throws Exception
    {
        mockMvc
            .perform(get("/hello/maxick"))
            .andExpect(status().isOk())
            .andExpect(content().string("hello maxick"))
        ;
    }
}

package ru.manannikov.oauth2authorizationserver.controllers;


import lombok.extern.log4j.Log4j2;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/")
@Log4j2
public class MainController {
    @PostMapping("/test")
    public String json(Authentication authentication) {
        logger.info("POST test method called");

        return String.format("HELLO %s, твои привилегии %s", authentication.getName(), authentication.getAuthorities());
    }
}

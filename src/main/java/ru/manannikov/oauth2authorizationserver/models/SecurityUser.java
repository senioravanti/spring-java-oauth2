package ru.manannikov.oauth2authorizationserver.models;


import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;


@RequiredArgsConstructor
public class SecurityUser implements UserDetails {

    private final UserEntity userEntity;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return userEntity.getAuthorities();
    }


    @Override
    public String getPassword() {
        return userEntity.getPassword();
    }

    @Override
    public String getUsername() {
        return userEntity.getUsername();
    }
}

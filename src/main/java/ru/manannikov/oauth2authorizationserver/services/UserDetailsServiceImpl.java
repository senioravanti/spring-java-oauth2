package ru.manannikov.oauth2authorizationserver.services;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import ru.manannikov.oauth2authorizationserver.models.SecurityUser;
import ru.manannikov.oauth2authorizationserver.repositories.UserRepository;

@Service("userDetailsService")
@RequiredArgsConstructor
public class UserDetailsServiceImpl
    implements UserDetailsService
{
    private final UserRepository userRepository;

    @Override public UserDetails loadUserByUsername(String username)
        throws UsernameNotFoundException {
        return userRepository.findByUsername(username)
            .map(SecurityUser::new)
            .orElseThrow(() -> new UsernameNotFoundException(username));
    }
}

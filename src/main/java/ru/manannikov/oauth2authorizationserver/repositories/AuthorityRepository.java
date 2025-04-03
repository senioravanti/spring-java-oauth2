package ru.manannikov.oauth2authorizationserver.repositories;


import org.springframework.data.jpa.repository.JpaRepository;
import ru.manannikov.oauth2authorizationserver.models.AuthorityEntity;

import java.util.Optional;


public interface AuthorityRepository extends JpaRepository<AuthorityEntity, Long> {
    Optional<AuthorityEntity> findByAuthority(String authority);
}

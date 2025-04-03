package ru.manannikov.oauth2authorizationserver.repositories;


import org.springframework.data.jpa.repository.JpaRepository;
import ru.manannikov.oauth2authorizationserver.models.UserEntity;

import java.util.Optional;


public interface UserRepository extends JpaRepository<UserEntity, Long> {
    Optional<UserEntity>  findByUsername(String username);
}

package ru.manannikov.oauth2authorizationserver.models;


import jakarta.persistence.*;
import lombok.*;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;


@Entity
@Getter @Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Table(name = "users")
public class UserEntity {
    @Id
    @Column(name = "user_id")
    private UUID id;

    @Column(
        name = "user_username",
        nullable = false, unique = true, length = 200
    )
    private String username;

    @Column(
        name = "user_password",
        nullable = false, length = 500
    )
    private String password;

    @ManyToMany(
        fetch = FetchType.EAGER
    )
    @JoinTable(
        name = "user_authorities",
        joinColumns = @JoinColumn(name = "user_id"),
        inverseJoinColumns = @JoinColumn(name = "authority_id")
    )
    private List<AuthorityEntity> authorities = new ArrayList<>();
}

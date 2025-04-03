package ru.manannikov.oauth2authorizationserver.models;


import jakarta.persistence.*;
import lombok.*;
import org.springframework.security.core.GrantedAuthority;


@Entity
@Getter @Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Table(name = "authorities")
public class AuthorityEntity implements GrantedAuthority {
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "authority_id")
    private Short id;

    @Column(
        name = "authority_name",
        unique = true, nullable = false, length = 200
    )
    private String authority;

    @Override
    public String getAuthority() {
        return authority;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof AuthorityEntity role) {
            return this.authority.equals(role.getAuthority());
        }
        return false;
    }

    @Override
    public int hashCode() {
        return this.authority.hashCode();
    }

    @Override
    public String toString() {
        return this.authority;
    }
}
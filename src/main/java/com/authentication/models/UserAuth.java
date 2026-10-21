package com.authentication.models;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.UUID;

import org.hibernate.annotations.CreationTimestamp;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import jakarta.validation.constraints.Email;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@Entity
@Table(name = "user_auth")
@NoArgsConstructor
@AllArgsConstructor
public class UserAuth implements UserDetails {
    
    @Id
    @GeneratedValue(generator = "UUID")
    private UUID id;

    @Column(name = "customer_id", nullable = false, unique = true)
    private UUID customerId;

    @Email
    @Column(name = "email", nullable = false, unique = true)
    private String email;

    @Column(name = "password", nullable = false)
    private String password;

    @ManyToOne
    @JoinColumn(name = "role", referencedColumnName = "name", nullable = false)
    private Role role;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @Builder.Default
    @Column(name = "is_account_non_locked", nullable = false)
    private boolean accountNonLocked = true;

    @Builder.Default
    @Column(name = "is_credentials_non_expired", nullable = false)
    private boolean credentialsNonExpired = true;

    @Builder.Default
    @Column(name = "is_account_non_expired", nullable = false)
    private boolean accountNonExpired = true;

    @Builder.Default
    @Column(name = "is_enabled", nullable = false)
    private boolean enabled = true;

    /** Name of the referenced role, for example {@code ADMIN}. */
    public String getRoleName() {
        return role.getName();
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        List<GrantedAuthority> authorities = new ArrayList<>();
        authorities.add(new SimpleGrantedAuthority("ROLE_" + getRoleName()));
        role.permissionAuthorities().forEach(permission -> authorities.add(new SimpleGrantedAuthority(permission)));
        return authorities;
    }

    @Override
    public String getUsername() {
        return this.email;
    }
}
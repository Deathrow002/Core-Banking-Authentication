package com.authentication.repository;

import java.util.Optional;
import java.util.UUID;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.authentication.models.UserAuth;

@Repository
public interface UserAuthRepository extends JpaRepository<UserAuth, UUID> {
    Optional<UserAuth> findByEmail(String email);

    boolean existsByCustomerId(UUID customerId);

    Page<UserAuth> findByRole_NameNot(String roleName, Pageable pageable);

    long countByRole_NameAndEnabled(String roleName, boolean enabled);
}
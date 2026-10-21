package com.authentication.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.authentication.models.Role;

@Repository
public interface RoleRepository extends JpaRepository<Role, String> {
}

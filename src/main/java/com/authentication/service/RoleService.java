package com.authentication.service;

import java.util.List;

import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.authentication.models.Role;
import com.authentication.repository.RoleRepository;

import lombok.RequiredArgsConstructor;

/** Reads roles from the {@code roles} table, so the set of valid roles is data, not code. */
@Service
@RequiredArgsConstructor
public class RoleService {

    private final RoleRepository roleRepository;

    @Transactional(readOnly = true)
    public List<Role> list() {
        return roleRepository.findAll(Sort.by("name").ascending());
    }

    @Transactional(readOnly = true)
    public Role require(String name) {
        if (name == null) {
            throw new UserManagementException(HttpStatus.BAD_REQUEST, "Role is required");
        }
        return roleRepository.findById(name)
                .orElseThrow(() -> new UserManagementException(HttpStatus.BAD_REQUEST, "Unknown role: " + name));
    }
}

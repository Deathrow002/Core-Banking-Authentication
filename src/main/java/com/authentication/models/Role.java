package com.authentication.models;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * A login role, stored in the {@code roles} table. Rows are seeded by {@code schema.sql}.
 * The name is the primary key, and {@code user_auth.role} references it.
 * The {@code can*} flags grant the matching {@link Permissions} authorities to every login with this role.
 */
@Data
@Entity
@Table(name = "roles")
@NoArgsConstructor
@AllArgsConstructor
public class Role implements Serializable {

    private static final long serialVersionUID = 1L;

    @Id
    @Column(name = "name", length = 50, nullable = false)
    private String name;

    @Column(name = "can_add", nullable = false)
    private boolean canAdd;

    @Column(name = "can_edit", nullable = false)
    private boolean canEdit;

    @Column(name = "can_delete", nullable = false)
    private boolean canDelete;

    /** A role without add, edit or delete permission. */
    public Role(String name) {
        this.name = name;
    }

    /** The {@link Permissions} authorities this role grants, for example {@code PERM_ADD}. */
    public List<String> permissionAuthorities() {
        List<String> authorities = new ArrayList<>(3);
        if (canAdd) {
            authorities.add(Permissions.ADD);
        }
        if (canEdit) {
            authorities.add(Permissions.EDIT);
        }
        if (canDelete) {
            authorities.add(Permissions.DELETE);
        }
        return authorities;
    }
}

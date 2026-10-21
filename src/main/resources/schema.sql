-- Runs on every startup before JPA (spring.sql.init.mode=always), so each statement must be idempotent.
-- Hibernate (ddl-auto=update) then adds the user_auth.role -> roles.name foreign key.
-- Statements with a body use a single-quoted string instead of $$ dollar quoting because Spring's
-- SQL script splitter does not understand $$ and would cut the body at its semicolons.

-- can_add / can_edit / can_delete grant PERM_ADD / PERM_EDIT / PERM_DELETE to every login with the role.
CREATE TABLE IF NOT EXISTS roles (
    name       VARCHAR(50) PRIMARY KEY,
    can_add    BOOLEAN NOT NULL DEFAULT FALSE,
    can_edit   BOOLEAN NOT NULL DEFAULT FALSE,
    can_delete BOOLEAN NOT NULL DEFAULT FALSE
);

-- Existing databases: roles was created with only a name. Add the permission columns once and give
-- the seeded roles their defaults; later runs leave any permissions changed in the table alone.
DO '
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_schema = current_schema() AND table_name = ''roles'' AND column_name = ''can_add'') THEN
        ALTER TABLE roles
            ADD COLUMN can_add    BOOLEAN NOT NULL DEFAULT FALSE,
            ADD COLUMN can_edit   BOOLEAN NOT NULL DEFAULT FALSE,
            ADD COLUMN can_delete BOOLEAN NOT NULL DEFAULT FALSE;
        UPDATE roles SET can_add = TRUE, can_edit = TRUE, can_delete = TRUE WHERE name = ''ADMIN'';
        UPDATE roles SET can_add = TRUE, can_edit = TRUE WHERE name = ''MANAGER'';
    END IF;
END
';

INSERT INTO roles (name, can_add, can_edit, can_delete) VALUES
    ('CUSTOMER', FALSE, FALSE, FALSE),
    ('ADMIN',    TRUE,  TRUE,  TRUE),
    ('MANAGER',  TRUE,  TRUE,  FALSE)
ON CONFLICT (name) DO NOTHING;

-- Existing databases: user_auth.role was an enum, which Hibernate created with a CHECK constraint
-- listing the old values. That constraint blocks the rename below, so it is dropped first.
DO '
BEGIN
    IF to_regclass(''user_auth'') IS NOT NULL THEN
        ALTER TABLE user_auth DROP CONSTRAINT IF EXISTS user_auth_role_check;
        UPDATE user_auth SET role = ''CUSTOMER'' WHERE role = ''USER'';
    END IF;
END
';

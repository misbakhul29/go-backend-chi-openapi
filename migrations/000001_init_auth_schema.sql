-- +goose Up
-- SQL in this section is executed when the migration is applied.

CREATE TABLE IF NOT EXISTS "user" (
    id VARCHAR(255) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    email_verified BOOLEAN NOT NULL DEFAULT FALSE,
    image TEXT,
    mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    mfa_secret TEXT,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    last_login_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS "role" (
    id VARCHAR(255) PRIMARY KEY,
    name VARCHAR(255) UNIQUE NOT NULL,
    is_default BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS "permission" (
    id VARCHAR(255) PRIMARY KEY,
    code VARCHAR(255) UNIQUE NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS "user_roles" (
    user_id VARCHAR(255) NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
    role_id VARCHAR(255) NOT NULL REFERENCES "role"(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, role_id)
);
CREATE INDEX IF NOT EXISTS idx_user_roles_role ON "user_roles"(role_id);
CREATE INDEX IF NOT EXISTS idx_user_roles_user ON "user_roles"(user_id);

CREATE TABLE IF NOT EXISTS "role_permissions" (
    role_id VARCHAR(255) NOT NULL REFERENCES "role"(id) ON DELETE CASCADE,
    permission_id VARCHAR(255) NOT NULL REFERENCES "permission"(id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);
CREATE INDEX IF NOT EXISTS idx_role_permissions_role ON "role_permissions"(role_id);
CREATE INDEX IF NOT EXISTS idx_role_permissions_perm ON "role_permissions"(permission_id);

CREATE TABLE IF NOT EXISTS "session" (
    id VARCHAR(255) PRIMARY KEY,
    expires_at TIMESTAMPTZ NOT NULL,
    token VARCHAR(255) DEFAULT '',
    token_hash VARCHAR(64),
    family_id VARCHAR(255),
    is_revoked BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    last_active_at TIMESTAMPTZ,
    ip_address VARCHAR(45),
    user_agent TEXT,
    device VARCHAR(255),
    user_id VARCHAR(255) NOT NULL REFERENCES "user"(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_session_user_id ON "session"(user_id);
CREATE INDEX IF NOT EXISTS idx_session_expires ON "session"(expires_at);
CREATE INDEX IF NOT EXISTS idx_session_token_hash ON "session"(token_hash);
CREATE INDEX IF NOT EXISTS idx_session_family_id ON "session"(family_id);
CREATE INDEX IF NOT EXISTS idx_session_revoked ON "session"(is_revoked);
CREATE INDEX IF NOT EXISTS idx_session_last_active ON "session"(last_active_at);

CREATE TABLE IF NOT EXISTS "refresh_token" (
    id VARCHAR(255) PRIMARY KEY,
    session_id VARCHAR(255) NOT NULL REFERENCES "session"(id) ON DELETE CASCADE,
    family_id VARCHAR(255) NOT NULL,
    token_hash VARCHAR(64) NOT NULL,
    is_revoked BOOLEAN NOT NULL DEFAULT FALSE,
    replaced_by_token_id VARCHAR(255),
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_refresh_token_hash ON "refresh_token"(token_hash);
CREATE INDEX IF NOT EXISTS idx_refresh_token_session_id ON "refresh_token"(session_id);
CREATE INDEX IF NOT EXISTS idx_refresh_token_family_id ON "refresh_token"(family_id);
CREATE INDEX IF NOT EXISTS idx_refresh_token_revoked ON "refresh_token"(is_revoked);
CREATE INDEX IF NOT EXISTS idx_refresh_token_expires ON "refresh_token"(expires_at);

CREATE TABLE IF NOT EXISTS "mfa_backup_code" (
    id VARCHAR(255) PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
    code_hash VARCHAR(64) NOT NULL,
    is_used BOOLEAN NOT NULL DEFAULT FALSE,
    used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_mfa_backup_code_user_id ON "mfa_backup_code"(user_id);
CREATE INDEX IF NOT EXISTS idx_mfa_backup_code_hash ON "mfa_backup_code"(code_hash);
CREATE INDEX IF NOT EXISTS idx_mfa_backup_code_user_used ON "mfa_backup_code"(user_id, is_used);

CREATE TABLE IF NOT EXISTS "audit_log" (
    id VARCHAR(255) PRIMARY KEY,
    "timestamp" TIMESTAMPTZ NOT NULL,
    event_type VARCHAR(100) NOT NULL,
    user_id VARCHAR(255),
    tenant_id VARCHAR(255),
    ip_address VARCHAR(45),
    user_agent TEXT,
    status VARCHAR(50) NOT NULL,
    metadata TEXT,
    created_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON "audit_log"("timestamp");
CREATE INDEX IF NOT EXISTS idx_audit_log_event_type ON "audit_log"(event_type);
CREATE INDEX IF NOT EXISTS idx_audit_log_user_id ON "audit_log"(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_tenant_id ON "audit_log"(tenant_id);

CREATE TABLE IF NOT EXISTS "account" (
    id VARCHAR(255) PRIMARY KEY,
    account_id VARCHAR(255) NOT NULL,
    provider_id VARCHAR(255) NOT NULL,
    user_id VARCHAR(255) NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
    access_token TEXT,
    refresh_token TEXT,
    id_token TEXT,
    access_token_expires_at TIMESTAMPTZ,
    refresh_token_expires_at TIMESTAMPTZ,
    scope TEXT,
    password VARCHAR(255),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_account_user_id ON "account"(user_id);

CREATE TABLE IF NOT EXISTS "verification" (
    id VARCHAR(255) PRIMARY KEY,
    identifier VARCHAR(255) NOT NULL,
    value VARCHAR(255) NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_verification_id_val ON "verification"(identifier, value);
CREATE INDEX IF NOT EXISTS idx_verification_expires ON "verification"(expires_at);

-- +goose Down
-- SQL in this section is executed when the migration is rolled back.

DROP TABLE IF EXISTS "verification" CASCADE;
DROP TABLE IF EXISTS "account" CASCADE;
DROP TABLE IF EXISTS "audit_log" CASCADE;
DROP TABLE IF EXISTS "mfa_backup_code" CASCADE;
DROP TABLE IF EXISTS "refresh_token" CASCADE;
DROP TABLE IF EXISTS "session" CASCADE;
DROP TABLE IF EXISTS "role_permissions" CASCADE;
DROP TABLE IF EXISTS "user_roles" CASCADE;
DROP TABLE IF EXISTS "permission" CASCADE;
DROP TABLE IF EXISTS "role" CASCADE;
DROP TABLE IF EXISTS "user" CASCADE;


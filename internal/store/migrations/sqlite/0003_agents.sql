-- Agents and deployment targets. Targets are re-created: until now nothing
-- could create them, so they hold no data.

DROP TABLE deployments;
DROP TABLE certificate_targets;
DROP TABLE targets;

ALTER TABLE agents ADD COLUMN name TEXT NOT NULL DEFAULT '';
ALTER TABLE agents ADD COLUMN enroll_expires_at TIMESTAMP;
-- During identity renewal the agent may still use its old certificate
-- until it has stored the new one, so both are accepted.
ALTER TABLE agents ADD COLUMN client_cert_fp_next TEXT;
CREATE UNIQUE INDEX agents_cert_next ON agents(client_cert_fp_next);
CREATE UNIQUE INDEX agents_name ON agents(project_id, name);

ALTER TABLE certificates ADD COLUMN renew_requested_at TIMESTAMP;

CREATE TABLE targets (
    id          TEXT PRIMARY KEY,
    project_id  TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    agent_id    TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    deployer    TEXT NOT NULL,                  -- agent deployer, e.g. nginx, files
    settings    TEXT NOT NULL DEFAULT '{}',
    created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (project_id, name)
);

CREATE TABLE certificate_targets (
    certificate_id  TEXT NOT NULL REFERENCES certificates(id) ON DELETE CASCADE,
    target_id       TEXT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    PRIMARY KEY (certificate_id, target_id)
);

-- The latest outcome of installing a version on a target.
CREATE TABLE deployments (
    id           TEXT PRIMARY KEY,
    version_id   TEXT NOT NULL REFERENCES certificate_versions(id) ON DELETE CASCADE,
    target_id    TEXT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    status       TEXT NOT NULL CHECK (status IN ('done', 'failed')),
    message      TEXT,
    finished_at  TIMESTAMP NOT NULL,
    UNIQUE (version_id, target_id)
);

-- Instance-wide keys (such as the agent CA), sealed with the KEK.
CREATE TABLE server_keys (
    name         TEXT PRIMARY KEY,
    cert_pem     TEXT NOT NULL,
    kek_id       TEXT NOT NULL,
    wrapped_dek  BLOB NOT NULL,
    ciphertext   BLOB NOT NULL,
    created_at   TIMESTAMP NOT NULL
);

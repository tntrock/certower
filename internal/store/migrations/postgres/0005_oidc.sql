-- OIDC group claims captured at login; role bindings on groups apply for
-- the life of the session.
ALTER TABLE sessions ADD COLUMN oidc_groups TEXT NOT NULL DEFAULT '[]';

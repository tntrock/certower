-- Issuance engine: ARI refresh tracking, job de-duplication, error display.

ALTER TABLE certificate_versions ADD COLUMN ari_checked_at TIMESTAMP;
ALTER TABLE certificates ADD COLUMN last_error TEXT;
ALTER TABLE jobs ADD COLUMN dedupe_key TEXT;

-- At most one open job per key, e.g. one pending issuance per certificate.
CREATE UNIQUE INDEX jobs_dedupe ON jobs(dedupe_key)
    WHERE status IN ('queued', 'running', 'waiting_manual');

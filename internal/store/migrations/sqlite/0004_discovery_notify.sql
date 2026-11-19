-- Discovery scheduling and notification de-duplication.

-- Events that must be announced once, such as "expires in 7 days" for one
-- version, are recorded here before notifications go out.
CREATE TABLE notification_log (
    dedupe_key  TEXT PRIMARY KEY,
    created_at  TIMESTAMP NOT NULL
);

CREATE INDEX discovery_endpoints_scan ON discovery_endpoints(last_scanned_at);

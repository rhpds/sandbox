BEGIN;

CREATE TABLE audit_log (
    id BIGSERIAL PRIMARY KEY,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT (now() AT TIME ZONE 'utc'),
    actor TEXT NOT NULL,         -- JWT "name" claim
    role TEXT NOT NULL,          -- JWT "role" claim
    method TEXT NOT NULL,        -- HTTP method (GET, POST, PUT, DELETE)
    path TEXT NOT NULL,          -- Request URL path
    status_code INTEGER,        -- HTTP response status code
    request_id TEXT              -- X-Request-Id for correlation
);

CREATE INDEX ON audit_log (actor);
CREATE INDEX ON audit_log (created_at);
CREATE INDEX ON audit_log (path);

COMMIT;

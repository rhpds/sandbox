-- Create table tokens
-- /api/v1/login http endpoint will check validity from this table
-- /api/v1/admin/jwt http endpoint will create new ones

BEGIN;

CREATE TABLE tokens (
    id SERIAL PRIMARY KEY,
    kind VARCHAR(20) NOT NULL,  -- kind of token, e.g. "login" as defined in the JWT token claim
    name VARCHAR(255) NOT NULL, -- name as defined in the JWT token claim
    role VARCHAR(255) NOT NULL, -- role as defined in the JWT token claim
    iat INTEGER NOT NULL,       -- creation time as defined in the JWT token claim
    exp INTEGER,                -- expiration unix time as defined in the JWT token claim
    expiration TIMESTAMP WITH TIME ZONE, -- expiration time readable by humans
    created_at timestamp with time zone NOT NULL DEFAULT (now() at time zone 'utc'),
    updated_at timestamp with time zone NOT NULL DEFAULT (now() at time zone 'utc'),
    valid BOOLEAN NOT NULL DEFAULT TRUE -- Used to invalidate tokens
);

CREATE TRIGGER tokens_updated_at
  BEFORE UPDATE ON tokens
  FOR EACH ROW
  WHEN (OLD.* IS DISTINCT FROM NEW.*)
  EXECUTE FUNCTION updated_at_column();

CREATE INDEX ON tokens (kind);
CREATE INDEX ON tokens (name);
CREATE INDEX ON tokens (name, kind);
CREATE INDEX ON tokens (name, iat);
CREATE INDEX ON tokens (name, iat, role);
COMMIT;

BEGIN;

CREATE TABLE ssl_account_configurations (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL UNIQUE,
    domain VARCHAR(255) NOT NULL,
    main_provider VARCHAR(255) NOT NULL,
    main_provider_url VARCHAR(512) NOT NULL,
    fallback_provider VARCHAR(255) DEFAULT '',
    fallback_provider_url VARCHAR(512) DEFAULT '',
    endpoint VARCHAR(512) NOT NULL,
    token BYTEA NOT NULL,
    additional_vars JSONB DEFAULT '{}'::jsonb NOT NULL,
    created_at TIMESTAMP with time zone NOT NULL DEFAULT (now() at time zone 'utc'),
    updated_at TIMESTAMP with time zone NOT NULL DEFAULT (now() at time zone 'utc'),
    annotations JSONB DEFAULT '{}'::jsonb NOT NULL,
    valid BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE TRIGGER ssl_account_configurations_updated_at
  BEFORE UPDATE ON ssl_account_configurations
  FOR EACH ROW
  WHEN (OLD.* IS DISTINCT FROM NEW.*)
  EXECUTE FUNCTION updated_at_column();

ALTER TYPE resource_type_enum ADD VALUE IF NOT EXISTS 'SSLSandbox';

COMMIT;

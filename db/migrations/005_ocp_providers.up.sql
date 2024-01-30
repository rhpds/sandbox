-- Create table Ocp_providers

BEGIN;

CREATE TABLE Ocp_providers (
    id SERIAL PRIMARY KEY,
    name  VARCHAR(64) NOT NULL, -- Name for the Ocp Provider
    api_url VARCHAR(255) NOT NULL, -- OCP Api URL
    kubeconfig text NOT NULL, -- kubeconfig content on base64
    created_at timestamp with time zone NOT NULL DEFAULT (now() at time zone 'utc'),
    updated_at timestamp with time zone NOT NULL DEFAULT (now() at time zone 'utc'),
    annotations jsonb DEFAULT '{}',
    valid BOOLEAN NOT NULL DEFAULT TRUE -- Used to invalidate Ocp_providers
);

CREATE TRIGGER Ocp_providers_updated_at
  BEFORE UPDATE ON Ocp_providers
  FOR EACH ROW
  WHEN (OLD.* IS DISTINCT FROM NEW.*)
  EXECUTE FUNCTION updated_at_column();

CREATE INDEX ON Ocp_providers (api_url);
COMMIT;

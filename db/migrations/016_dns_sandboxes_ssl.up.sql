-- Create table dns_account_configurations

BEGIN;
-- Add ssl_auth_eab_kid column to the dns_account_configurations table of type VARCHAR(255)
-- default value ''
ALTER TABLE dns_account_configurations ADD COLUMN ssl_auth_eab_kid VARCHAR(255) DEFAULT '';

-- Add ssl_auth_eab_hmac column to the dns_account_configurations table of type bytea 
ALTER TABLE dns_account_configurations ADD COLUMN ssl_auth_eab_hmac BYTEA;

-- Add ssl_auth_provider column to the dns_account_configurations table of type VARCHAR(255)
-- default value ''
ALTER TABLE dns_account_configurations ADD COLUMN ssl_auth_provider VARCHAR(255) DEFAULT '';

-- Add ssl_auth_acme_directory column to the dns_account_configurations table of type VARCHAR(255)
-- default value ''
ALTER TABLE dns_account_configurations ADD COLUMN ssl_auth_acme_directory VARCHAR(255) DEFAULT '';

COMMIT;


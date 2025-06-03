-- Add columns for SSL generation

BEGIN;
-- Drop ssl_auth_eab_kid column from the dns_account_configurations table 
ALTER TABLE dns_account_configurations DROP COLUMN ssl_auth_eab_kid; 

-- Drop ssl_auth_eab_hmac column from the dns_account_configurations table
ALTER TABLE dns_account_configurations DROP COLUMN ssl_auth_eab_hmac;

-- Drop ssl_auth_provider column from the dns_account_configurations table
ALTER TABLE dns_account_configurations DROP COLUMN ssl_auth_provider;

-- Drop ssl_auth_acme_directory column from the dns_account_configurations table
ALTER TABLE dns_account_configurations DROP COLUMN ssl_auth_acme_directory;

COMMIT;


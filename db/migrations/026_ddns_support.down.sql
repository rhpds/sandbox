BEGIN;

-- Remove DDNS configurations before restoring NOT NULL constraints.
DELETE FROM dns_account_configurations WHERE provider_type != 'route53';

ALTER TABLE dns_account_configurations
    ALTER COLUMN aws_access_key_id SET NOT NULL,
    ALTER COLUMN aws_secret_access_key SET NOT NULL,
    ALTER COLUMN hosted_zone_id SET NOT NULL;

ALTER TABLE dns_account_configurations
    DROP COLUMN IF EXISTS token,
    DROP COLUMN IF EXISTS endpoint,
    DROP COLUMN IF EXISTS provider_type;

COMMIT;

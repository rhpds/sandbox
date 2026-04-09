BEGIN;

-- Add DDNS support to dns_account_configurations.
-- provider_type distinguishes Route53 (existing) from DDNS (BIND TSIG key API).

ALTER TABLE dns_account_configurations
    ADD COLUMN provider_type VARCHAR(32) NOT NULL DEFAULT 'route53',
    ADD COLUMN endpoint VARCHAR(512),
    ADD COLUMN token BYTEA;

-- AWS-specific fields are not needed for DDNS configurations.
ALTER TABLE dns_account_configurations
    ALTER COLUMN aws_access_key_id DROP NOT NULL,
    ALTER COLUMN aws_secret_access_key DROP NOT NULL,
    ALTER COLUMN hosted_zone_id DROP NOT NULL;

COMMIT;

-- Update the lifecycle_resource_jobs table by adding a column 'locality'

-- Default to 'any'
ALTER TABLE lifecycle_placement_jobs ADD COLUMN locality VARCHAR(128) NOT NULL DEFAULT 'any';
ALTER TABLE lifecycle_resource_jobs  ADD COLUMN locality VARCHAR(128) NOT NULL DEFAULT 'any';

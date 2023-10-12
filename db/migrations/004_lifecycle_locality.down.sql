-- Update the lifecycle_resource_jobs table by removing the column 'locality'

ALTER TABLE lifecycle_resource_jobs DROP COLUMN locality;
ALTER TABLE lifecycle_placement_jobs DROP COLUMN locality;

CREATE TYPE job_status AS ENUM ('new', 'initializing', 'initialized', 'running', 'successfully_dispatched', 'success', 'error');
CREATE TYPE lifecycle_action AS ENUM ('start', 'stop', 'status');

-- Jobs for placements
CREATE TABLE lifecycle_placement_jobs (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  placement_id INT NOT NULL REFERENCES placements(id) ON DELETE CASCADE,
  request_id VARCHAR(128) NULL,
  created_at timestamp with time zone NOT NULL DEFAULT (now() at time zone 'utc'),
  updated_at timestamp with time zone NOT NULL DEFAULT (now() at time zone 'utc'),
  status job_status NOT NULL DEFAULT 'new',
  lifecycle_action lifecycle_action NOT NULL,
  request jsonb DEFAULT '{}',
  annotations jsonb DEFAULT '{}'
);

CREATE TRIGGER lifecycle_placement_jobs_updated_at
  BEFORE UPDATE ON lifecycle_placement_jobs
  FOR EACH ROW
  WHEN (OLD.* IS DISTINCT FROM NEW.*)
  EXECUTE FUNCTION updated_at_column();


CREATE OR REPLACE FUNCTION lifecycle_placement_jobs_status_notify()
	RETURNS trigger AS
$$
BEGIN
	PERFORM pg_notify('lifecycle_placement_jobs_status_channel', NEW.id::text);
	RETURN NEW;
END;
$$ LANGUAGE plpgsql;


CREATE TRIGGER lifecycle_placement_jobs_status
	AFTER INSERT OR UPDATE OF status
	ON lifecycle_placement_jobs
	FOR EACH ROW
EXECUTE PROCEDURE lifecycle_placement_jobs_status_notify();


-- Jobs for resources
CREATE TABLE lifecycle_resource_jobs (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  parent_id BIGINT DEFAULT NULL REFERENCES lifecycle_placement_jobs(id) ON DELETE CASCADE,
  request_id VARCHAR(128) NULL DEFAULT NULL,
  -- Resource identification ----------------------------------------------
  -- TODO: change id to NOT NULL when we have all resources inside postgres
  resource_id INT NULL DEFAULT NULL REFERENCES resources(id) ON DELETE CASCADE,
  -- Alternative id (resource_name, resource_type)
  resource_name VARCHAR(128) NULL,
  resource_type VARCHAR(32) NULL,

  -- ----------------------------------------------------------------------
  created_at timestamp with time zone NOT NULL DEFAULT (now() at time zone 'utc'),
  updated_at timestamp with time zone NOT NULL DEFAULT (now() at time zone 'utc'),
  status job_status NOT NULL DEFAULT 'new',
  lifecycle_action lifecycle_action NOT NULL,
  request jsonb DEFAULT '{}',
  lifecycle_result jsonb DEFAULT '{}',
  annotations jsonb DEFAULT '{}'
);

CREATE TRIGGER lifecycle_resource_jobs_updated_at
  BEFORE UPDATE ON lifecycle_resource_jobs
  FOR EACH ROW
  WHEN (OLD.* IS DISTINCT FROM NEW.*)
  EXECUTE FUNCTION updated_at_column();

CREATE OR REPLACE FUNCTION lifecycle_resource_jobs_status_notify()
	RETURNS trigger AS
$$
BEGIN
	PERFORM pg_notify('lifecycle_resource_jobs_status_channel', NEW.id::text);
	RETURN NEW;
END;
$$ LANGUAGE plpgsql;


CREATE TRIGGER lifecycle_resource_jobs_status
	AFTER INSERT OR UPDATE OF status
	ON lifecycle_resource_jobs
	FOR EACH ROW
EXECUTE PROCEDURE lifecycle_resource_jobs_status_notify();

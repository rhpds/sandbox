-- Table for generic jobs (free form)
CREATE TABLE jobs (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  request_id VARCHAR(128) NOT NULL UNIQUE,
  placement_id BIGINT DEFAULT NULL REFERENCES placements(id) ON DELETE CASCADE,
  parent_job_id BIGINT DEFAULT NULL REFERENCES jobs(id) ON DELETE CASCADE,
  created_at timestamp with time zone NOT NULL DEFAULT (now() at time zone 'utc'),
  updated_at timestamp with time zone NOT NULL DEFAULT (now() at time zone 'utc'),
  completed_at timestamp with time zone DEFAULT NULL,
  locality VARCHAR(128) NOT NULL DEFAULT 'any',
  status job_status NOT NULL DEFAULT 'new',
  job_type VARCHAR(32) NOT NULL,
  body jsonb DEFAULT '{}'
);

CREATE TRIGGER jobs_updated_at
  BEFORE UPDATE ON jobs
  FOR EACH ROW
  WHEN (OLD.* IS DISTINCT FROM NEW.*)
  EXECUTE FUNCTION updated_at_column();

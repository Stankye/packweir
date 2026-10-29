ALTER TABLE artifacts ADD COLUMN package JSONB;
ALTER TABLE jobs ADD COLUMN engine_configuration TEXT;
ALTER TABLE jobs ADD COLUMN scope JSONB;
CREATE INDEX jobs_engine_queue ON jobs(engine_configuration, state, created_at);
CREATE TABLE package_claims (
    repository TEXT NOT NULL,
    origin TEXT NOT NULL,
    coordinate TEXT NOT NULL,
    source TEXT NOT NULL,
    package JSONB,
    PRIMARY KEY (repository, origin, coordinate)
);

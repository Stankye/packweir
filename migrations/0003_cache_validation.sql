-- Freshness is separate from identity updates and analysis/evidence validity.
ALTER TABLE artifacts ADD COLUMN last_validated_at TIMESTAMPTZ;

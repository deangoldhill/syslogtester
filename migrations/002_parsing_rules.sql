CREATE TABLE IF NOT EXISTS parsing_rules (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  name TEXT NOT NULL UNIQUE CHECK (char_length(name) BETWEEN 1 AND 80),
  match_literal TEXT NOT NULL CHECK (char_length(match_literal) BETWEEN 1 AND 120),
  delimiter TEXT NOT NULL CHECK (delimiter IN (',', '|', E'\t')),
  field_names JSONB NOT NULL CHECK (
    jsonb_typeof(field_names) = 'array'
    AND jsonb_array_length(field_names) BETWEEN 1 AND 32
  ),
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_parsing_rules_created_at ON parsing_rules (created_at DESC);

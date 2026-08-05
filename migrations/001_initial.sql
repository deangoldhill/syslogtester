CREATE TABLE IF NOT EXISTS schema_migrations (
  version TEXT PRIMARY KEY,
  applied_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS listeners (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  port INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
  protocol TEXT NOT NULL CHECK (protocol IN ('udp', 'tcp')),
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE (port, protocol)
);

CREATE TABLE IF NOT EXISTS messages (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  received_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  listener_id BIGINT REFERENCES listeners(id) ON DELETE SET NULL,
  source_ip INET NOT NULL,
  source_port INTEGER NOT NULL CHECK (source_port BETWEEN 0 AND 65535),
  facility SMALLINT,
  severity SMALLINT,
  hostname TEXT,
  app_name TEXT,
  message TEXT NOT NULL,
  raw TEXT NOT NULL,
  event_time TEXT,
  syslog_version SMALLINT,
  process_id TEXT,
  event_type TEXT
);

CREATE TABLE IF NOT EXISTS message_fields (
  message_id BIGINT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
  field_name TEXT NOT NULL,
  field_value TEXT NOT NULL,
  PRIMARY KEY (message_id, field_name)
);

CREATE TABLE IF NOT EXISTS settings (
  setting_key TEXT PRIMARY KEY,
  setting_value TEXT NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO settings(setting_key, setting_value)
VALUES ('retention_days', '30')
ON CONFLICT (setting_key) DO NOTHING;

CREATE INDEX IF NOT EXISTS idx_messages_received_at ON messages (received_at DESC);
CREATE INDEX IF NOT EXISTS idx_messages_listener ON messages (listener_id);
CREATE INDEX IF NOT EXISTS idx_messages_hostname ON messages (hostname);
CREATE INDEX IF NOT EXISTS idx_messages_app_name ON messages (app_name);
CREATE INDEX IF NOT EXISTS idx_messages_event_type ON messages (event_type);
CREATE INDEX IF NOT EXISTS idx_message_fields_lookup ON message_fields (field_name, field_value, message_id);
CREATE INDEX IF NOT EXISTS idx_messages_search ON messages USING GIN (
  to_tsvector('simple', coalesce(raw, '') || ' ' || coalesce(hostname, '') || ' ' || coalesce(app_name, '') || ' ' || coalesce(event_type, ''))
);

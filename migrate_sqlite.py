#!/usr/bin/env python3
"""One-time, idempotent import of the legacy SQLite Syslog Command Center data."""
import os
import sqlite3

import psycopg

SOURCE = os.environ.get("LEGACY_SQLITE_PATH", "/source/syslog.db")
DATABASE_URL = os.environ["DATABASE_URL"]


def rows(connection, table, columns):
    return connection.execute(f"SELECT {','.join(columns)} FROM {table}")


def main():
    if not os.path.exists(SOURCE):
        print("legacy SQLite database not found; nothing to import")
        return
    source = sqlite3.connect(SOURCE)
    source.row_factory = sqlite3.Row
    with psycopg.connect(DATABASE_URL) as target:
        existing = target.execute("SELECT COUNT(*) FROM messages").fetchone()[0]
        if existing:
            raise SystemExit("target PostgreSQL messages table is not empty; refusing duplicate import")
        listener_ids = {}
        for row in rows(source, "listeners", ("id", "port", "protocol", "enabled", "created_at")):
            created = target.execute("INSERT INTO listeners(port,protocol,enabled,created_at) VALUES(%s,%s,%s,%s) RETURNING id", (row["port"], row["protocol"], bool(row["enabled"]), row["created_at"])).fetchone()[0]
            listener_ids[row["id"]] = created
        message_ids = {}
        for row in rows(source, "messages", ("id", "received_at", "listener_id", "source_ip", "source_port", "facility", "severity", "hostname", "app_name", "message", "raw", "event_time", "syslog_version", "process_id", "event_type")):
            new_id = target.execute("""INSERT INTO messages(received_at,listener_id,source_ip,source_port,facility,severity,hostname,app_name,message,raw,event_time,syslog_version,process_id,event_type)
            VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id""", (row["received_at"], listener_ids.get(row["listener_id"]), row["source_ip"], row["source_port"], row["facility"], row["severity"], row["hostname"], row["app_name"], row["message"], row["raw"], row["event_time"], row["syslog_version"], row["process_id"], row["event_type"])).fetchone()[0]
            message_ids[row["id"]] = new_id
        with target.cursor() as cursor:
            cursor.executemany("INSERT INTO message_fields(message_id,field_name,field_value) VALUES(%s,%s,%s)", [(message_ids[row["message_id"]], row["field_name"], row["field_value"]) for row in rows(source, "message_fields", ("message_id", "field_name", "field_value")) if row["message_id"] in message_ids])
        target.commit()
        print(f"imported {len(listener_ids)} listeners, {len(message_ids)} messages")


if __name__ == "__main__":
    main()

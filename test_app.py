import os
import unittest
from unittest.mock import patch

import app


class PostgreSqlAndAdminTests(unittest.TestCase):
    def test_forward_auth_identity_requires_exact_dean_header(self):
        self.assertTrue(app.is_dean({"Remote-User": "dean"}))
        self.assertFalse(app.is_dean({"Remote-User": "Dean"}))
        self.assertFalse(app.is_dean({}))
        self.assertFalse(app.is_dean({"Remote-User": "dean,other"}))

    def test_retention_requires_a_bounded_integer_day_count(self):
        self.assertEqual(app.parse_retention_days("30"), 30)
        for invalid in ("0", "3651", "1.5", "thirty", None):
            with self.assertRaises(ValueError):
                app.parse_retention_days(invalid)

    def test_postgresql_migrations_define_search_and_operational_indexes(self):
        migration_sql = "\n".join(app.load_migration_sql())
        self.assertIn("CREATE TABLE IF NOT EXISTS schema_migrations", migration_sql)
        self.assertIn("tsvector", migration_sql.lower())
        self.assertIn("USING GIN", migration_sql)
        self.assertIn("idx_messages_received_at", migration_sql)
        self.assertIn("idx_message_fields_lookup", migration_sql)
        self.assertNotIn("AUTOINCREMENT", migration_sql.upper())

    def test_admin_page_is_explicitly_proxy_authenticated_and_has_only_scoped_controls(self):
        self.assertIn("ForwardAuth identity", app.ADMIN_PAGE)
        self.assertIn("Retention (days)", app.ADMIN_PAGE)
        self.assertIn("/api/admin/listeners", app.ADMIN_PAGE)
        self.assertNotIn("password", app.ADMIN_PAGE.lower())
        self.assertNotIn("totp", app.ADMIN_PAGE.lower())

    def test_palo_alto_traffic_csv_is_normalized_to_searchable_fields(self):
        line = "15:22:01,007954000734581,TRAFFIC,end,3073,2026/08/06 15:22:01,192.168.5.100,142.251.29.95,91.228.233.131,142.251.29.95,User-Internet,,,quic-base,vsys1,User,WAN,ethernet1/3,ethernet1/1,Traffic-Syslog,2026/08/06 15:22:01,661504,1,63521,443,11725,443,0x400053,udp,allow,11493,5106,6387,26,2026/08/06 15:19:56,1"
        fields = app.parse_palo_alto_fields(line)
        observed = app.parse_syslog("<134>Aug  6 15:22:01 PANFW.deanscloud.com 1,2026/08/06 " + line)
        self.assertEqual(fields["vendor"], "paloalto")
        self.assertEqual(observed["fields"]["vendor"], "paloalto")
        self.assertEqual(fields["pan_log_type"], "traffic")
        self.assertEqual(fields["src_ip"], "192.168.5.100")
        self.assertEqual(fields["dst_ip"], "142.251.29.95")
        self.assertEqual(fields["rule"], "User-Internet")
        self.assertEqual(fields["source_zone"], "User")
        self.assertEqual(fields["destination_zone"], "WAN")
        self.assertEqual(fields["action"], "allow")

    def test_insights_page_and_api_expose_operational_explorer_capabilities(self):
        self.assertIn("Investigation Workspace", app.INSIGHTS_PAGE)
        self.assertIn("/api/insights", app.INSIGHTS_PAGE)
        self.assertIn("Last 24 hours", app.INSIGHTS_PAGE)
        self.assertIn("severity", app.insight_query_spec()["facets"])
        self.assertIn("application", app.insight_query_spec()["facets"])

    def test_compose_has_no_browser_or_database_port_published(self):
        with open(os.path.join(os.path.dirname(__file__), "compose.yaml"), encoding="utf-8") as compose_file:
            compose = compose_file.read()
        self.assertIn("postgres:", compose)
        self.assertNotIn('"${WEB_PORT', compose)
        self.assertNotIn('"5432:5432"', compose)
        self.assertIn("traefik", compose)


if __name__ == "__main__":
    unittest.main()

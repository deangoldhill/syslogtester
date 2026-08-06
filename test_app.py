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
        self.assertIn("CREATE TABLE IF NOT EXISTS parsing_rules", migration_sql)
        self.assertIn("jsonb_array_length(field_names) BETWEEN 1 AND 32", migration_sql)
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

    def test_navigation_uses_responsive_dashboard_investigate_admin_tabs(self):
        for page in (app.PAGE, app.INSIGHTS_PAGE, app.ADMIN_PAGE):
            self.assertIn('role="tablist"', page)
            self.assertIn(">Dashboard<", page)
            self.assertIn(">Investigate<", page)
            self.assertIn(">Admin<", page)
            self.assertIn("@media", page)

    def test_built_in_rules_identify_the_existing_pan_os_csv_parser(self):
        rules = app.built_in_parsing_rules()
        self.assertTrue(any(rule["id"] == "pan-os-csv" for rule in rules))
        self.assertTrue(any("PAN-OS" in rule["name"] for rule in rules))

    def test_user_defined_rule_validation_is_bounded_and_does_not_accept_code_or_regex(self):
        rule = app.validate_user_defined_rule({
            "name": "Appliance events", "match_literal": "ACME,", "delimiter": "comma",
            "field_names": "device_id, event_type, severity",
        })
        self.assertEqual(rule["delimiter"], ",")
        self.assertEqual(rule["field_names"], ["device_id", "event_type", "severity"])
        invalid_rules = (
            {"name": "bad", "match_literal": "x" * 121, "delimiter": ",", "field_names": "one"},
            {"name": "bad", "match_literal": "x", "delimiter": ";", "field_names": "one"},
            {"name": "bad", "match_literal": "x", "delimiter": ",", "field_names": "one,(.*)"},
            {"name": "bad", "match_literal": "x", "delimiter": ",", "field_names": ",".join(f"f{i}" for i in range(33))},
        )
        for invalid in invalid_rules:
            with self.assertRaises(ValueError):
                app.validate_user_defined_rule(invalid)

    def test_user_defined_delimited_rules_extract_only_bounded_values_on_literal_match(self):
        rules = [{"match_literal": "ACME,", "delimiter": ",", "field_names": ["device_id", "event_type", "severity"]}]
        self.assertEqual(
            app.parse_user_defined_fields("ACME,edge-1,login,high", rules),
            {"device_id": "ACME", "event_type": "edge-1", "severity": "login"},
        )
        self.assertEqual(app.parse_user_defined_fields("OTHER,edge-1,login,high", rules), {})
        long_value = "x" * (app.MAX_FIELD_VALUE_LENGTH + 1)
        self.assertNotIn("event_type", app.parse_user_defined_fields(f"ACME,{long_value},high", rules))

    def test_parsing_rules_are_in_admin_page_and_dean_only_api_routes(self):
        self.assertIn("Parsing Rules", app.ADMIN_PAGE)
        self.assertIn("/api/admin/parsing-rules", app.ADMIN_PAGE)
        handler_source = app.Handler.do_GET.__code__.co_consts + app.Handler.do_POST.__code__.co_consts
        self.assertIn("/api/admin/parsing-rules", handler_source)

    def test_compose_has_no_browser_or_database_port_published(self):
        with open(os.path.join(os.path.dirname(__file__), "compose.yaml"), encoding="utf-8") as compose_file:
            compose = compose_file.read()
        self.assertIn("postgres:", compose)
        self.assertNotIn('"${WEB_PORT', compose)
        self.assertNotIn('"5432:5432"', compose)
        self.assertIn("traefik", compose)


if __name__ == "__main__":
    unittest.main()

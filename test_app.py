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

    def test_compose_has_no_browser_or_database_port_published(self):
        with open(os.path.join(os.path.dirname(__file__), "compose.yaml"), encoding="utf-8") as compose_file:
            compose = compose_file.read()
        self.assertIn("postgres:", compose)
        self.assertNotIn('"${WEB_PORT', compose)
        self.assertNotIn('"5432:5432"', compose)
        self.assertIn("traefik", compose)


if __name__ == "__main__":
    unittest.main()

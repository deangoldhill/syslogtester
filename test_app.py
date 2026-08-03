import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

import app


class AdminAndAnalyticsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        app.DATA_DIR = self.tmp.name
        app.DB_PATH = os.path.join(self.tmp.name, "syslog.db")
        app.sessions.clear()
        app.setup_db()

    def tearDown(self):
        self.tmp.cleanup()

    def test_admin_passwords_are_salted_and_mfa_requires_a_valid_code(self):
        secret = "JBSWY3DPEHPK3PXP"
        admin_id = app.create_admin("alice", "correct horse battery staple", secret)
        with app.db() as con:
            stored = con.execute("SELECT password_hash FROM admins WHERE id=?", (admin_id,)).fetchone()["password_hash"]
        self.assertNotIn("correct horse battery staple", stored)
        self.assertFalse(app.authenticate_admin("alice", "wrong password", "000000"))
        self.assertFalse(app.authenticate_admin("alice", "correct horse battery staple", "000000"))
        self.assertTrue(app.authenticate_admin("alice", "correct horse battery staple", app.totp_code(secret)))

    def test_pending_mfa_enrolment_is_not_enforced_until_confirmed(self):
        admin_id = app.create_admin("bob", "correct horse battery staple")
        secret = app.start_totp_enrolment(admin_id)
        self.assertTrue(app.authenticate_admin("bob", "correct horse battery staple"))
        self.assertFalse(app.confirm_totp_enrolment(admin_id, "000000"))
        self.assertTrue(app.confirm_totp_enrolment(admin_id, app.totp_code(secret)))
        self.assertFalse(app.authenticate_admin("bob", "correct horse battery staple"))
        self.assertTrue(app.authenticate_admin("bob", "correct horse battery staple", app.totp_code(secret)))

    def test_dashboard_metrics_include_current_rate_and_per_host_counts(self):
        with app.db() as con:
            listener = con.execute("INSERT INTO listeners(port,protocol,created_at) VALUES(?,?,?)", (5514, "udp", app.now())).lastrowid
        app.store(listener, ("192.0.2.10", 5514), b"<13>Aug  3 12:00:00 radius-a auth: accepted username=alice")
        app.store(listener, ("192.0.2.11", 5514), b"<13>Aug  3 12:00:01 radius-b auth: rejected username=bob")
        app.store(listener, ("192.0.2.10", 5514), b"<13>Aug  3 12:00:02 radius-a auth: accepted username=carol")
        metrics = app.dashboard_metrics()
        self.assertEqual(metrics["total_messages"], 3)
        self.assertEqual(metrics["messages_last_minute"], 3)
        self.assertEqual(metrics["unique_hosts"], 2)
        self.assertEqual([(row["hostname"], row["count"]) for row in metrics["hosts"]], [("radius-a", 2), ("radius-b", 1)])
        self.assertEqual(sum(bucket["count"] for bucket in metrics["rate"]), 3)

    def test_tcp_buffer_limit_rejects_unterminated_oversized_frames(self):
        self.assertTrue(app.tcp_buffer_within_limit(b"x" * app.MAX_TCP_MESSAGE_BYTES))
        self.assertFalse(app.tcp_buffer_within_limit(b"x" * (app.MAX_TCP_MESSAGE_BYTES + 1)))

    def test_totp_code_cannot_be_reused_for_a_second_login(self):
        secret = "JBSWY3DPEHPK3PXP"
        app.create_admin("replay", "correct horse battery staple", secret)
        code = app.totp_code(secret)
        self.assertTrue(app.authenticate_admin("replay", "correct horse battery staple", code))
        self.assertFalse(app.authenticate_admin("replay", "correct horse battery staple", code))

    def test_json_object_rejects_valid_non_object_json(self):
        with self.assertRaises(ValueError):
            app.json_object(b"[]")

    def test_mfa_enrollment_revokes_other_sessions_for_the_same_admin(self):
        admin_id = app.create_admin("sessions", "correct horse battery staple")
        with app.db() as con: admin = dict(con.execute("SELECT * FROM admins WHERE id=?", (admin_id,)).fetchone())
        keep = app.create_session(admin)
        other = app.create_session(admin)
        app.revoke_other_sessions(admin_id, keep)
        self.assertIn(keep, app.sessions)
        self.assertNotIn(other, app.sessions)

    def test_direct_http_cookie_omits_secure_attribute_but_https_cookie_includes_it(self):
        self.assertNotIn("; Secure", app.session_cookie("token", secure=False))
        self.assertIn("; Secure", app.session_cookie("token", secure=True))

    def test_login_failure_page_includes_a_clear_error(self):
        self.assertIn("Incorrect username, password, or MFA code.", app.login_page("Incorrect username, password, or MFA code."))

    def test_four_character_password_is_accepted(self):
        self.assertIsInstance(app.create_admin("tiny", "pass"), int)

    def test_configuration_page_is_separate_from_dashboard(self):
        self.assertIn("Configuration", app.CONFIG_PAGE)
        self.assertNotIn("Search & correlation", app.CONFIG_PAGE)
        self.assertIn('href="/config"', app.PAGE)

    def test_db_context_manager_closes_connections(self):
        with app.db() as con:
            con.execute("SELECT 1")
        with self.assertRaises(Exception):
            con.execute("SELECT 1")

    def test_tabs_logout_and_per_admin_mfa_controls_are_rendered(self):
        self.assertIn('class="tabs"', app.PAGE)
        self.assertIn('action="/logout"', app.PAGE)
        self.assertIn('class="tabs"', app.CONFIG_PAGE)
        self.assertIn('enrolMfa(${v.id})', app.CONFIG_PAGE)
        self.assertIn("'/api/admins/'+id+'/totp'", app.CONFIG_PAGE)


if __name__ == "__main__":
    unittest.main()

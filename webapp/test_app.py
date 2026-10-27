import unittest
from app import app

class WebAppTests(unittest.TestCase):
    def setUp(self):
        app.config["TESTING"] = True
        self.client = app.test_client()

    def test_dashboard_requires_login(self):
        response = self.client.get("/")
        self.assertIn(response.status_code, (301, 302))
        self.assertIn("/login", response.headers["Location"])

    def test_login_page_loads(self):
        response = self.client.get("/login")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"TraceForge", response.data)

    def test_security_headers(self):
        response = self.client.get("/login")
        self.assertEqual(response.headers["X-Frame-Options"], "DENY")
        self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")

    def test_login_requires_csrf(self):
        response = self.client.post("/login", data={"password": "wrong"})
        self.assertEqual(response.status_code, 400)


    def logged_in_client(self):
        with self.client.session_transaction() as sess:
            sess["authenticated"] = True
            sess["csrf_token"] = "test-token"
        return self.client

    def test_analysis_requires_login(self):
        response = self.client.get("/analysis")
        self.assertIn(response.status_code, (301, 302))

    def test_analysis_page_loads_when_authenticated(self):
        response = self.logged_in_client().get("/analysis")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Risk is a review priority", response.data)

    def test_integrity_page_loads_when_authenticated(self):
        response = self.logged_in_client().get("/integrity")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"SHA-256", response.data)

    def test_csv_export_requires_login(self):
        response = self.client.get("/export/incidents.csv")
        self.assertIn(response.status_code, (301, 302))

    def test_json_analysis_export_when_authenticated(self):
        response = self.logged_in_client().get("/export/analysis.json")
        self.assertEqual(response.status_code, 200)
        self.assertIn("application/json", response.headers["Content-Type"])

if __name__ == "__main__":
    unittest.main()

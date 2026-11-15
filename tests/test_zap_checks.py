import unittest

from index import BASIC_TESTS, DEEP_TESTS, build_test_results


def run_one(test_group, alerts=None, missing_headers=None):
    return build_test_results([test_group], alerts or [], missing_headers)[0]


class BasicTierTests(unittest.TestCase):
    def test_1_missing_security_headers(self):
        self.assertEqual(len(BASIC_TESTS), 5)
        result = run_one(BASIC_TESTS[0], missing_headers=["content-security-policy"])
        self.assertEqual(result["status"], "FAIL")
        self.assertIn("content-security-policy", result["evidence"][0])

    def test_2_cookie_flags(self):
        result = run_one(BASIC_TESTS[1], [{"pluginId": "10011", "name": "Cookie Without Secure Flag"}])
        self.assertEqual(result["status"], "FAIL")
        self.assertEqual(result["alert_count"], 1)

    def test_3_vulnerable_javascript_libraries(self):
        result = run_one(BASIC_TESTS[2], [{"pluginId": "10003", "name": "Vulnerable JS Library"}])
        self.assertEqual(result["status"], "FAIL")

    def test_4_server_version_disclosure(self):
        result = run_one(BASIC_TESTS[3], [{"pluginId": "10036", "name": "Server Leaks Version Information"}])
        self.assertEqual(result["status"], "FAIL")

    def test_5_directory_browsing(self):
        result = run_one(BASIC_TESTS[4], [{"pluginId": "10033", "name": "Directory Browsing"}])
        self.assertEqual(result["status"], "FAIL")


class DeepTierTests(unittest.TestCase):
    def test_1_reflected_xss_plugin_40012(self):
        self.assertEqual(len(DEEP_TESTS), 5)
        result = run_one(DEEP_TESTS[0], [{"pluginId": "40012", "name": "Cross Site Scripting (Reflected)"}])
        self.assertEqual(result["status"], "FAIL")

    def test_2_sql_injection_plugin_40018(self):
        result = run_one(DEEP_TESTS[1], [{"pluginId": "40018", "name": "SQL Injection"}])
        self.assertEqual(result["status"], "FAIL")

    def test_3_open_redirect_plugin_20019(self):
        result = run_one(DEEP_TESTS[2], [{"pluginId": "20019-2", "name": "External Redirect"}])
        self.assertEqual(result["status"], "FAIL")

    def test_4_git_exposure_plugin_41(self):
        result = run_one(DEEP_TESTS[3], [{"pluginId": "41", "name": "Source Code Disclosure - Git"}])
        self.assertEqual(result["status"], "FAIL")

    def test_5_cors_plugin_40040(self):
        result = run_one(DEEP_TESTS[4], [{"pluginId": "40040-2", "name": "CORS Misconfiguration"}])
        self.assertEqual(result["status"], "FAIL")


if __name__ == "__main__":
    unittest.main()

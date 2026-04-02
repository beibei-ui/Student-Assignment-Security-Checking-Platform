import json
import os
import sys
import unittest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "lambda_b"))

from scanner import SecurityScanner


def _make_semgrep_result(findings=None):
    """Return a mock subprocess.CompletedProcess for a successful semgrep run."""
    output = json.dumps({"results": findings or []})
    mock = MagicMock()
    mock.returncode = 0
    mock.stdout = output
    mock.stderr = ""
    return mock


class TestScannerLanguageRouting(unittest.TestCase):
    """
    Verify that the five previously-unsupported languages (typescript, go,
    ruby, c, cpp) are routed to Semgrep and given the correct file extension.
    """

    def _run_scan(self, language):
        """Helper: run scan_code with subprocess.run mocked out."""
        with patch("scanner.subprocess.run", return_value=_make_semgrep_result()) as mock_run:
            scanner = SecurityScanner()
            result = scanner.scan_code("// sample code", language, "test-scan-id")
        return result, mock_run

    def _assert_semgrep_with_ext(self, language, expected_ext):
        result, mock_run = self._run_scan(language)
        # tool should be semgrep, not error
        self.assertEqual(result["tool"], "semgrep", f"{language}: expected semgrep, got {result.get('tool')}")
        # the file passed to semgrep should have the correct extension
        called_file = mock_run.call_args[0][0][-1]
        self.assertTrue(
            called_file.endswith(expected_ext),
            f"{language}: expected extension {expected_ext}, got {called_file}"
        )

    def test_typescript_routes_to_semgrep_with_ts_extension(self):
        self._assert_semgrep_with_ext("typescript", ".ts")

    def test_go_routes_to_semgrep_with_go_extension(self):
        self._assert_semgrep_with_ext("go", ".go")

    def test_ruby_routes_to_semgrep_with_rb_extension(self):
        self._assert_semgrep_with_ext("ruby", ".rb")

    def test_c_routes_to_semgrep_with_c_extension(self):
        self._assert_semgrep_with_ext("c", ".c")

    def test_cpp_routes_to_semgrep_with_cpp_extension(self):
        self._assert_semgrep_with_ext("cpp", ".cpp")

    def test_unsupported_language_returns_error(self):
        result, _ = self._run_scan("cobol")
        self.assertEqual(result["tool"], "error")

    def test_typescript_case_insensitive(self):
        self._assert_semgrep_with_ext("TypeScript", ".ts")


if __name__ == "__main__":
    unittest.main()

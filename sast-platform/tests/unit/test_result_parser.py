import os
import sys
import unittest


sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "lambda_b"))

from result_parser import normalize_result, parse_bandit_output, parse_semgrep_output


class TestResultParser(unittest.TestCase):
	def test_parse_bandit_output_normalizes_fields(self):
		raw = {
			"results": [
				{
					"line_number": 5,
					"issue_severity": "HIGH",
					"issue_confidence": "MEDIUM",
					"issue_text": "Use of exec detected",
					"code": "exec(user_input)",
					"test_id": "B102",
				}
			]
		}

		parsed = parse_bandit_output(raw, scan_id="scan-1", language="python")

		self.assertEqual(parsed["scan_id"], "scan-1")
		self.assertEqual(parsed["tool"], "bandit")
		self.assertEqual(parsed["vuln_count"], 1)
		self.assertEqual(parsed["summary"], {"HIGH": 1, "MEDIUM": 0, "LOW": 0})
		self.assertEqual(parsed["findings"][0]["rule_id"], "B102")

	def test_parse_semgrep_output_normalizes_fields(self):
		raw = {
			"results": [
				{
					"check_id": "javascript.lang.security.audit.eval",
					"start": {"line": 12},
					"extra": {
						"severity": "WARNING",
						"message": "Avoid eval()",
						"lines": "eval(userInput)",
						"metadata": {"confidence": "HIGH"},
					},
				}
			]
		}

		parsed = parse_semgrep_output(raw, scan_id="scan-2", language="javascript")

		self.assertEqual(parsed["scan_id"], "scan-2")
		self.assertEqual(parsed["tool"], "semgrep")
		self.assertEqual(parsed["vuln_count"], 1)
		self.assertEqual(parsed["summary"], {"HIGH": 0, "MEDIUM": 1, "LOW": 0})
		self.assertEqual(parsed["findings"][0]["line"], 12)

	def test_empty_output_returns_zero_summary(self):
		parsed = normalize_result(
			tool="bandit",
			raw_output={},
			scan_id="scan-3",
			language="python",
		)

		self.assertEqual(parsed["findings"], [])
		self.assertEqual(parsed["summary"], {"HIGH": 0, "MEDIUM": 0, "LOW": 0})
		self.assertEqual(parsed["vuln_count"], 0)

	def test_missing_fields_fallback_values(self):
		raw = {
			"results": [
				{
					"start": {},
					"extra": {},
				}
			]
		}

		parsed = parse_semgrep_output(raw, scan_id="scan-4", language="java")
		finding = parsed["findings"][0]

		self.assertEqual(finding["line"], 0)
		self.assertEqual(finding["severity"], "LOW")
		self.assertEqual(finding["confidence"], "UNKNOWN")
		self.assertEqual(finding["rule_id"], "UNKNOWN")

	def test_unsupported_tool_raises_value_error(self):
		with self.assertRaises(ValueError):
			normalize_result("unknown", {}, "scan-5", "python")


if __name__ == "__main__":
	unittest.main()


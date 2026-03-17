import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "lambda_b"))

import result_parser


def test_parse_bandit_output_normalizes_fields():
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

	parsed = result_parser.parse_bandit_output(raw, scan_id="scan-1", language="python")

	assert parsed["scan_id"] == "scan-1"
	assert parsed["tool"] == "bandit"
	assert parsed["vuln_count"] == 1
	assert parsed["summary"] == {"HIGH": 1, "MEDIUM": 0, "LOW": 0}
	assert parsed["findings"][0]["rule_id"] == "B102"


def test_parse_semgrep_output_normalizes_fields():
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

	parsed = result_parser.parse_semgrep_output(raw, scan_id="scan-2", language="javascript")

	assert parsed["scan_id"] == "scan-2"
	assert parsed["tool"] == "semgrep"
	assert parsed["vuln_count"] == 1
	assert parsed["summary"] == {"HIGH": 0, "MEDIUM": 1, "LOW": 0}
	assert parsed["findings"][0]["line"] == 12


def test_empty_output_returns_zero_summary():
	parsed = result_parser.normalize_result(
		tool="bandit",
		raw_output={},
		scan_id="scan-3",
		language="python",
	)

	assert parsed["findings"] == []
	assert parsed["summary"] == {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
	assert parsed["vuln_count"] == 0


def test_missing_fields_fallback_values():
	raw = {
		"results": [
			{
				"start": {},
				"extra": {},
			}
		]
	}

	parsed = result_parser.parse_semgrep_output(raw, scan_id="scan-4", language="java")
	finding = parsed["findings"][0]

	assert finding["line"] == 0
	assert finding["severity"] == "LOW"
	assert finding["confidence"] == "UNKNOWN"
	assert finding["rule_id"] == "UNKNOWN"


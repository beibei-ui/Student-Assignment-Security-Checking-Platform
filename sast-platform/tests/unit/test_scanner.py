"""
单元测试 - scanner.py
测试 Bandit 和 Semgrep 扫描引擎的功能
"""
import unittest
from unittest.mock import patch, MagicMock
import json
import tempfile
import os
import sys

# 添加 lambda_b 目录到 Python 路径
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'lambda_b'))

from scanner import SecurityScanner, scan_code_with_timeout


class TestSecurityScanner(unittest.TestCase):
    """SecurityScanner 类的单元测试"""
    
    def setUp(self):
        """测试前准备"""
        self.scanner = SecurityScanner()
        self.test_scan_id = "test-scan-123"
    
    def test_scan_python_code_success(self):
        """测试成功扫描 Python 代码"""
        python_code = """
import os
password = "hardcoded_password"
os.system("rm -rf /")
exec(user_input)
"""
        
        with patch('scanner.subprocess.run') as mock_run:
            # 模拟 Bandit 成功执行
            mock_result = MagicMock()
            mock_result.returncode = 1  # Bandit 发现问题时返回 1
            mock_result.stdout = json.dumps({
                "results": [
                    {
                        "code": "exec(user_input)",
                        "filename": "test.py",
                        "issue_confidence": "HIGH",
                        "issue_severity": "HIGH",
                        "issue_text": "Use of exec detected.",
                        "line_number": 4,
                        "test_id": "B102",
                        "test_name": "exec_used"
                    }
                ],
                "metrics": {
                    "SEVERITY.HIGH": 1,
                    "SEVERITY.MEDIUM": 0,
                    "SEVERITY.LOW": 0
                }
            })
            mock_result.stderr = ""
            mock_run.return_value = mock_result
            
            result = self.scanner.scan_code(python_code, "python", self.test_scan_id)
            
            self.assertEqual(result['scan_id'], self.test_scan_id)
            self.assertEqual(result['language'], 'python')
            self.assertEqual(result['tool'], 'bandit')
            self.assertIn('findings', result)
            self.assertEqual(len(result['findings']), 1)
    
    def test_scan_javascript_code_success(self):
        """测试成功扫描 JavaScript 代码"""
        js_code = """
const userInput = req.params.input;
const html = `<div>${userInput}</div>`;
eval(userInput);
"""
        
        with patch('scanner.subprocess.run') as mock_run:
            # 模拟 Semgrep 成功执行
            mock_result = MagicMock()
            mock_result.returncode = 1  # Semgrep 发现问题时返回 1
            mock_result.stdout = json.dumps({
                "results": [
                    {
                        "check_id": "javascript.lang.security.audit.eval-detected",
                        "path": "test.js",
                        "start": {"line": 3, "col": 0},
                        "end": {"line": 3, "col": 15},
                        "message": "Detected eval usage",
                        "severity": "WARNING",
                        "extra": {
                            "lines": "eval(userInput);",
                            "metadata": {}
                        }
                    }
                ]
            })
            mock_result.stderr = ""
            mock_run.return_value = mock_result
            
            result = self.scanner.scan_code(js_code, "javascript", self.test_scan_id)
            
            self.assertEqual(result['scan_id'], self.test_scan_id)
            self.assertEqual(result['language'], 'javascript')
            self.assertEqual(result['tool'], 'semgrep')
            self.assertIn('findings', result)
            self.assertEqual(len(result['findings']), 1)
    
    def test_scan_java_code_success(self):
        """测试成功扫描 Java 代码"""
        java_code = """
public class Test {
    public void vulnerable(String input) {
        Runtime.getRuntime().exec(input);
    }
}
"""
        
        with patch('scanner.subprocess.run') as mock_run:
            # 模拟 Semgrep 成功执行
            mock_result = MagicMock()
            mock_result.returncode = 0  # Semgrep 没有发现问题
            mock_result.stdout = json.dumps({"results": []})
            mock_result.stderr = ""
            mock_run.return_value = mock_result
            
            result = self.scanner.scan_code(java_code, "java", self.test_scan_id)
            
            self.assertEqual(result['scan_id'], self.test_scan_id)
            self.assertEqual(result['language'], 'java')
            self.assertEqual(result['tool'], 'semgrep')
            self.assertIn('findings', result)
            self.assertEqual(len(result['findings']), 0)
    
    def test_unsupported_language(self):
        """测试不支持的语言"""
        code = "print('hello')"
        
        result = self.scanner.scan_code(code, "ruby", self.test_scan_id)
        
        self.assertEqual(result['tool'], 'error')
        self.assertIn('不支持的语言类型', result['error'])
    
    def test_bandit_execution_error(self):
        """测试 Bandit 执行错误"""
        python_code = "print('hello')"
        
        with patch('scanner.subprocess.run') as mock_run:
            # 模拟 Bandit 执行失败
            mock_result = MagicMock()
            mock_result.returncode = 2  # Bandit 错误
            mock_result.stderr = "Bandit execution failed"
            mock_run.return_value = mock_result
            
            result = self.scanner.scan_code(python_code, "python", self.test_scan_id)
            
            self.assertEqual(result['tool'], 'error')
            self.assertIn('Bandit 执行失败', result['error'])
    
    def test_bandit_timeout(self):
        """测试 Bandit 超时"""
        python_code = "print('hello')"
        
        with patch('scanner.subprocess.run') as mock_run:
            # 模拟 Bandit 超时
            mock_run.side_effect = subprocess.TimeoutExpired('bandit', 300)
            
            result = self.scanner.scan_code(python_code, "python", self.test_scan_id)
            
            self.assertEqual(result['tool'], 'error')
            self.assertIn('Bandit 扫描超时', result['error'])
    
    def test_semgrep_json_parse_error(self):
        """测试 Semgrep JSON 解析错误"""
        js_code = "console.log('hello');"
        
        with patch('scanner.subprocess.run') as mock_run:
            # 模拟 Semgrep 返回无效 JSON
            mock_result = MagicMock()
            mock_result.returncode = 0
            mock_result.stdout = "invalid json output"
            mock_result.stderr = ""
            mock_run.return_value = mock_result
            
            result = self.scanner.scan_code(js_code, "javascript", self.test_scan_id)
            
            self.assertEqual(result['tool'], 'error')
            self.assertIn('Semgrep 输出解析失败', result['error'])
    
    def test_bandit_empty_output(self):
        """测试 Bandit 空输出（无问题发现）"""
        python_code = "print('hello world')"
        
        with patch('scanner.subprocess.run') as mock_run:
            # 模拟 Bandit 没有发现问题
            mock_result = MagicMock()
            mock_result.returncode = 0  # 无问题
            mock_result.stdout = ""
            mock_result.stderr = ""
            mock_run.return_value = mock_result
            
            result = self.scanner.scan_code(python_code, "python", self.test_scan_id)
            
            self.assertEqual(result['tool'], 'bandit')
            self.assertEqual(len(result['findings']), 0)
            self.assertIn('metrics', result)


class TestScanCodeWithTimeout(unittest.TestCase):
    """scan_code_with_timeout 函数的单元测试"""
    
    def test_scan_with_custom_timeout(self):
        """测试自定义超时时间"""
        code = "print('test')"
        
        with patch('scanner.SecurityScanner') as mock_scanner_class:
            mock_scanner = MagicMock()
            mock_scanner.scan_code.return_value = {
                'scan_id': 'test-123',
                'tool': 'bandit',
                'findings': []
            }
            mock_scanner_class.return_value = mock_scanner
            
            result = scan_code_with_timeout(code, "python", "test-123", timeout=600)
            
            mock_scanner.scan_code.assert_called_once_with(code, "python", "test-123")
            self.assertEqual(result['scan_id'], 'test-123')


if __name__ == '__main__':
    # 需要先导入 subprocess 模块
    import subprocess
    unittest.main()
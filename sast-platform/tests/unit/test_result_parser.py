"""
单元测试 - result_parser.py
测试结果解析器的功能，验证不同工具输出的标准化
"""
import unittest
import json
import os
import sys
from datetime import datetime

# 添加 lambda_b 目录到 Python 路径
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'lambda_b'))

from result_parser import ResultParser


class TestResultParser(unittest.TestCase):
    """ResultParser 类的单元测试"""
    
    def test_parse_bandit_result(self):
        """测试解析 Bandit 扫描结果"""
        raw_bandit_result = {
            'scan_id': 'test-scan-123',
            'language': 'python',
            'tool': 'bandit',
            'findings': [
                {
                    'code': 'exec(user_input)',
                    'filename': 'test.py',
                    'issue_confidence': 'HIGH',
                    'issue_severity': 'HIGH',
                    'issue_text': 'Use of exec detected.',
                    'line_number': 5,
                    'line_range': [5],
                    'more_info': 'https://bandit.readthedocs.io/en/latest/',
                    'test_id': 'B102',
                    'test_name': 'exec_used'
                },
                {
                    'code': 'password = "hardcoded"',
                    'filename': 'test.py',
                    'issue_confidence': 'MEDIUM',
                    'issue_severity': 'MEDIUM',
                    'issue_text': 'Possible hardcoded password.',
                    'line_number': 3,
                    'test_id': 'B105',
                    'test_name': 'hardcoded_password_string'
                }
            ],
            'metrics': {
                'SEVERITY.HIGH': 1,
                'SEVERITY.MEDIUM': 1,
                'SEVERITY.LOW': 0
            }
        }
        
        result = ResultParser.parse_scan_result(raw_bandit_result)
        
        # 验证基本信息
        self.assertEqual(result['scan_id'], 'test-scan-123')
        self.assertEqual(result['language'], 'python')
        self.assertEqual(result['tool'], 'bandit')
        self.assertIn('timestamp', result)
        
        # 验证 findings 转换
        self.assertEqual(len(result['findings']), 2)
        
        finding1 = result['findings'][0]
        self.assertEqual(finding1['line'], 5)
        self.assertEqual(finding1['severity'], 'HIGH')
        self.assertEqual(finding1['confidence'], 'HIGH')
        self.assertEqual(finding1['issue'], 'Use of exec detected.')
        self.assertEqual(finding1['code_snippet'], 'exec(user_input)')
        self.assertEqual(finding1['rule_id'], 'B102')
        self.assertEqual(finding1['rule_name'], 'exec_used')
        
        finding2 = result['findings'][1]
        self.assertEqual(finding2['line'], 3)
        self.assertEqual(finding2['severity'], 'MEDIUM')
        self.assertEqual(finding2['confidence'], 'MEDIUM')
        
        # 验证摘要统计
        summary = result['summary']
        self.assertEqual(summary['HIGH'], 1)
        self.assertEqual(summary['MEDIUM'], 1)
        self.assertEqual(summary['LOW'], 0)
    
    def test_parse_semgrep_result(self):
        """测试解析 Semgrep 扫描结果"""
        raw_semgrep_result = {
            'scan_id': 'test-scan-456',
            'language': 'javascript',
            'tool': 'semgrep',
            'findings': [
                {
                    'check_id': 'javascript.lang.security.audit.xss.template-string',
                    'path': 'test.js',
                    'start': {'line': 3, 'col': 12},
                    'end': {'line': 3, 'col': 25},
                    'message': 'Detected template string with user input',
                    'severity': 'WARNING',
                    'extra': {
                        'lines': 'const html = `<div>${userInput}</div>`;',
                        'metadata': {
                            'source': 'https://semgrep.dev/rule/...'
                        }
                    }
                },
                {
                    'check_id': 'javascript.lang.security.audit.eval-usage',
                    'path': 'test.js',
                    'start': {'line': 5, 'col': 0},
                    'message': 'Use of eval detected',
                    'extra': {
                        'severity': 'ERROR',
                        'lines': 'eval(userCode);'
                    }
                }
            ]
        }
        
        result = ResultParser.parse_scan_result(raw_semgrep_result)
        
        # 验证基本信息
        self.assertEqual(result['scan_id'], 'test-scan-456')
        self.assertEqual(result['language'], 'javascript')
        self.assertEqual(result['tool'], 'semgrep')
        
        # 验证 findings 转换
        self.assertEqual(len(result['findings']), 2)
        
        finding1 = result['findings'][0]
        self.assertEqual(finding1['line'], 3)
        self.assertEqual(finding1['severity'], 'MEDIUM')  # WARNING 映射到 MEDIUM
        self.assertEqual(finding1['confidence'], 'HIGH')  # Semgrep 默认高置信度
        self.assertEqual(finding1['issue'], 'Detected template string with user input')
        self.assertEqual(finding1['code_snippet'], 'const html = `<div>${userInput}</div>`;')
        self.assertEqual(finding1['rule_id'], 'javascript.lang.security.audit.xss.template-string')
        
        finding2 = result['findings'][1]
        self.assertEqual(finding2['line'], 5)
        self.assertEqual(finding2['severity'], 'HIGH')  # ERROR 映射到 HIGH
        self.assertEqual(finding2['code_snippet'], 'eval(userCode);')
        
        # 验证摘要统计
        summary = result['summary']
        self.assertEqual(summary['HIGH'], 1)
        self.assertEqual(summary['MEDIUM'], 1)
        self.assertEqual(summary['LOW'], 0)
    
    def test_parse_error_result(self):
        """测试解析错误结果"""
        error_result = {
            'scan_id': 'test-scan-error',
            'language': 'python',
            'tool': 'error',
            'error': 'Scanner execution failed',
            'findings': [],
            'summary': {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        }
        
        result = ResultParser.parse_scan_result(error_result)
        
        self.assertEqual(result['scan_id'], 'test-scan-error')
        self.assertEqual(result['language'], 'python')
        self.assertEqual(result['tool'], 'error')
        self.assertEqual(result['error'], 'Scanner execution failed')
        self.assertEqual(len(result['findings']), 0)
        self.assertEqual(result['summary']['HIGH'], 0)
    
    def test_parse_unknown_tool(self):
        """测试解析未知工具结果"""
        unknown_result = {
            'scan_id': 'test-scan-unknown',
            'language': 'python',
            'tool': 'unknown_tool',
            'findings': []
        }
        
        result = ResultParser.parse_scan_result(unknown_result)
        
        self.assertEqual(result['scan_id'], 'test-scan-unknown')
        self.assertEqual(result['language'], 'python')
        self.assertEqual(result['tool'], 'unknown_tool')
        self.assertEqual(len(result['findings']), 0)
        self.assertEqual(result['summary'], {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0})
    
    def test_calculate_vuln_count(self):
        """测试计算漏洞总数"""
        parsed_result = {
            'summary': {
                'HIGH': 2,
                'MEDIUM': 3,
                'LOW': 1
            }
        }
        
        total_count = ResultParser.calculate_vuln_count(parsed_result)
        self.assertEqual(total_count, 6)
    
    def test_calculate_vuln_count_empty(self):
        """测试空结果的漏洞计数"""
        empty_result = {'summary': {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}}
        
        total_count = ResultParser.calculate_vuln_count(empty_result)
        self.assertEqual(total_count, 0)
    
    def test_get_severity_distribution(self):
        """测试获取严重程度分布"""
        parsed_result = {
            'summary': {
                'HIGH': 5,
                'MEDIUM': 3,
                'LOW': 2
            }
        }
        
        distribution = ResultParser.get_severity_distribution(parsed_result)
        
        self.assertEqual(distribution['HIGH'], 5)
        self.assertEqual(distribution['MEDIUM'], 3)
        self.assertEqual(distribution['LOW'], 2)
    
    def test_bandit_missing_fields(self):
        """测试处理 Bandit 结果中缺失字段的情况"""
        raw_result = {
            'scan_id': 'test-incomplete',
            'language': 'python',
            'tool': 'bandit',
            'findings': [
                {
                    # 只有必需字段，其他字段缺失
                    'line_number': 10,
                    'issue_text': 'Some security issue'
                }
            ],
            'metrics': {}  # 空的 metrics
        }
        
        result = ResultParser.parse_scan_result(raw_result)
        
        self.assertEqual(len(result['findings']), 1)
        
        finding = result['findings'][0]
        self.assertEqual(finding['line'], 10)
        self.assertEqual(finding['severity'], 'UNKNOWN')
        self.assertEqual(finding['confidence'], 'UNKNOWN')
        self.assertEqual(finding['issue'], 'Some security issue')
        self.assertEqual(finding['code_snippet'], '')
        self.assertEqual(finding['rule_id'], '')
        
        # 验证空 metrics 处理
        summary = result['summary']
        self.assertEqual(summary['HIGH'], 0)
        self.assertEqual(summary['MEDIUM'], 0)
        self.assertEqual(summary['LOW'], 0)
    
    def test_semgrep_severity_mapping(self):
        """测试 Semgrep 严重程度映射"""
        test_cases = [
            ('ERROR', 'HIGH'),
            ('WARNING', 'MEDIUM'),
            ('INFO', 'LOW'),
            ('UNKNOWN_SEVERITY', 'MEDIUM')  # 未知严重程度默认为 MEDIUM
        ]
        
        for original, expected in test_cases:
            raw_result = {
                'scan_id': 'test-severity',
                'language': 'javascript',
                'tool': 'semgrep',
                'findings': [
                    {
                        'check_id': 'test.rule',
                        'start': {'line': 1},
                        'message': 'Test message',
                        'extra': {
                            'severity': original,
                            'lines': 'test code'
                        }
                    }
                ]
            }
            
            result = ResultParser.parse_scan_result(raw_result)
            self.assertEqual(result['findings'][0]['severity'], expected)


if __name__ == '__main__':
    unittest.main()
"""
扫描引擎模块
负责集成 Bandit（Python 代码扫描）和 Semgrep（Java/JS 代码扫描）
"""
import json
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, Any, List
import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


class SecurityScanner:
    """安全扫描器类，整合 Bandit 和 Semgrep"""
    
    def __init__(self):
        self.temp_dir = None
    
    def scan_code(self, code: str, language: str, scan_id: str) -> Dict[str, Any]:
        """
        根据语言类型选择合适的扫描器扫描代码
        
        Args:
            code: 要扫描的代码内容
            language: 代码语言 (python, java, javascript)
            scan_id: 扫描任务ID
            
        Returns:
            包含扫描结果的字典
        """
        try:
            # 创建临时目录
            with tempfile.TemporaryDirectory() as temp_dir:
                self.temp_dir = temp_dir
                
                # 根据语言选择扫描器
                if language.lower() == 'python':
                    return self._scan_with_bandit(code, scan_id)
                elif language.lower() in ['java', 'javascript', 'js']:
                    return self._scan_with_semgrep(code, language, scan_id)
                else:
                    raise ValueError(f"不支持的语言类型: {language}")
                    
        except Exception as e:
            logger.error(f"扫描失败 - scan_id: {scan_id}, error: {str(e)}")
            return {
                'scan_id': scan_id,
                'language': language,
                'tool': 'error',
                'error': str(e),
                'findings': [],
                'summary': {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
            }
    
    def _scan_with_bandit(self, code: str, scan_id: str) -> Dict[str, Any]:
        """
        使用 Bandit 扫描 Python 代码
        
        Args:
            code: Python 代码内容
            scan_id: 扫描任务ID
            
        Returns:
            Bandit 扫描结果
        """
        logger.info(f"开始 Bandit 扫描 - scan_id: {scan_id}")
        
        # 写入临时 Python 文件
        python_file = os.path.join(self.temp_dir, f"code_{scan_id}.py")
        with open(python_file, 'w', encoding='utf-8') as f:
            f.write(code)
        
        try:
            # 运行 Bandit 扫描
            cmd = [
                'bandit',
                '-r', python_file,
                '-f', 'json',
                '--silent'  # 减少输出噪音
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,  # 5分钟超时
                cwd=self.temp_dir
            )
            
            # Bandit 返回码: 0=无问题, 1=有问题但成功, >=2=错误
            if result.returncode >= 2:
                raise RuntimeError(f"Bandit 执行失败: {result.stderr}")
            
            # 解析 JSON 结果
            if result.stdout.strip():
                bandit_output = json.loads(result.stdout)
            else:
                # 没有发现问题
                bandit_output = {
                    "results": [],
                    "metrics": {
                        "CONFIDENCE.HIGH": 0,
                        "CONFIDENCE.MEDIUM": 0,
                        "CONFIDENCE.LOW": 0,
                        "SEVERITY.HIGH": 0,
                        "SEVERITY.MEDIUM": 0,
                        "SEVERITY.LOW": 0
                    }
                }
            
            logger.info(f"Bandit 扫描完成 - scan_id: {scan_id}, 发现问题: {len(bandit_output.get('results', []))}")
            
            return {
                'scan_id': scan_id,
                'language': 'python',
                'tool': 'bandit',
                'raw_output': bandit_output,
                'findings': bandit_output.get('results', []),
                'metrics': bandit_output.get('metrics', {})
            }
            
        except subprocess.TimeoutExpired:
            raise RuntimeError("Bandit 扫描超时")
        except json.JSONDecodeError as e:
            raise RuntimeError(f"Bandit 输出解析失败: {str(e)}")
        except Exception as e:
            raise RuntimeError(f"Bandit 扫描异常: {str(e)}")
    
    def _scan_with_semgrep(self, code: str, language: str, scan_id: str) -> Dict[str, Any]:
        """
        使用 Semgrep 扫描 Java/JavaScript 代码
        
        Args:
            code: 代码内容
            language: 语言类型
            scan_id: 扫描任务ID
            
        Returns:
            Semgrep 扫描结果
        """
        logger.info(f"开始 Semgrep 扫描 - scan_id: {scan_id}, language: {language}")
        
        # 根据语言确定文件扩展名
        ext_map = {
            'java': '.java',
            'javascript': '.js',
            'js': '.js'
        }
        
        file_ext = ext_map.get(language.lower(), '.txt')
        code_file = os.path.join(self.temp_dir, f"code_{scan_id}{file_ext}")
        
        # 写入临时代码文件
        with open(code_file, 'w', encoding='utf-8') as f:
            f.write(code)
        
        try:
            # 运行 Semgrep 扫描
            cmd = [
                'semgrep',
                '--config=auto',  # 使用自动规则集
                '--json',         # JSON 输出
                '--quiet',        # 减少输出
                '--no-git-ignore', # 忽略 .gitignore
                code_file
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,  # 5分钟超时
                cwd=self.temp_dir
            )
            
            # Semgrep 返回码: 0=无问题, 1=有问题, >=2=错误
            if result.returncode >= 2:
                raise RuntimeError(f"Semgrep 执行失败: {result.stderr}")
            
            # 解析 JSON 结果
            if result.stdout.strip():
                semgrep_output = json.loads(result.stdout)
            else:
                semgrep_output = {"results": []}
            
            results = semgrep_output.get('results', [])
            logger.info(f"Semgrep 扫描完成 - scan_id: {scan_id}, 发现问题: {len(results)}")
            
            return {
                'scan_id': scan_id,
                'language': language,
                'tool': 'semgrep',
                'raw_output': semgrep_output,
                'findings': results
            }
            
        except subprocess.TimeoutExpired:
            raise RuntimeError("Semgrep 扫描超时")
        except json.JSONDecodeError as e:
            raise RuntimeError(f"Semgrep 输出解析失败: {str(e)}")
        except Exception as e:
            raise RuntimeError(f"Semgrep 扫描异常: {str(e)}")


def scan_code_with_timeout(code: str, language: str, scan_id: str, timeout: int = 300) -> Dict[str, Any]:
    """
    带超时的代码扫描函数
    
    Args:
        code: 要扫描的代码
        language: 代码语言
        scan_id: 扫描ID
        timeout: 超时时间（秒）
        
    Returns:
        扫描结果
    """
    scanner = SecurityScanner()
    return scanner.scan_code(code, language, scan_id)
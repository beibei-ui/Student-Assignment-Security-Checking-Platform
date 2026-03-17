"""
S3 写入器模块
负责将扫描结果 JSON 报告写入到 S3 存储桶
"""
import json
import boto3
import logging
from typing import Dict, Any, Optional
from botocore.exceptions import ClientError, NoCredentialsError

logger = logging.getLogger(__name__)


class S3Writer:
    """S3 写入器类"""
    
    def __init__(self, bucket_name: str, region: str = 'us-east-1'):
        """
        初始化 S3 写入器
        
        Args:
            bucket_name: S3 存储桶名称
            region: AWS 区域
        """
        self.bucket_name = bucket_name
        self.region = region
        self.s3_client = boto3.client('s3', region_name=region)
    
    def write_scan_report(self, scan_id: str, report_data: Dict[str, Any]) -> str:
        """
        将扫描报告写入 S3
        
        Args:
            scan_id: 扫描任务ID
            report_data: 标准化的扫描报告数据
            
        Returns:
            S3 对象键名
            
        Raises:
            S3WriteError: S3 写入失败时抛出
        """
        try:
            # 构造 S3 对象键名：reports/scan-{scan_id}.json
            s3_key = f"reports/{scan_id}.json"
            
            # 将报告数据转换为 JSON 字符串
            json_content = json.dumps(report_data, indent=2, ensure_ascii=False)
            
            # 上传到 S3
            self.s3_client.put_object(
                Bucket=self.bucket_name,
                Key=s3_key,
                Body=json_content.encode('utf-8'),
                ContentType='application/json',
                Metadata={
                    'scan_id': scan_id,
                    'language': report_data.get('language', 'unknown'),
                    'tool': report_data.get('tool', 'unknown'),
                    'vuln_count': str(self._calculate_total_vulns(report_data))
                }
            )
            
            logger.info(f"扫描报告已写入 S3 - bucket: {self.bucket_name}, key: {s3_key}")
            return s3_key
            
        except NoCredentialsError:
            error_msg = "AWS 凭证未找到或无效"
            logger.error(error_msg)
            raise S3WriteError(error_msg)
        except ClientError as e:
            error_code = e.response['Error']['Code']
            error_msg = f"S3 操作失败 - {error_code}: {e.response['Error']['Message']}"
            logger.error(error_msg)
            raise S3WriteError(error_msg)
        except Exception as e:
            error_msg = f"写入 S3 时发生未知错误: {str(e)}"
            logger.error(error_msg)
            raise S3WriteError(error_msg)
    
    def generate_presigned_url(self, s3_key: str, expiration: int = 3600) -> str:
        """
        生成预签名 URL 供前端下载报告
        
        Args:
            s3_key: S3 对象键名
            expiration: URL 过期时间（秒），默认1小时
            
        Returns:
            预签名 URL
            
        Raises:
            S3WriteError: 生成 URL 失败时抛出
        """
        try:
            presigned_url = self.s3_client.generate_presigned_url(
                'get_object',
                Params={'Bucket': self.bucket_name, 'Key': s3_key},
                ExpiresIn=expiration
            )
            
            logger.info(f"已生成预签名 URL - key: {s3_key}, expires_in: {expiration}s")
            return presigned_url
            
        except ClientError as e:
            error_msg = f"生成预签名 URL 失败: {e.response['Error']['Message']}"
            logger.error(error_msg)
            raise S3WriteError(error_msg)
        except Exception as e:
            error_msg = f"生成预签名 URL 时发生未知错误: {str(e)}"
            logger.error(error_msg)
            raise S3WriteError(error_msg)
    
    def check_object_exists(self, s3_key: str) -> bool:
        """
        检查 S3 对象是否存在
        
        Args:
            s3_key: S3 对象键名
            
        Returns:
            对象是否存在
        """
        try:
            self.s3_client.head_object(Bucket=self.bucket_name, Key=s3_key)
            return True
        except ClientError as e:
            if e.response['Error']['Code'] == '404':
                return False
            else:
                # 其他错误，重新抛出
                raise S3WriteError(f"检查对象存在性失败: {e.response['Error']['Message']}")
    
    def delete_report(self, s3_key: str) -> bool:
        """
        删除 S3 中的扫描报告（用于清理或重新扫描）
        
        Args:
            s3_key: S3 对象键名
            
        Returns:
            删除是否成功
        """
        try:
            self.s3_client.delete_object(Bucket=self.bucket_name, Key=s3_key)
            logger.info(f"已删除 S3 对象 - key: {s3_key}")
            return True
        except ClientError as e:
            logger.error(f"删除 S3 对象失败 - key: {s3_key}, error: {e.response['Error']['Message']}")
            return False
    
    @staticmethod
    def _calculate_total_vulns(report_data: Dict[str, Any]) -> int:
        """
        计算报告中的漏洞总数
        
        Args:
            report_data: 扫描报告数据
            
        Returns:
            漏洞总数
        """
        summary = report_data.get('summary', {})
        return summary.get('HIGH', 0) + summary.get('MEDIUM', 0) + summary.get('LOW', 0)


class S3WriteError(Exception):
    """S3 写入错误异常类"""
    pass


# 便利函数
def write_scan_result_to_s3(bucket_name: str, scan_id: str, report_data: Dict[str, Any], 
                           region: str = 'us-east-1') -> tuple[str, str]:
    """
    将扫描结果写入 S3 并生成预签名 URL
    
    Args:
        bucket_name: S3 存储桶名称
        scan_id: 扫描ID
        report_data: 扫描报告数据
        region: AWS 区域
        
    Returns:
        (s3_key, presigned_url) 元组
        
    Raises:
        S3WriteError: 写入或 URL 生成失败时抛出
    """
    writer = S3Writer(bucket_name, region)
    
    # 写入报告
    s3_key = writer.write_scan_report(scan_id, report_data)
    
    # 生成预签名 URL
    presigned_url = writer.generate_presigned_url(s3_key)
    
    return s3_key, presigned_url


def get_s3_bucket_from_env() -> str:
    """
    从环境变量获取 S3 存储桶名称
    
    Returns:
        S3 存储桶名称
        
    Raises:
        ValueError: 环境变量未设置时抛出
    """
    import os
    bucket_name = os.environ.get('S3_BUCKET_NAME')
    if not bucket_name:
        raise ValueError("环境变量 S3_BUCKET_NAME 未设置")
    return bucket_name
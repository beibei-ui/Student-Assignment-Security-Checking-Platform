"""
ECS Fargate 任务处理器
用于处理大文件或复杂扫描任务，当 Lambda 资源不足时使用
从环境变量获取扫描参数，执行扫描后写入 S3 和更新 DynamoDB
"""
import os
import json
import logging
import boto3
import sys
from typing import Dict, Any

from scanner import scan_code_with_timeout
from result_parser import ResultParser
from s3_writer import write_scan_result_to_s3, S3WriteError
from botocore.exceptions import ClientError

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# 初始化 AWS 客户端
dynamodb = boto3.resource('dynamodb')


def main():
    """ECS 任务主入口"""
    try:
        # 从环境变量获取任务参数
        scan_id = os.environ.get('SCAN_ID')
        student_id = os.environ.get('STUDENT_ID') 
        language = os.environ.get('LANGUAGE')
        code_content = os.environ.get('CODE_CONTENT')
        
        # 验证必需参数
        if not all([scan_id, student_id, language, code_content]):
            missing = [name for name, value in [
                ('SCAN_ID', scan_id),
                ('STUDENT_ID', student_id), 
                ('LANGUAGE', language),
                ('CODE_CONTENT', code_content)
            ] if not value]
            raise ValueError(f"缺少必需的环境变量: {', '.join(missing)}")
        
        # 获取其他配置
        table_name = os.environ.get('DYNAMODB_TABLE_NAME')
        s3_bucket_name = os.environ.get('S3_BUCKET_NAME')
        
        if not table_name:
            raise ValueError("环境变量 DYNAMODB_TABLE_NAME 未设置")
        if not s3_bucket_name:
            raise ValueError("环境变量 S3_BUCKET_NAME 未设置")
        
        logger.info(f"开始 ECS 扫描任务 - scan_id: {scan_id}, language: {language}")
        
        # 执行扫描处理
        table = dynamodb.Table(table_name)
        result = process_ecs_scan(
            scan_id=scan_id,
            code=code_content,
            language=language,
            student_id=student_id,
            table=table,
            s3_bucket_name=s3_bucket_name
        )
        
        if result['success']:
            logger.info(f"ECS 扫描任务完成 - scan_id: {scan_id}")
            sys.exit(0)
        else:
            logger.error(f"ECS 扫描任务失败 - scan_id: {scan_id}, error: {result['error']}")
            sys.exit(1)
            
    except Exception as e:
        logger.error(f"ECS 任务异常退出: {str(e)}")
        sys.exit(1)


def process_ecs_scan(scan_id: str, code: str, language: str, student_id: str,
                     table: Any, s3_bucket_name: str) -> Dict[str, Any]:
    """
    处理 ECS 扫描任务
    
    Args:
        scan_id: 扫描任务ID
        code: 要扫描的代码
        language: 代码语言
        student_id: 学生ID
        table: DynamoDB 表对象
        s3_bucket_name: S3 存储桶名称
        
    Returns:
        处理结果
    """
    try:
        # 步骤1: 执行安全扫描（ECS 有更多资源，可以设置更长超时）
        logger.info(f"开始扫描 - scan_id: {scan_id}")
        raw_scan_result = scan_code_with_timeout(code, language, scan_id, timeout=1800)  # 30分钟超时
        
        # 步骤2: 解析扫描结果
        logger.info(f"解析扫描结果 - scan_id: {scan_id}")
        parsed_result = ResultParser.parse_scan_result(raw_scan_result)
        vuln_count = ResultParser.calculate_vuln_count(parsed_result)
        
        # 步骤3: 写入 S3
        logger.info(f"写入扫描报告到 S3 - scan_id: {scan_id}")
        s3_key, presigned_url = write_scan_result_to_s3(
            bucket_name=s3_bucket_name,
            scan_id=scan_id,
            report_data=parsed_result
        )
        
        # 步骤4: 更新 DynamoDB 状态
        logger.info(f"更新 DynamoDB 状态 - scan_id: {scan_id}")
        update_scan_status_ecs(
            table=table,
            student_id=student_id,
            scan_id=scan_id,
            status='DONE',
            vuln_count=vuln_count,
            s3_report_key=s3_key
        )
        
        logger.info(f"ECS 扫描任务完成 - scan_id: {scan_id}, 发现 {vuln_count} 个漏洞")
        
        return {
            'success': True,
            'scan_id': scan_id,
            'vuln_count': vuln_count,
            's3_key': s3_key
        }
        
    except S3WriteError as e:
        # S3 写入失败，更新 DynamoDB 为 FAILED 状态
        logger.error(f"S3 写入失败 - scan_id: {scan_id}, error: {str(e)}")
        try:
            update_scan_status_ecs(table, student_id, scan_id, 'FAILED', error_message=str(e))
        except Exception as db_error:
            logger.error(f"更新失败状态到 DynamoDB 也失败 - scan_id: {scan_id}, error: {str(db_error)}")
        
        return {'success': False, 'error': f"S3 写入失败: {str(e)}"}
        
    except Exception as e:
        # 其他错误，也更新 DynamoDB 为 FAILED 状态
        logger.error(f"ECS 扫描处理失败 - scan_id: {scan_id}, error: {str(e)}")
        try:
            update_scan_status_ecs(table, student_id, scan_id, 'FAILED', error_message=str(e))
        except Exception as db_error:
            logger.error(f"更新失败状态到 DynamoDB 也失败 - scan_id: {scan_id}, error: {str(db_error)}")
        
        return {'success': False, 'error': str(e)}


def update_scan_status_ecs(table: Any, student_id: str, scan_id: str, status: str,
                          vuln_count: int = 0, s3_report_key: str = None,
                          error_message: str = None) -> None:
    """
    更新 DynamoDB 中的扫描状态（ECS 版本）
    
    Args:
        table: DynamoDB 表对象
        student_id: 学生ID
        scan_id: 扫描ID
        status: 新状态 (DONE, FAILED)
        vuln_count: 漏洞数量
        s3_report_key: S3 报告键名
        error_message: 错误消息（仅在 FAILED 状态时使用）
    """
    try:
        from datetime import datetime
        
        # 构造更新表达式
        update_expression = "SET #status = :status, completed_at = :completed_at, processing_method = :method"
        expression_attribute_names = {"#status": "status"}
        expression_attribute_values = {
            ":status": status,
            ":completed_at": datetime.utcnow().isoformat() + 'Z',
            ":method": "ECS_FARGATE"  # 标记为 ECS 处理
        }
        
        if status == 'DONE':
            update_expression += ", vuln_count = :vuln_count"
            expression_attribute_values[":vuln_count"] = vuln_count
            
            if s3_report_key:
                update_expression += ", s3_report_key = :s3_key"
                expression_attribute_values[":s3_key"] = s3_report_key
                
        elif status == 'FAILED' and error_message:
            update_expression += ", error_message = :error_msg"
            expression_attribute_values[":error_msg"] = error_message
        
        # 执行更新
        table.update_item(
            Key={
                'student_id': student_id,
                'scan_id': scan_id
            },
            UpdateExpression=update_expression,
            ExpressionAttributeNames=expression_attribute_names,
            ExpressionAttributeValues=expression_attribute_values
        )
        
        logger.info(f"DynamoDB 状态已更新 (ECS) - scan_id: {scan_id}, status: {status}")
        
    except ClientError as e:
        logger.error(f"DynamoDB 更新失败 - scan_id: {scan_id}, error: {e.response['Error']['Message']}")
        raise
    except Exception as e:
        logger.error(f"DynamoDB 更新异常 - scan_id: {scan_id}, error: {str(e)}")
        raise


if __name__ == "__main__":
    main()

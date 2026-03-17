"""
Lambda B 主处理器
负责：
1. 从 SQS 消息中提取扫描任务信息
2. 调用扫描引擎进行代码安全分析
3. 解析并标准化扫描结果
4. 将结果写入 S3 和更新 DynamoDB 状态
"""
import json
import os
import logging
import boto3
from typing import Dict, Any, List
from botocore.exceptions import ClientError

from scanner import scan_code_with_timeout
from result_parser import ResultParser
from s3_writer import write_scan_result_to_s3, get_s3_bucket_from_env, S3WriteError

# 配置日志
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# 初始化 AWS 客户端
dynamodb = boto3.resource('dynamodb')
sqs = boto3.client('sqs')


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Lambda B 主入口点
    
    Args:
        event: SQS 事件数据
        context: Lambda 运行时上下文
        
    Returns:
        处理结果
    """
    logger.info(f"Lambda B 开始处理 SQS 事件: {json.dumps(event)}")
    
    # 处理结果统计
    successful_count = 0
    failed_count = 0
    failed_messages = []
    
    try:
        # 获取环境变量
        table_name = os.environ.get('DYNAMODB_TABLE_NAME')
        if not table_name:
            raise ValueError("环境变量 DYNAMODB_TABLE_NAME 未设置")
        
        s3_bucket_name = get_s3_bucket_from_env()
        table = dynamodb.Table(table_name)
        
        # 处理 SQS 消息
        records = event.get('Records', [])
        logger.info(f"收到 {len(records)} 条 SQS 消息")
        
        for record in records:
            try:
                # 解析消息
                message_body = json.loads(record['body'])
                scan_id = message_body['scan_id']
                code = message_body['code']
                language = message_body['language']
                student_id = message_body['student_id']
                
                logger.info(f"开始处理扫描任务 - scan_id: {scan_id}, language: {language}")
                
                # 执行扫描
                result = process_scan_request(
                    scan_id=scan_id,
                    code=code,
                    language=language,
                    student_id=student_id,
                    table=table,
                    s3_bucket_name=s3_bucket_name
                )
                
                if result['success']:
                    successful_count += 1
                    logger.info(f"扫描任务完成 - scan_id: {scan_id}")
                else:
                    failed_count += 1
                    failed_messages.append({
                        'scan_id': scan_id,
                        'error': result['error']
                    })
                    logger.error(f"扫描任务失败 - scan_id: {scan_id}, error: {result['error']}")
                    
            except Exception as e:
                failed_count += 1
                error_msg = f"处理 SQS 消息失败: {str(e)}"
                logger.error(error_msg)
                failed_messages.append({
                    'record_id': record.get('messageId', 'unknown'),
                    'error': error_msg
                })
        
        # 返回处理结果
        result = {
            'statusCode': 200,
            'body': {
                'total_messages': len(records),
                'successful': successful_count,
                'failed': failed_count,
                'failed_messages': failed_messages
            }
        }
        
        logger.info(f"Lambda B 处理完成 - 成功: {successful_count}, 失败: {failed_count}")
        return result
        
    except Exception as e:
        logger.error(f"Lambda B 处理异常: {str(e)}")
        return {
            'statusCode': 500,
            'body': {
                'error': str(e),
                'successful': successful_count,
                'failed': failed_count + 1
            }
        }


def process_scan_request(scan_id: str, code: str, language: str, student_id: str,
                        table: Any, s3_bucket_name: str) -> Dict[str, Any]:
    """
    处理单个扫描请求
    
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
        # 步骤1: 执行安全扫描
        logger.info(f"开始扫描 - scan_id: {scan_id}")
        raw_scan_result = scan_code_with_timeout(code, language, scan_id, timeout=300)
        
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
        update_scan_status(
            table=table,
            student_id=student_id,
            scan_id=scan_id,
            status='DONE',
            vuln_count=vuln_count,
            s3_report_key=s3_key
        )
        
        logger.info(f"扫描任务完成 - scan_id: {scan_id}, 发现 {vuln_count} 个漏洞")
        
        return {
            'success': True,
            'scan_id': scan_id,
            'vuln_count': vuln_count,
            's3_key': s3_key,
            'presigned_url': presigned_url
        }
        
    except S3WriteError as e:
        # S3 写入失败，更新 DynamoDB 为 FAILED 状态
        logger.error(f"S3 写入失败 - scan_id: {scan_id}, error: {str(e)}")
        try:
            update_scan_status(table, student_id, scan_id, 'FAILED', error_message=str(e))
        except Exception as db_error:
            logger.error(f"更新失败状态到 DynamoDB 也失败 - scan_id: {scan_id}, error: {str(db_error)}")
        
        return {'success': False, 'error': f"S3 写入失败: {str(e)}"}
        
    except Exception as e:
        # 其他错误，也更新 DynamoDB 为 FAILED 状态
        logger.error(f"扫描处理失败 - scan_id: {scan_id}, error: {str(e)}")
        try:
            update_scan_status(table, student_id, scan_id, 'FAILED', error_message=str(e))
        except Exception as db_error:
            logger.error(f"更新失败状态到 DynamoDB 也失败 - scan_id: {scan_id}, error: {str(db_error)}")
        
        return {'success': False, 'error': str(e)}


def update_scan_status(table: Any, student_id: str, scan_id: str, status: str,
                      vuln_count: int = 0, s3_report_key: str = None,
                      error_message: str = None) -> None:
    """
    更新 DynamoDB 中的扫描状态
    
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
        update_expression = "SET #status = :status, completed_at = :completed_at"
        expression_attribute_names = {"#status": "status"}
        expression_attribute_values = {
            ":status": status,
            ":completed_at": datetime.utcnow().isoformat() + 'Z'
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
        
        logger.info(f"DynamoDB 状态已更新 - scan_id: {scan_id}, status: {status}")
        
    except ClientError as e:
        logger.error(f"DynamoDB 更新失败 - scan_id: {scan_id}, error: {e.response['Error']['Message']}")
        raise
    except Exception as e:
        logger.error(f"DynamoDB 更新异常 - scan_id: {scan_id}, error: {str(e)}")
        raise


def handle_ecs_fallback(scan_id: str, code: str, language: str, student_id: str) -> Dict[str, Any]:
    """
    处理大文件或复杂扫描的 ECS Fargate 回退逻辑
    当 Lambda 内存不足或执行时间超时时使用
    
    Args:
        scan_id: 扫描ID
        code: 代码内容
        language: 代码语言
        student_id: 学生ID
        
    Returns:
        ECS 任务启动结果
    """
    try:
        ecs_client = boto3.client('ecs')
        cluster_name = os.environ.get('ECS_CLUSTER_NAME', 'sast-platform-cluster')
        task_definition = os.environ.get('ECS_TASK_DEFINITION', 'sast-scanner-task')
        
        # 启动 ECS 任务
        response = ecs_client.run_task(
            cluster=cluster_name,
            taskDefinition=task_definition,
            launchType='FARGATE',
            networkConfiguration={
                'awsvpcConfiguration': {
                    'subnets': os.environ.get('ECS_SUBNETS', '').split(','),
                    'securityGroups': os.environ.get('ECS_SECURITY_GROUPS', '').split(','),
                    'assignPublicIp': 'ENABLED'
                }
            },
            overrides={
                'containerOverrides': [
                    {
                        'name': 'scanner-container',
                        'environment': [
                            {'name': 'SCAN_ID', 'value': scan_id},
                            {'name': 'STUDENT_ID', 'value': student_id},
                            {'name': 'LANGUAGE', 'value': language},
                            {'name': 'CODE_CONTENT', 'value': code}
                        ]
                    }
                ]
            }
        )
        
        task_arn = response['tasks'][0]['taskArn']
        logger.info(f"ECS 任务已启动 - scan_id: {scan_id}, task_arn: {task_arn}")
        
        return {
            'success': True,
            'task_arn': task_arn,
            'message': 'ECS 任务已启动，将异步完成扫描'
        }
        
    except Exception as e:
        logger.error(f"ECS 任务启动失败 - scan_id: {scan_id}, error: {str(e)}")
        return {
            'success': False,
            'error': f"ECS 任务启动失败: {str(e)}"
        }
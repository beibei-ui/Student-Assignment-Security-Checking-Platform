#!/bin/bash

# Lambda B 部署脚本
# 负责打包和部署 Lambda B 扫描引擎

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 配置参数
PROJECT_NAME="${PROJECT_NAME:-sast-platform}"
ENVIRONMENT="${ENVIRONMENT:-dev}"
AWS_REGION="${AWS_REGION:-us-east-1}"
LAMBDA_FUNCTION_NAME="${PROJECT_NAME}-${ENVIRONMENT}-scanner"
CODE_BUCKET="${CODE_BUCKET:-}"

# 目录设置
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
LAMBDA_B_DIR="$PROJECT_ROOT/lambda_b"
BUILD_DIR="/tmp/lambda_b_build"

echo -e "${GREEN}🚀 开始部署 Lambda B (扫描引擎)${NC}"
echo "Project: $PROJECT_NAME"
echo "Environment: $ENVIRONMENT"
echo "Region: $AWS_REGION"
echo "Function: $LAMBDA_FUNCTION_NAME"
echo

# 检查必需工具
check_dependencies() {
    echo -e "${YELLOW}📋 检查依赖工具...${NC}"
    
    local missing_tools=()
    
    if ! command -v aws &> /dev/null; then
        missing_tools+=("aws-cli")
    fi
    
    if ! command -v zip &> /dev/null; then
        missing_tools+=("zip")
    fi
    
    if ! command -v python3 &> /dev/null; then
        missing_tools+=("python3")
    fi
    
    if [ ${#missing_tools[@]} -ne 0 ]; then
        echo -e "${RED}❌ 缺少必需工具: ${missing_tools[*]}${NC}"
        exit 1
    fi
    
    # 检查 AWS 凭证
    if ! aws sts get-caller-identity &> /dev/null; then
        echo -e "${RED}❌ AWS 凭证未配置或无效${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}✅ 依赖检查通过${NC}"
}

# 创建构建目录
prepare_build_dir() {
    echo -e "${YELLOW}📁 准备构建目录...${NC}"
    
    # 清理并创建构建目录
    rm -rf "$BUILD_DIR"
    mkdir -p "$BUILD_DIR"
    
    # 复制 Lambda B 源代码
    cp -r "$LAMBDA_B_DIR"/* "$BUILD_DIR/"
    
    # 删除不需要的文件
    rm -f "$BUILD_DIR/Dockerfile"
    rm -f "$BUILD_DIR/ecs_handler.py"  # ECS 专用，不需要在 Lambda 中
    
    echo -e "${GREEN}✅ 构建目录准备完成${NC}"
}

# 安装 Python 依赖
install_dependencies() {
    echo -e "${YELLOW}📦 安装 Python 依赖...${NC}"
    
    cd "$BUILD_DIR"
    
    # 检查 requirements.txt 是否存在
    if [ ! -f "requirements.txt" ]; then
        echo -e "${RED}❌ 未找到 requirements.txt${NC}"
        exit 1
    fi
    
    # 使用 pip 安装依赖到当前目录
    # 注意：Lambda 运行时已包含 boto3 和 botocore，但为了版本一致性还是安装
    python3 -m pip install --target . -r requirements.txt --upgrade
    
    # 清理不需要的文件以减少包大小
    find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
    find . -type f -name "*.pyc" -delete 2>/dev/null || true
    find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
    find . -type d -name "tests" -exec rm -rf {} + 2>/dev/null || true
    find . -type d -name "test" -exec rm -rf {} + 2>/dev/null || true
    
    # 删除大的不必要文件
    rm -rf ./semgrep/semgrep-core* 2>/dev/null || true
    rm -rf ./bandit/formatters/html* 2>/dev/null || true
    
    echo -e "${GREEN}✅ 依赖安装完成${NC}"
}

# 创建部署包
create_deployment_package() {
    echo -e "${YELLOW}📦 创建部署包...${NC}"
    
    cd "$BUILD_DIR"
    
    # 创建 ZIP 文件
    local zip_file="/tmp/lambda_b_deployment.zip"
    rm -f "$zip_file"
    
    # 打包所有文件
    zip -r "$zip_file" . -x "*.git*" "*.DS_Store*" "*.pyc" "__pycache__/*"
    
    # 检查包大小
    local file_size=$(du -h "$zip_file" | cut -f1)
    echo "部署包大小: $file_size"
    
    # Lambda 限制检查
    local size_bytes=$(stat -c%s "$zip_file" 2>/dev/null || stat -f%z "$zip_file")
    local max_size=$((250 * 1024 * 1024))  # 250MB
    
    if [ "$size_bytes" -gt "$max_size" ]; then
        echo -e "${YELLOW}⚠️  警告: 部署包较大 ($file_size), 可能需要使用 S3 部署${NC}"
    fi
    
    echo "部署包路径: $zip_file"
    echo -e "${GREEN}✅ 部署包创建完成${NC}"
}

# 检查 Lambda 函数是否存在
check_lambda_function() {
    echo -e "${YELLOW}🔍 检查 Lambda 函数...${NC}"
    
    if aws lambda get-function --function-name "$LAMBDA_FUNCTION_NAME" --region "$AWS_REGION" &>/dev/null; then
        echo "Lambda 函数 $LAMBDA_FUNCTION_NAME 已存在"
        return 0
    else
        echo "Lambda 函数 $LAMBDA_FUNCTION_NAME 不存在，需要先部署基础设施"
        return 1
    fi
}

# 更新 Lambda 函数代码
update_lambda_function() {
    echo -e "${YELLOW}🔄 更新 Lambda 函数代码...${NC}"
    
    local zip_file="/tmp/lambda_b_deployment.zip"
    
    # 检查包大小决定部署方式
    local size_bytes=$(stat -c%s "$zip_file" 2>/dev/null || stat -f%z "$zip_file")
    local direct_limit=$((50 * 1024 * 1024))  # 50MB
    
    if [ "$size_bytes" -gt "$direct_limit" ]; then
        echo "部署包大于 50MB，使用 S3 方式部署..."
        update_lambda_via_s3 "$zip_file"
    else
        echo "部署包小于 50MB，直接上传..."
        aws lambda update-function-code \
            --function-name "$LAMBDA_FUNCTION_NAME" \
            --zip-file "fileb://$zip_file" \
            --region "$AWS_REGION" > /dev/null

        # Sync to CODE_BUCKET so CloudFormation re-deployments stay in sync.
        if [[ -n "$CODE_BUCKET" ]]; then
            echo "同步部署包到 CODE_BUCKET: s3://$CODE_BUCKET/lambda_b.zip"
            aws s3 cp "$zip_file" "s3://$CODE_BUCKET/lambda_b.zip" --region "$AWS_REGION"
        fi
    fi
    
    echo -e "${GREEN}✅ Lambda 函数代码更新完成${NC}"
}

# 通过 S3 更新 Lambda 函数
update_lambda_via_s3() {
    local zip_file="$1"
    local s3_bucket="${PROJECT_NAME}-${ENVIRONMENT}-deployments"
    local s3_key="lambda_b/$(date +%Y%m%d-%H%M%S)/lambda_b.zip"
    
    echo "上传部署包到 S3..."
    
    # 创建 S3 存储桶（如果不存在）
    if ! aws s3api head-bucket --bucket "$s3_bucket" --region "$AWS_REGION" 2>/dev/null; then
        echo "创建部署存储桶: $s3_bucket"
        aws s3api create-bucket --bucket "$s3_bucket" --region "$AWS_REGION"
    fi
    
    # 上传到 S3
    aws s3 cp "$zip_file" "s3://$s3_bucket/$s3_key" --region "$AWS_REGION"
    
    # 使用 S3 位置更新 Lambda
    aws lambda update-function-code \
        --function-name "$LAMBDA_FUNCTION_NAME" \
        --s3-bucket "$s3_bucket" \
        --s3-key "$s3_key" \
        --region "$AWS_REGION" > /dev/null
    
    echo "通过 S3 更新完成"

    # Sync to CODE_BUCKET/lambda_b.zip so CloudFormation re-deployments
    # pick up the latest code (must match CodeBucket param in lambda_b.yaml).
    if [[ -n "$CODE_BUCKET" ]]; then
        echo "同步部署包到 CODE_BUCKET: s3://$CODE_BUCKET/lambda_b.zip"
        aws s3 cp "$zip_file" "s3://$CODE_BUCKET/lambda_b.zip" --region "$AWS_REGION"
    fi
}

# 更新函数配置（如果需要）
update_lambda_configuration() {
    echo -e "${YELLOW}⚙️  更新 Lambda 配置...${NC}"
    
    # 获取当前配置
    local current_timeout=$(aws lambda get-function-configuration \
        --function-name "$LAMBDA_FUNCTION_NAME" \
        --region "$AWS_REGION" \
        --query 'Timeout' --output text)
    
    local current_memory=$(aws lambda get-function-configuration \
        --function-name "$LAMBDA_FUNCTION_NAME" \
        --region "$AWS_REGION" \
        --query 'MemorySize' --output text)
    
    echo "当前配置 - 超时: ${current_timeout}s, 内存: ${current_memory}MB"
    
    # 推荐配置
    local recommended_timeout=900  # 15分钟
    local recommended_memory=3008  # 3GB
    
    if [ "$current_timeout" -lt "$recommended_timeout" ] || [ "$current_memory" -lt "$recommended_memory" ]; then
        echo "更新配置以优化扫描性能..."
        aws lambda update-function-configuration \
            --function-name "$LAMBDA_FUNCTION_NAME" \
            --timeout "$recommended_timeout" \
            --memory-size "$recommended_memory" \
            --region "$AWS_REGION" > /dev/null
        echo "配置已更新 - 超时: ${recommended_timeout}s, 内存: ${recommended_memory}MB"
    else
        echo "配置已是最优"
    fi
    
    echo -e "${GREEN}✅ Lambda 配置更新完成${NC}"
}

# 测试 Lambda 函数
test_lambda_function() {
    echo -e "${YELLOW}🧪 测试 Lambda 函数...${NC}"
    
    # 创建测试事件（模拟 SQS 消息）
    local test_event='{
        "Records": [
            {
                "messageId": "test-message-id",
                "body": "{\"scan_id\": \"test-scan-123\", \"code\": \"print(\\\"hello world\\\")\", \"language\": \"python\", \"student_id\": \"test-student\"}"
            }
        ]
    }'
    
    echo "发送测试事件..."
    local response=$(aws lambda invoke \
        --function-name "$LAMBDA_FUNCTION_NAME" \
        --payload "$test_event" \
        --region "$AWS_REGION" \
        /tmp/lambda_b_test_response.json 2>&1)
    
    # 检查调用是否成功
    if echo "$response" | grep -q "StatusCode.*200"; then
        echo -e "${GREEN}✅ Lambda 函数测试通过${NC}"
        
        # 显示响应（如果有的话）
        if [ -f "/tmp/lambda_b_test_response.json" ]; then
            echo "响应内容:"
            cat /tmp/lambda_b_test_response.json | jq . 2>/dev/null || cat /tmp/lambda_b_test_response.json
        fi
    else
        echo -e "${RED}❌ Lambda 函数测试失败${NC}"
        echo "$response"
        return 1
    fi
}

# 清理临时文件
cleanup() {
    echo -e "${YELLOW}🧹 清理临时文件...${NC}"
    
    rm -rf "$BUILD_DIR"
    rm -f "/tmp/lambda_b_deployment.zip"
    rm -f "/tmp/lambda_b_test_response.json"
    
    echo -e "${GREEN}✅ 清理完成${NC}"
}

# 主执行流程
main() {
    echo -e "${GREEN}=== Lambda B 部署开始 ===${NC}"
    
    check_dependencies
    
    if ! check_lambda_function; then
        echo -e "${RED}❌ 请先运行基础设施部署脚本创建 Lambda 函数${NC}"
        exit 1
    fi
    
    prepare_build_dir
    install_dependencies
    create_deployment_package
    update_lambda_function
    update_lambda_configuration
    
    # 测试（可选，通过环境变量控制）
    if [ "${SKIP_TEST}" != "true" ]; then
        test_lambda_function
    fi
    
    cleanup
    
    echo
    echo -e "${GREEN}🎉 Lambda B 部署成功完成！${NC}"
    echo -e "函数名称: ${GREEN}$LAMBDA_FUNCTION_NAME${NC}"
    echo -e "AWS 区域: ${GREEN}$AWS_REGION${NC}"
    echo
    echo -e "${YELLOW}💡 提示:${NC}"
    echo "- 使用 'aws logs tail /aws/lambda/$LAMBDA_FUNCTION_NAME --follow' 查看实时日志"
    echo "- 在 AWS 控制台中监控函数指标和错误"
    echo "- 确保 SQS 触发器已正确配置"
}

# 错误处理
trap cleanup ERR

# 执行主程序
main "$@"
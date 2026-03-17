#!/bin/bash

# Docker 镜像构建和推送脚本
# 用于构建包含 Bandit + Semgrep 的 ECS Fargate 扫描器镜像

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
IMAGE_TAG="${IMAGE_TAG:-latest}"

# 获取 AWS 账号 ID
AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
ECR_REPOSITORY_NAME="${PROJECT_NAME}-${ENVIRONMENT}-scanner"
ECR_URI="${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/${ECR_REPOSITORY_NAME}"

# 目录设置
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
LAMBDA_B_DIR="$PROJECT_ROOT/lambda_b"

echo -e "${GREEN}🐳 开始构建和推送 ECS 扫描器镜像${NC}"
echo "Project: $PROJECT_NAME"
echo "Environment: $ENVIRONMENT"
echo "AWS Account: $AWS_ACCOUNT_ID"
echo "ECR Repository: $ECR_URI"
echo "Image Tag: $IMAGE_TAG"
echo

# 检查必需工具
check_dependencies() {
    echo -e "${YELLOW}📋 检查依赖工具...${NC}"
    
    local missing_tools=()
    
    if ! command -v docker &> /dev/null; then
        missing_tools+=("docker")
    fi
    
    if ! command -v aws &> /dev/null; then
        missing_tools+=("aws-cli")
    fi
    
    if [ ${#missing_tools[@]} -ne 0 ]; then
        echo -e "${RED}❌ 缺少必需工具: ${missing_tools[*]}${NC}"
        echo "请安装 Docker 和 AWS CLI"
        exit 1
    fi
    
    # 检查 Docker 守护进程
    if ! docker info &> /dev/null; then
        echo -e "${RED}❌ Docker 守护进程未运行${NC}"
        exit 1
    fi
    
    # 检查 AWS 凭证
    if ! aws sts get-caller-identity &> /dev/null; then
        echo -e "${RED}❌ AWS 凭证未配置或无效${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}✅ 依赖检查通过${NC}"
}

# 登录到 ECR
ecr_login() {
    echo -e "${YELLOW}🔑 登录到 ECR...${NC}"
    
    # 获取登录令牌并登录
    aws ecr get-login-password --region "$AWS_REGION" | \
        docker login --username AWS --password-stdin "$AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com"
    
    echo -e "${GREEN}✅ ECR 登录成功${NC}"
}

# 确保 ECR 仓库存在
ensure_ecr_repository() {
    echo -e "${YELLOW}📦 检查 ECR 仓库...${NC}"
    
    # 检查仓库是否存在
    if ! aws ecr describe-repositories --repository-names "$ECR_REPOSITORY_NAME" --region "$AWS_REGION" &>/dev/null; then
        echo "创建 ECR 仓库: $ECR_REPOSITORY_NAME"
        aws ecr create-repository \
            --repository-name "$ECR_REPOSITORY_NAME" \
            --region "$AWS_REGION" \
            --image-scanning-configuration scanOnPush=true \
            --image-tag-mutability MUTABLE > /dev/null
        
        # 设置生命周期策略
        local lifecycle_policy='{
            "rules": [
                {
                    "rulePriority": 1,
                    "description": "Keep last 10 images",
                    "selection": {
                        "tagStatus": "any",
                        "countType": "imageCountMoreThan",
                        "countNumber": 10
                    },
                    "action": {
                        "type": "expire"
                    }
                }
            ]
        }'
        
        aws ecr put-lifecycle-policy \
            --repository-name "$ECR_REPOSITORY_NAME" \
            --region "$AWS_REGION" \
            --lifecycle-policy-text "$lifecycle_policy" > /dev/null
    else
        echo "ECR 仓库 $ECR_REPOSITORY_NAME 已存在"
    fi
    
    echo -e "${GREEN}✅ ECR 仓库准备完成${NC}"
}

# 构建 Docker 镜像
build_docker_image() {
    echo -e "${YELLOW}🔨 构建 Docker 镜像...${NC}"
    
    cd "$LAMBDA_B_DIR"
    
    # 构建镜像
    docker build \
        --tag "$ECR_REPOSITORY_NAME:$IMAGE_TAG" \
        --tag "$ECR_URI:$IMAGE_TAG" \
        --build-arg BUILD_DATE="$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
        --build-arg VERSION="$IMAGE_TAG" \
        --build-arg PROJECT_NAME="$PROJECT_NAME" \
        --build-arg ENVIRONMENT="$ENVIRONMENT" \
        .
    
    echo -e "${GREEN}✅ Docker 镜像构建完成${NC}"
    
    # 显示镜像信息
    echo "镜像详情:"
    docker images "$ECR_REPOSITORY_NAME:$IMAGE_TAG" --format "table {{.Repository}}:{{.Tag}}\t{{.Size}}\t{{.CreatedAt}}"
}

# 测试镜像
test_docker_image() {
    echo -e "${YELLOW}🧪 测试 Docker 镜像...${NC}"
    
    # 测试镜像是否可以正常启动
    echo "测试镜像基本功能..."
    
    # 测试工具可用性
    docker run --rm "$ECR_REPOSITORY_NAME:$IMAGE_TAG" python -c "
import subprocess
try:
    subprocess.run(['bandit', '--version'], check=True, capture_output=True)
    subprocess.run(['semgrep', '--version'], check=True, capture_output=True)
    print('✅ 扫描工具测试通过')
except Exception as e:
    print(f'❌ 扫描工具测试失败: {e}')
    exit(1)
"
    
    # 测试 Python 模块导入
    docker run --rm "$ECR_REPOSITORY_NAME:$IMAGE_TAG" python -c "
try:
    import boto3
    import scanner
    import result_parser
    import s3_writer
    print('✅ Python 模块导入测试通过')
except Exception as e:
    print(f'❌ Python 模块导入测试失败: {e}')
    exit(1)
"
    
    echo -e "${GREEN}✅ Docker 镜像测试通过${NC}"
}

# 推送镜像到 ECR
push_docker_image() {
    echo -e "${YELLOW}📤 推送镜像到 ECR...${NC}"
    
    # 推送镜像
    docker push "$ECR_URI:$IMAGE_TAG"
    
    # 如果是 latest 标签，也推送一个带时间戳的版本
    if [ "$IMAGE_TAG" = "latest" ]; then
        local timestamp_tag="$(date +%Y%m%d-%H%M%S)"
        docker tag "$ECR_URI:$IMAGE_TAG" "$ECR_URI:$timestamp_tag"
        docker push "$ECR_URI:$timestamp_tag"
        echo "同时推送了时间戳版本: $timestamp_tag"
    fi
    
    echo -e "${GREEN}✅ 镜像推送完成${NC}"
}

# 清理本地镜像
cleanup_local_images() {
    echo -e "${YELLOW}🧹 清理本地镜像...${NC}"
    
    if [ "${KEEP_LOCAL_IMAGES}" != "true" ]; then
        # 清理构建过程中的中间镜像
        docker image prune -f &>/dev/null || true
        
        echo "本地镜像已保留，可手动清理:"
        echo "  docker rmi $ECR_REPOSITORY_NAME:$IMAGE_TAG"
        echo "  docker rmi $ECR_URI:$IMAGE_TAG"
    else
        echo "保留本地镜像（KEEP_LOCAL_IMAGES=true）"
    fi
    
    echo -e "${GREEN}✅ 清理完成${NC}"
}

# 显示部署信息
show_deployment_info() {
    echo
    echo -e "${GREEN}=== 镜像信息 ===${NC}"
    echo -e "ECR URI: ${GREEN}$ECR_URI:$IMAGE_TAG${NC}"
    echo -e "镜像大小: $(docker images "$ECR_URI:$IMAGE_TAG" --format "{{.Size}}")"
    echo
    echo -e "${YELLOW}💡 使用说明:${NC}"
    echo "1. 更新 ECS 任务定义中的镜像 URI"
    echo "2. 在 Lambda B 中设置环境变量 ECS_TASK_DEFINITION"
    echo "3. 确保 ECS 服务有权限从 ECR 拉取镜像"
    echo
    echo -e "${YELLOW}🔧 本地测试命令:${NC}"
    echo "docker run --rm -e SCAN_ID=test -e STUDENT_ID=test -e LANGUAGE=python -e CODE_CONTENT='print(\"hello\")' $ECR_URI:$IMAGE_TAG"
    echo
}

# 主执行流程
main() {
    echo -e "${GREEN}=== ECS 镜像构建开始 ===${NC}"
    
    check_dependencies
    ecr_login
    ensure_ecr_repository
    build_docker_image
    
    # 测试（可选，通过环境变量控制）
    if [ "${SKIP_TEST}" != "true" ]; then
        test_docker_image
    fi
    
    push_docker_image
    cleanup_local_images
    show_deployment_info
    
    echo
    echo -e "${GREEN}🎉 ECS 镜像构建和推送成功完成！${NC}"
}

# 错误处理
trap 'echo -e "${RED}❌ 构建过程中发生错误${NC}"; exit 1' ERR

# 执行主程序
main "$@"

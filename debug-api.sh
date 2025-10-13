#!/bin/bash

# 调试脚本：获取Token和OrgId，然后测试Event创建API
set -e

echo "=== MeetlyOmni API 调试脚本 ==="
echo "时间: $(date)"
echo

# 检查API健康状态
echo "1. 检查API健康状态..."
curl -sS -i http://localhost:5232/health | head -n 1
echo

# 生成唯一标识符
EMAIL="dev$(date +%s%N)@example.com"
ORGCODE="devorg$(date +%s)"
PASSWORD="Pa55-$(date +%s)-X"

echo "2. 生成测试用户信息..."
echo "Email: $EMAIL"
echo "OrgCode: $ORGCODE"
echo

# 调用dev/bootstrap获取Token和OrgId
echo "3. 调用dev/bootstrap获取认证信息..."
BOOTSTRAP_RESPONSE=$(curl -sS -X POST http://localhost:5232/api/v1/auth/dev/bootstrap \
  -H 'Content-Type: application/json' \
  -d "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\",\"organizationName\":\"Dev Org\",\"organizationCode\":\"$ORGCODE\"}")

echo "Bootstrap响应:"
echo "$BOOTSTRAP_RESPONSE" | jq . 2>/dev/null || echo "$BOOTSTRAP_RESPONSE"
echo

# 提取Token和OrgId
TOKEN=$(echo "$BOOTSTRAP_RESPONSE" | jq -r '.accessToken' 2>/dev/null)
ORG_ID=$(echo "$BOOTSTRAP_RESPONSE" | jq -r '.orgId' 2>/dev/null)

if [ "$TOKEN" = "null" ] || [ -z "$TOKEN" ]; then
    echo "❌ 无法获取Token，请检查API状态"
    exit 1
fi

if [ "$ORG_ID" = "null" ] || [ -z "$ORG_ID" ]; then
    echo "❌ 无法获取OrgId，请检查API状态"
    exit 1
fi

echo "4. 提取的认证信息:"
echo "Token前缀: ${TOKEN:0:24}..."
echo "OrgId: $ORG_ID"
echo

# 测试Event创建API
echo "5. 测试Event创建API (201场景)..."
CREATE_RESPONSE=$(curl -sS -i -X POST http://localhost:5232/api/v1/events \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $TOKEN" \
  -d "{\"orgId\":\"$ORG_ID\",\"title\":\"My Test Event\",\"description\":\"Created via API\",\"coverImageUrl\":\"https://example.com/image.png\",\"location\":\"Sydney\",\"language\":\"en\",\"status\":0}")

echo "创建事件响应:"
echo "$CREATE_RESPONSE"
echo

# 检查响应状态
HTTP_STATUS=$(echo "$CREATE_RESPONSE" | head -n 1 | grep -o '[0-9]\{3\}')
echo "HTTP状态码: $HTTP_STATUS"

if [ "$HTTP_STATUS" = "201" ]; then
    echo "✅ 事件创建成功 (201)"
elif [ "$HTTP_STATUS" = "500" ]; then
    echo "❌ 服务器内部错误 (500)"
    echo "检查数据库表是否存在..."
    
    # 检查数据库表
    echo "6. 检查数据库表结构..."
    psql -h localhost -U postgres -d meetlyomni -c "\dt" 2>/dev/null || echo "无法连接数据库"
    
elif [ "$HTTP_STATUS" = "401" ]; then
    echo "❌ 认证失败 (401)"
elif [ "$HTTP_STATUS" = "400" ]; then
    echo "❌ 请求参数错误 (400)"
else
    echo "❓ 未知状态码: $HTTP_STATUS"
fi

echo
echo "=== 调试完成 ==="

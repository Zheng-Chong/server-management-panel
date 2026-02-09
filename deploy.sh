#!/bin/bash

# 服务器管理面板部署脚本

set -e

echo "🚀 开始部署服务器管理面板..."

# 检查Python环境
if ! command -v python3 &> /dev/null; then
    echo "❌ Python3 未安装，请先安装Python3"
    exit 1
fi

# 检查pip
if ! command -v pip3 &> /dev/null; then
    echo "❌ pip3 未安装，请先安装pip3"
    exit 1
fi

# 创建虚拟环境（可选）
read -p "是否创建虚拟环境？(y/N): " create_venv
if [[ $create_venv =~ ^[Yy]$ ]]; then
    echo "📦 创建虚拟环境..."
    python3 -m venv venv
    source venv/bin/activate
    echo "✅ 虚拟环境已激活"
fi

# 安装依赖
echo "📋 安装Python依赖..."
pip3 install -r requirements.txt

# 检查是否需要数据库初始化
if [ ! -f "server_management.db" ]; then
    echo "🔄 初始化数据库..."
    python3 init_database.py
    echo "✅ 数据库初始化完成"
else
    echo "ℹ️  数据库已存在，跳过初始化"
fi

# 设置权限
chmod +x start.sh
chmod +x init_database.py
chmod +x reset_password.py

# 生产环境提醒
echo ""
echo "⚠️  生产环境部署提醒："
echo "   1. 设置环境变量 SECRET_KEY"
echo "   2. 使用 HTTPS 协议"
echo "   3. 配置防火墙"
echo "   4. 修改默认管理员密码"
echo ""

# 启动选项
read -p "是否立即启动应用？(y/N): " start_app
if [[ $start_app =~ ^[Yy]$ ]]; then
    echo "🔥 启动应用..."
    python3 app.py
else
    echo "✅ 部署完成！"
    echo ""
    echo "启动命令："
    echo "  python3 app.py"
    echo ""
    echo "访问地址："
    echo "  主面板: http://localhost:5000/"
    echo "  管理面板: http://localhost:5000/admin"
    echo ""
    echo "默认管理员账户："
    echo "  用户名: admin"
    echo "  密码: 123456"
    echo ""
    echo "项目仓库: https://github.com/Zheng-Chong/server-management-panel"
fi

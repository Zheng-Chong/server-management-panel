# 🚀 快速开始指南

这是服务器管理面板的快速开始指南，帮助你在5分钟内运行项目。

## ⚡ 一键部署

### 方法1: 使用部署脚本（推荐）
```bash
# 克隆项目
git clone https://github.com/Zheng-Chong/server-management-panel.git
cd server-management-panel

# 运行部署脚本
chmod +x deploy.sh
./deploy.sh
```

### 方法2: 手动部署
```bash
# 1. 克隆项目
git clone https://github.com/Zheng-Chong/server-management-panel.git
cd server-management-panel

# 2. 安装依赖
pip install -r requirements.txt

# 3. 初始化数据库
python init_database.py

# 4. 启动应用
python app.py
```

## 🔑 默认账户信息

访问 http://localhost:5000/admin 使用以下账户登录：

- **用户名**: `admin`
- **密码**: `123456`

> ⚠️ **重要**: 首次登录后请立即在管理面板修改密码！

## 📱 功能测试

### 1. 添加服务器
1. 登录管理面板
2. 在"服务器管理"部分点击"添加服务器"
3. 填写服务器信息：
   - 服务器名称: `测试服务器`
   - IP地址: `your-server-ip`
   - 端口: `22`
   - 用户名: `root`
   - 密码: `your-password`

### 2. 测试监控功能
1. 返回主页 http://localhost:5000
2. 查看服务器状态卡片
3. 确认显示CPU、内存、磁盘等信息

### 3. 测试用户创建
1. 在管理面板生成授权码
2. 在主页使用授权码创建用户
3. 下载SSH私钥

## 🛠️ 常见问题

**Q: 启动失败显示端口被占用**
```bash
# 查看端口使用情况
lsof -i:5000

# 或者修改端口（在app.py最后一行）
app.run(host='0.0.0.0', port=8080, debug=True)
```

**Q: 无法连接到服务器**
- 检查服务器IP和端口是否正确
- 确认网络连接正常
- 验证SSH凭据

**Q: 忘记管理员密码**
```bash
python reset_password.py
```

## 📖 下一步

- 阅读完整的 [README.md](README.md)
- 查看详细的 [DEPLOYMENT.md](DEPLOYMENT.md)
- 了解如何贡献 [CONTRIBUTING.md](CONTRIBUTING.md)

## 🆘 获取帮助

如果遇到问题：

1. 查看 [Issues](https://github.com/Zheng-Chong/server-management-panel/issues)
2. 提交新的 [Issue](https://github.com/Zheng-Chong/server-management-panel/issues/new)
3. 参考详细文档

---

🎉 **恭喜！你已经成功运行了服务器管理面板！**

# 贡献指南

感谢您对服务器管理面板项目的关注！我们欢迎所有形式的贡献。

## 🤝 如何贡献

### 报告问题
- 使用 GitHub Issues 报告bug
- 提供详细的错误信息和复现步骤
- 包含环境信息（Python版本、操作系统等）

### 提交功能建议
- 在 Issues 中描述新功能需求
- 说明功能的使用场景和价值
- 如果可能，提供设计草图或示例

### 代码贡献

#### 1. 开发环境设置
```bash
# 1. Fork 并克隆仓库
git clone https://github.com/Zheng-Chong/server-management-panel.git
cd server-management-panel

# 2. 创建虚拟环境
python -m venv venv
source venv/bin/activate  # Linux/Mac
# 或
venv\Scripts\activate  # Windows

# 3. 安装依赖
pip install -r requirements.txt

# 4. 初始化开发数据库
python migrate_data.py
```

#### 2. 开发流程
```bash
# 1. 创建功能分支
git checkout -b feature/your-feature-name

# 2. 进行开发
# 编写代码...

# 3. 测试功能
python app.py
# 访问 http://localhost:5000 测试

# 4. 提交更改
git add .
git commit -m "feat: 添加新功能描述"

# 5. 推送分支
git push origin feature/your-feature-name

# 6. 创建 Pull Request
```

## 📝 代码规范

### Python 代码风格
- 遵循 PEP 8 标准
- 使用 4 个空格缩进
- 函数和类使用docstring注释
- 变量和函数名使用小写字母和下划线

### 前端代码风格
- HTML: 使用 2 个空格缩进
- CSS: 使用 kebab-case 命名
- JavaScript: 使用 camelCase 命名

### 提交信息规范
使用 [Conventional Commits](https://www.conventionalcommits.org/) 格式：

```
类型(作用域): 简短描述

详细描述（可选）

相关Issue: #123
```

**类型说明：**
- `feat`: 新功能
- `fix`: 修复bug
- `docs`: 文档更新
- `style`: 代码格式调整
- `refactor`: 代码重构
- `test`: 测试相关
- `chore`: 构建工具或辅助工具的变动

## 🧪 测试

### 手动测试
- 测试主要功能路径
- 验证不同浏览器兼容性
- 检查响应式设计

### 测试清单
- [ ] 服务器状态显示正常
- [ ] 用户创建流程完整
- [ ] 管理员功能可用
- [ ] 错误处理适当
- [ ] 界面在不同设备上显示正常

## 🐛 调试指南

### 常见问题排查
1. **数据库问题**: 检查 `server_management.db` 文件权限
2. **SSH连接失败**: 验证服务器信息和网络连接
3. **界面显示异常**: 检查浏览器控制台错误

### 调试工具
- Flask Debug模式: 设置 `FLASK_DEBUG=1`
- Python调试器: 使用 `pdb` 或IDE调试器
- 浏览器开发工具: 检查网络请求和JavaScript错误

## 📚 项目结构说明

### 核心文件
- `app.py`: Flask应用主文件，包含路由和API
- `database.py`: 数据库操作封装
- `templates/`: HTML模板文件

### 关键功能模块
- **服务器监控**: SSH连接获取系统状态
- **用户管理**: 自动化SSH用户创建和管理
- **安全认证**: 会话管理和权限控制

## 🔒 安全注意事项

### 敏感信息处理
- 不要提交真实的服务器信息
- 加密密钥和数据库文件已在 `.gitignore` 中排除
- 测试时使用虚拟或测试环境

### 代码审查重点
- SQL注入防护
- XSS攻击防护
- 权限验证完整性
- 敏感数据加密

## 📖 文档贡献

### 文档更新
- README.md: 项目介绍和快速开始
- DEPLOYMENT.md: 详细部署说明
- API文档: 接口说明和示例

### 注释规范
- 复杂逻辑必须有注释
- 函数需要docstring说明
- 配置项需要说明作用

## 🎯 发布流程

### 版本号规范
遵循 [语义化版本](https://semver.org/) 规范：
- `主版本号.次版本号.修订号`
- 不兼容变更：主版本号+1
- 新功能：次版本号+1  
- bug修复：修订号+1

### 发布检查清单
- [ ] 所有测试通过
- [ ] 文档更新完整
- [ ] 安全审查通过
- [ ] 性能测试正常

## 💬 社区

### 沟通渠道
- GitHub Issues: 问题讨论和功能建议
- Pull Requests: 代码审查和讨论

### 行为准则
- 保持友善和专业
- 尊重不同观点
- 提供建设性反馈
- 帮助新贡献者

---

再次感谢您的贡献！如有任何问题，请随时在 Issues 中提出。

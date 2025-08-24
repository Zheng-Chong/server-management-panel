# 服务器监控系统部署文档

## 系统架构

### 新架构特点
1. **数据库存储**: 使用SQLite数据库加密存储服务器信息
2. **分离的管理界面**: 管理员功能独立为单独页面
3. **安全性增强**: 敏感信息加密存储，管理员身份验证

### 文件结构
```
ServerManage/
├── app.py                    # 主应用程序
├── database.py               # 数据库管理模块
├── init_database.py          # 数据库初始化脚本
├── reset_password.py         # 密码重置脚本
├── requirements.txt          # Python依赖
├── server_management.db      # SQLite数据库（自动生成）
├── encryption.key            # 加密密钥（自动生成）
├── templates/
│   ├── index.html           # 主监控界面
│   ├── admin.html           # 管理员界面
│   └── admin_login.html     # 管理员登录界面
└── DEPLOYMENT.md            # 部署文档
```

## 部署步骤

### 1. 安装依赖
```bash
pip install -r requirements.txt
```

### 2. 启动应用
```bash
python app.py
```

## 访问地址

- **主监控面板**: http://localhost:5000/
- **管理员登录**: http://localhost:5000/admin/login
- **管理员面板**: http://localhost:5000/admin

## 默认管理员账户

- **用户名**: admin
- **密码**: 123456

> ⚠️ **安全提醒**: 首次登录后请立即在管理面板中修改默认密码！

## 主要功能

### 主界面（用户）
- 查看服务器状态（CPU、内存、磁盘、GPU）
- 创建用户账户（需要授权码）
- 下载SSH私钥

### 管理员界面
- 服务器管理（增删改查）
- 生成用户创建授权码
- 用户管理（查看、删除、权限管理）

## 安全特性

1. **数据加密**: 服务器密码等敏感信息使用Fernet加密存储
2. **会话管理**: 管理员登录状态基于Flask session
3. **授权码系统**: 用户创建需要管理员生成的临时授权码
4. **权限隔离**: 普通用户无法访问管理功能

## 配置说明

### 环境变量
- `SECRET_KEY`: Flask会话密钥（生产环境必须设置）

### 数据库
- 自动创建SQLite数据库
- 加密密钥自动生成并保存到文件

## 注意事项

1. **生产环境部署**:
   - 设置环境变量 `SECRET_KEY`
   - 使用HTTPS
   - 配置防火墙
   - 定期备份数据库

2. **安全建议**:
   - 修改默认管理员密码
   - 保护 `encryption.key` 文件
   - 定期更新依赖

3. **备份策略**:
   - 备份 `server_management.db`
   - 备份 `encryption.key`
   - 如丢失加密密钥，所有数据将无法解密


## API文档

### 用户API
- `GET /api/status` - 获取服务器状态
- `POST /api/create-user` - 创建用户账户
- `GET /api/download-key/<server>/<user>` - 下载私钥

### 管理员API
- `POST /api/admin/login` - 管理员登录
- `POST /api/admin/logout` - 管理员登出
- `GET /api/admin/servers` - 获取服务器列表
- `POST /api/admin/servers` - 添加服务器
- `PUT /api/admin/servers/<id>` - 更新服务器
- `DELETE /api/admin/servers/<id>` - 删除服务器
- `POST /api/get-auth-code` - 生成授权码

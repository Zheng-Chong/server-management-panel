#!/usr/bin/env python3
"""
数据库初始化脚本
用于首次部署时初始化数据库和创建默认管理员账户
"""

import os
import sys
from database import DatabaseManager

def main():
    print("🔄 初始化数据库...")
    
    # 检查数据库是否已存在
    if os.path.exists('server_management.db'):
        print("⚠️  数据库文件已存在")
        overwrite = input("是否要重新初始化数据库？这将删除所有现有数据 (y/N): ")
        if not overwrite.lower().startswith('y'):
            print("❌ 取消初始化")
            return False
        
        # 备份现有数据库
        import shutil
        shutil.copy2('server_management.db', 'server_management.db.backup')
        print("📋 已备份现有数据库到 server_management.db.backup")
        
        # 删除现有数据库和密钥
        os.remove('server_management.db')
        if os.path.exists('encryption.key'):
            os.remove('encryption.key')
    
    # 初始化数据库管理器
    db = DatabaseManager()
    
    # 初始化数据库
    print("📊 创建数据库表...")
    db.init_database()
    
    # 创建默认管理员用户
    print("👤 创建默认管理员用户...")
    admin_success, admin_message = db.create_admin_user('admin', '123456')
    
    if admin_success:
        print(f"✅ {admin_message}")
        print("✅ 数据库初始化完成！")
        print()
        print("默认管理员账户信息：")
        print("  用户名: admin")
        print("  密码: 123456")
        print()
        print("⚠️  安全提醒: 请在首次登录后立即修改默认密码！")
        return True
    else:
        print(f"❌ 管理员用户创建失败: {admin_message}")
        return False

if __name__ == '__main__':
    if main():
        print("\n🎉 初始化成功！现在可以启动应用了:")
        print("   python app.py")
    else:
        print("\n💥 初始化失败！")
        sys.exit(1)

#!/usr/bin/env python3
"""
管理员密码重置脚本
用于忘记密码时重置管理员密码
"""

import os
import sys
from database import DatabaseManager

def main():
    print("🔑 管理员密码重置工具")
    print("=" * 30)
    
    # 检查数据库是否存在
    if not os.path.exists('server_management.db'):
        print("❌ 数据库文件不存在，请先运行 python init_database.py 初始化数据库")
        return False
    
    # 初始化数据库管理器
    db = DatabaseManager()
    
    # 询问新密码
    print("当前将重置管理员账户 'admin' 的密码")
    print()
    
    new_password = input("请输入新密码（至少6位）: ").strip()
    
    if len(new_password) < 6:
        print("❌ 密码长度至少需要6位")
        return False
    
    confirm_password = input("请再次输入新密码: ").strip()
    
    if new_password != confirm_password:
        print("❌ 两次输入的密码不一致")
        return False
    
    # 确认操作
    print()
    confirm = input("确定要重置密码吗？(y/N): ").strip().lower()
    if not confirm.startswith('y'):
        print("❌ 操作已取消")
        return False
    
    # 重置密码
    success, message = db.update_admin_password('admin', new_password)
    
    if success:
        print(f"✅ {message}")
        print("✅ 管理员密码重置成功！")
        print()
        print("新的登录信息：")
        print("  用户名: admin")
        print(f"  密码: {new_password}")
        print()
        print("现在可以使用新密码登录管理面板了。")
        return True
    else:
        print(f"❌ 重置失败: {message}")
        return False

if __name__ == '__main__':
    if main():
        print("\n🎉 密码重置完成！")
    else:
        print("\n💥 密码重置失败！")
        sys.exit(1)

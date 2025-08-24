import sqlite3
import json
from cryptography.fernet import Fernet
import os
import hashlib

class DatabaseManager:
    def __init__(self, db_path='server_management.db', key_file='encryption.key'):
        self.db_path = db_path
        self.key_file = key_file
        self.fernet = self._get_or_create_fernet_key()
        self.init_database()
    
    def _get_or_create_fernet_key(self):
        """获取或创建加密密钥"""
        if os.path.exists(self.key_file):
            with open(self.key_file, 'rb') as f:
                key = f.read()
        else:
            key = Fernet.generate_key()
            with open(self.key_file, 'wb') as f:
                f.write(key)
        return Fernet(key)
    
    def encrypt_data(self, data):
        """加密数据"""
        if isinstance(data, str):
            data = data.encode('utf-8')
        return self.fernet.encrypt(data).decode('utf-8')
    
    def decrypt_data(self, encrypted_data):
        """解密数据"""
        if isinstance(encrypted_data, str):
            encrypted_data = encrypted_data.encode('utf-8')
        return self.fernet.decrypt(encrypted_data).decode('utf-8')
    
    def init_database(self):
        """初始化数据库表"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # 创建服务器表
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS servers (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT UNIQUE NOT NULL,
                    ip TEXT NOT NULL,
                    port INTEGER DEFAULT 22,
                    username TEXT NOT NULL,
                    password TEXT NOT NULL,
                    description TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # 创建管理员表
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS admin_users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            conn.commit()
    
    def add_server(self, name, ip, port, username, password, description=''):
        """添加服务器"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # 加密敏感信息
                encrypted_username = self.encrypt_data(username)
                encrypted_password = self.encrypt_data(password)
                
                cursor.execute('''
                    INSERT INTO servers (name, ip, port, username, password, description)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (name, ip, port, encrypted_username, encrypted_password, description))
                
                conn.commit()
                return True, "服务器添加成功"
        except sqlite3.IntegrityError:
            return False, "服务器名称已存在"
        except Exception as e:
            return False, f"添加服务器失败: {str(e)}"
    
    def get_all_servers(self):
        """获取所有服务器（解密后）"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT * FROM servers ORDER BY name')
                rows = cursor.fetchall()
                
                servers = []
                for row in rows:
                    server = {
                        'id': row[0],
                        'name': row[1],
                        'ip': row[2],
                        'port': row[3],
                        'username': self.decrypt_data(row[4]),
                        'password': self.decrypt_data(row[5]),
                        'description': row[6],
                        'created_at': row[7],
                        'updated_at': row[8]
                    }
                    servers.append(server)
                
                return servers
        except Exception as e:
            print(f"获取服务器列表失败: {str(e)}")
            return []
    
    def get_server_by_name(self, name):
        """根据名称获取服务器"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT * FROM servers WHERE name = ?', (name,))
                row = cursor.fetchone()
                
                if row:
                    return {
                        'id': row[0],
                        'name': row[1],
                        'ip': row[2],
                        'port': row[3],
                        'username': self.decrypt_data(row[4]),
                        'password': self.decrypt_data(row[5]),
                        'description': row[6],
                        'created_at': row[7],
                        'updated_at': row[8]
                    }
                return None
        except Exception as e:
            print(f"获取服务器失败: {str(e)}")
            return None
    
    def update_server(self, server_id, name=None, ip=None, port=None, username=None, password=None, description=None):
        """更新服务器信息"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # 构建更新语句
                update_fields = []
                values = []
                
                if name is not None:
                    update_fields.append('name = ?')
                    values.append(name)
                
                if ip is not None:
                    update_fields.append('ip = ?')
                    values.append(ip)
                
                if port is not None:
                    update_fields.append('port = ?')
                    values.append(port)
                
                if username is not None:
                    update_fields.append('username = ?')
                    values.append(self.encrypt_data(username))
                
                if password is not None:
                    update_fields.append('password = ?')
                    values.append(self.encrypt_data(password))
                
                if description is not None:
                    update_fields.append('description = ?')
                    values.append(description)
                
                update_fields.append('updated_at = CURRENT_TIMESTAMP')
                values.append(server_id)
                
                if update_fields:
                    sql = f"UPDATE servers SET {', '.join(update_fields)} WHERE id = ?"
                    cursor.execute(sql, values)
                    conn.commit()
                    
                    if cursor.rowcount > 0:
                        return True, "服务器更新成功"
                    else:
                        return False, "服务器不存在"
                
                return False, "没有提供更新字段"
        
        except sqlite3.IntegrityError:
            return False, "服务器名称已存在"
        except Exception as e:
            return False, f"更新服务器失败: {str(e)}"
    
    def delete_server(self, server_id):
        """删除服务器"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('DELETE FROM servers WHERE id = ?', (server_id,))
                conn.commit()
                
                if cursor.rowcount > 0:
                    return True, "服务器删除成功"
                else:
                    return False, "服务器不存在"
        
        except Exception as e:
            return False, f"删除服务器失败: {str(e)}"
    
    def migrate_from_json(self, json_file='servers.json'):
        """从JSON文件迁移数据到数据库"""
        try:
            if not os.path.exists(json_file):
                return False, "JSON文件不存在"
            
            with open(json_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            servers = data.get('servers', [])
            success_count = 0
            error_messages = []
            
            for server in servers:
                success, message = self.add_server(
                    name=server.get('name', ''),
                    ip=server.get('ip', ''),
                    port=server.get('port', 22),
                    username=server.get('username', ''),
                    password=server.get('password', ''),
                    description=server.get('description', '')
                )
                
                if success:
                    success_count += 1
                else:
                    error_messages.append(f"服务器 {server.get('name', 'Unknown')}: {message}")
            
            if success_count > 0:
                return True, f"成功迁移 {success_count} 个服务器"
            else:
                return False, f"迁移失败: {'; '.join(error_messages)}"
        
        except Exception as e:
            return False, f"迁移失败: {str(e)}"
    
    def create_admin_user(self, username, password):
        """创建管理员用户"""
        try:
            # 使用SHA-256哈希密码
            password_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO admin_users (username, password_hash)
                    VALUES (?, ?)
                ''', (username, password_hash))
                conn.commit()
                return True, "管理员用户创建成功"
        
        except sqlite3.IntegrityError:
            return False, "管理员用户名已存在"
        except Exception as e:
            return False, f"创建管理员失败: {str(e)}"
    
    def verify_admin(self, username, password):
        """验证管理员用户"""
        try:
            password_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT id FROM admin_users 
                    WHERE username = ? AND password_hash = ?
                ''', (username, password_hash))
                
                return cursor.fetchone() is not None
        
        except Exception as e:
            print(f"验证管理员失败: {str(e)}")
            return False
    
    def update_admin_password(self, username, new_password):
        """更新管理员密码"""
        try:
            password_hash = hashlib.sha256(new_password.encode('utf-8')).hexdigest()
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    UPDATE admin_users 
                    SET password_hash = ? 
                    WHERE username = ?
                ''', (password_hash, username))
                conn.commit()
                
                if cursor.rowcount > 0:
                    return True, "密码更新成功"
                else:
                    return False, "用户不存在"
        
        except Exception as e:
            return False, f"更新密码失败: {str(e)}"

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
    
    def _safe_decrypt(self, data):
        """安全解密，如果解密失败则返回原数据"""
        if not data:
            return None
        try:
            return self.decrypt_data(data)
        except:
            # 如果解密失败，可能是明文数据，直接返回
            return data
    
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
                    password TEXT,
                    private_key TEXT,
                    dedicated_password TEXT,
                    description TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # 检查并添加private_key字段（如果不存在）
            cursor.execute('PRAGMA table_info(servers)')
            columns = [column[1] for column in cursor.fetchall()]
            if 'private_key' not in columns:
                cursor.execute('ALTER TABLE servers ADD COLUMN private_key TEXT')
            
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
    
    def add_server(self, name, ip, port, username, password=None, description='', dedicated_password=None, private_key=None):
        """添加服务器"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # 验证：密码和密钥至少提供一个
                if not password and not private_key:
                    return False, "密码和密钥至少需要提供一个"
                
                # 只加密用户名，密码和专用密码明文存储，密钥加密存储
                encrypted_username = self.encrypt_data(username)
                encrypted_key = self.encrypt_data(private_key) if private_key else None
                
                cursor.execute('''
                    INSERT INTO servers (name, ip, port, username, password, private_key, dedicated_password, description)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (name, ip, port, encrypted_username, password, encrypted_key, dedicated_password, description))
                
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
                    # 兼容旧数据结构（没有private_key字段）
                    row_list = list(row)
                    while len(row_list) < 11:
                        row_list.append(None)
                    
                    server = {
                        'id': row_list[0],
                        'name': row_list[1],
                        'ip': row_list[2],
                        'port': row_list[3],
                        'username': self.decrypt_data(row_list[4]),
                        'password': row_list[5] if row_list[5] else None,  # 明文存储，直接返回
                        'description': row_list[6] if len(row_list) > 6 else None,
                        'created_at': row_list[7] if len(row_list) > 7 else None,
                        'updated_at': row_list[8] if len(row_list) > 8 else None,
                        'dedicated_password': row_list[9] if len(row_list) > 9 and row_list[9] else None,  # 明文存储，直接返回
                        'private_key': self._safe_decrypt(row_list[10]) if len(row_list) > 10 and row_list[10] else None,  # 加密存储，需要解密
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
                    # 兼容旧数据结构（没有private_key字段）
                    row_list = list(row)
                    while len(row_list) < 11:
                        row_list.append(None)
                    
                    return {
                        'id': row_list[0],
                        'name': row_list[1],
                        'ip': row_list[2],
                        'port': row_list[3],
                        'username': self.decrypt_data(row_list[4]),
                        'password': row_list[5] if row_list[5] else None,  # 明文存储，直接返回
                        'description': row_list[6] if len(row_list) > 6 else None,
                        'created_at': row_list[7] if len(row_list) > 7 else None,
                        'updated_at': row_list[8] if len(row_list) > 8 else None,
                        'dedicated_password': row_list[9] if len(row_list) > 9 and row_list[9] else None,  # 明文存储，直接返回
                        'private_key': self._safe_decrypt(row_list[10]) if len(row_list) > 10 and row_list[10] else None,  # 加密存储，需要解密
                    }
                return None
        except Exception as e:
            print(f"获取服务器失败: {str(e)}")
            return None
    
    def update_server(self, server_id, name=None, ip=None, port=None, username=None, password=None, description=None, dedicated_password=None, private_key=None):
        """更新服务器信息"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # 如果同时更新密码和密钥，需要验证至少有一个
                if password is not None and private_key is not None:
                    if not password and not private_key:
                        return False, "密码和密钥至少需要提供一个"
                
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
                    values.append(password)  # 明文存储
                
                if private_key is not None:
                    if private_key == '':
                        update_fields.append('private_key = NULL')
                    else:
                        update_fields.append('private_key = ?')
                        values.append(self.encrypt_data(private_key))  # 加密存储
                
                if dedicated_password is not None:
                    if dedicated_password == '':
                        update_fields.append('dedicated_password = NULL')
                    else:
                        update_fields.append('dedicated_password = ?')
                        values.append(dedicated_password)  # 明文存储
                
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
                    description=server.get('description', ''),
                    dedicated_password=server.get('dedicated_password')
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

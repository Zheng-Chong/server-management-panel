from flask import Flask, render_template, jsonify, request, send_file, session, redirect, url_for
import json
import paramiko
import time
import threading
import os
import tempfile
import re
import secrets
import hashlib
from datetime import datetime, timezone, timedelta
from database import DatabaseManager

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'your-secret-key-change-in-production')

# 初始化数据库管理器
db = DatabaseManager()

# 全局变量存储服务器状态
server_status = {}

# 存储用户私钥的临时文件
user_keys = {}

# 存储授权码
auth_codes = {}

# 东八区时区
CST = timezone(timedelta(hours=8))

# 验证管理员权限的装饰器
def require_admin(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('admin_logged_in'):
            return jsonify({'success': False, 'error': '需要管理员权限'}), 401
        return f(*args, **kwargs)
    return decorated_function

def load_servers():
    """从数据库加载服务器列表"""
    return db.get_all_servers()

def execute_ssh_command(server, command):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(
            hostname=server['ip'],
            port=server['port'],
            username=server['username'],
            password=server['password'],
            timeout=10
        )
        
        stdin, stdout, stderr = ssh.exec_command(command)
        output = stdout.read().decode('utf-8')
        error = stderr.read().decode('utf-8')
        
        ssh.close()
        
        if error:
            return f"Error: {error}"
        return output
    except Exception as e:
        return f"Connection Error: {str(e)}"

def get_server_status(server):
    status = {
        'name': server['name'],
        'ip': server['ip'],
        'port': server.get('port', 22),
        'timestamp': datetime.now(CST).strftime('%Y-%m-%d %H:%M:%S'),
        'disk_usage': 'Loading...',
        'gpu_status': 'Loading...'
    }
    
    # 获取磁盘使用情况
    disk_output = execute_ssh_command(server, 'df -h')
    status['disk_usage'] = disk_output
    
    # 获取GPU状态
    gpu_output = execute_ssh_command(server, 'gpustat')
    status['gpu_status'] = gpu_output
    
    return status

def update_all_servers():
    global server_status
    
    while True:
        servers = load_servers()  # 每次循环重新加载服务器列表
        for server in servers:
            server_status[server['name']] = get_server_status(server)
        time.sleep(30)  # 每30秒更新一次

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/admin')
def admin_panel():
    """管理员面板"""
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))
    return render_template('admin.html')

@app.route('/admin/login')
def admin_login():
    """管理员登录页面"""
    return render_template('admin_login.html')

@app.route('/api/admin/login', methods=['POST'])
def admin_login_api():
    """管理员登录API"""
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({'success': False, 'error': '用户名和密码不能为空'})
    
    if db.verify_admin(username, password):
        session['admin_logged_in'] = True
        session['admin_username'] = username
        return jsonify({'success': True, 'message': '登录成功'})
    else:
        return jsonify({'success': False, 'error': '用户名或密码错误'})

@app.route('/api/admin/logout', methods=['POST'])
def admin_logout():
    """管理员退出登录"""
    session.pop('admin_logged_in', None)
    session.pop('admin_username', None)
    return jsonify({'success': True, 'message': '退出成功'})

@app.route('/api/admin/change-password', methods=['POST'])
@require_admin
def change_admin_password():
    """修改管理员密码"""
    data = request.get_json()
    old_password = data.get('old_password')
    new_password = data.get('new_password')
    
    if not old_password or not new_password:
        return jsonify({'success': False, 'error': '旧密码和新密码不能为空'})
    
    # 验证旧密码
    if not db.verify_admin('admin', old_password):
        return jsonify({'success': False, 'error': '当前密码不正确'})
    
    # 验证新密码长度
    if len(new_password) < 6:
        return jsonify({'success': False, 'error': '新密码长度至少6位'})
    
    # 更新密码
    success, message = db.update_admin_password('admin', new_password)
    
    if success:
        return jsonify({'success': True, 'message': '密码修改成功'})
    else:
        return jsonify({'success': False, 'error': message})

@app.route('/api/admin/generate-auth-code', methods=['POST'])
@require_admin
def admin_generate_auth_code():
    """管理员生成授权码（无需再次验证密码）"""
    # 生成授权码
    auth_code = secrets.token_hex(16)
    auth_codes[auth_code] = {
        'created_at': datetime.now(CST),
        'expires_in': 1800  # 30分钟 = 1800秒
    }
    
    return jsonify({
        'success': True, 
        'auth_code': auth_code,
        'expires_in': 1800,
        'message': '授权码生成成功，有效期30分钟'
    })

@app.route('/api/status')
def get_status():
    return jsonify(server_status)



def verify_auth_code(auth_code):
    """验证授权码是否有效"""
    if auth_code not in auth_codes:
        return False
    
    code_info = auth_codes[auth_code]
    current_time = datetime.now(CST)
    
    # 检查是否过期
    time_diff = (current_time - code_info['created_at']).total_seconds()
    if time_diff > code_info['expires_in']:
        # 删除过期的授权码
        del auth_codes[auth_code]
        return False
    
    return True

@app.route('/api/get-auth-code', methods=['POST'])
def get_auth_code():
    data = request.get_json()
    admin_password = data.get('admin_password')
    
    # 验证管理员密码
    if not db.verify_admin('admin', admin_password):
        return jsonify({'success': False, 'error': '管理员密码错误'})
    
    # 生成授权码
    auth_code = secrets.token_hex(16)
    auth_codes[auth_code] = {
        'created_at': datetime.now(CST),
        'expires_in': 1800  # 30分钟 = 1800秒
    }
    
    return jsonify({
        'success': True, 
        'auth_code': auth_code,
        'expires_in': 1800,
        'message': '授权码生成成功，有效期30分钟'
    })

def create_user_on_server(server, username, admin_password):
    """在指定服务器上创建用户"""
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(
            hostname=server['ip'],
            port=server['port'],
            username=server['username'],
            password=server['password'],
            timeout=10
        )
        
        # 创建用户命令序列
        commands = [
            f'echo "{admin_password}" | sudo -S useradd -s /bin/bash -m {username}',
            f'echo "{admin_password}" | sudo -S -u {username} ssh-keygen -t rsa -m PEM -f /home/{username}/.ssh/id_rsa -N ""',
            f'echo "{admin_password}" | sudo -S -u {username} cp /home/{username}/.ssh/id_rsa.pub /home/{username}/.ssh/authorized_keys',
            f'echo "{admin_password}" | sudo -S chmod 600 /home/{username}/.ssh/authorized_keys',
            f'echo "{admin_password}" | sudo -S chown {username}:{username} /home/{username}/.ssh/authorized_keys',
            f'echo "{admin_password}\\n{username}" | sudo -S passwd {username}'
        ]
        
        results = []
        for cmd in commands:
            stdin, stdout, stderr = ssh.exec_command(cmd)
            output = stdout.read().decode('utf-8')
            error = stderr.read().decode('utf-8')
            results.append(f"Command: {cmd}\nOutput: {output}\nError: {error}\n")
        
        # 获取私钥内容
        stdin, stdout, stderr = ssh.exec_command(f'echo "{admin_password}" | sudo -S cat /home/{username}/.ssh/id_rsa')
        private_key = stdout.read().decode('utf-8')
        key_error = stderr.read().decode('utf-8')
        
        ssh.close()
        
        if key_error and 'No such file' in key_error:
            return False, f"私钥文件未找到: {key_error}", None
        
        if private_key:
            return True, "用户创建成功", private_key
        else:
            return False, f"无法获取私钥: {key_error}", None
            
    except Exception as e:
        return False, f"连接错误: {str(e)}", None

@app.route('/api/create-user', methods=['POST'])
def create_user():
    data = request.get_json()
    server_name = data.get('server_name')
    username = data.get('username')
    auth_code = data.get('auth_code')
    
    # 验证授权码
    if not verify_auth_code(auth_code):
        return jsonify({'success': False, 'error': '授权码无效或已过期'})
    
    # 立即删除授权码（单次有效）
    if auth_code in auth_codes:
        del auth_codes[auth_code]
    
    # 查找服务器配置
    server = db.get_server_by_name(server_name)
    
    if not server:
        return jsonify({'success': False, 'error': '服务器未找到'})
    
    # 验证用户名格式
    if not re.match(r'^[a-zA-Z][a-zA-Z0-9_-]{0,31}$', username):
        return jsonify({'success': False, 'error': '用户名格式无效'})
    
    # 创建用户（使用固定的管理员密码）
    success, message, private_key = create_user_on_server(server, username, '123456')
    
    if success and private_key:
        # 存储私钥到临时文件
        key_id = f"{server_name}_{username}"
        user_keys[key_id] = private_key
        
        # 生成私钥文件名
        filename = f"id_rsa-{server_name}-{username}"
        
        return jsonify({
            'success': True, 
            'message': message,
            'ssh_command': f'ssh {username}@{server["ip"]} -p {server.get("port", 22)}',
            'key_filename': filename
        })
    else:
        return jsonify({'success': False, 'error': message})

@app.route('/api/get-users/<server_name>', methods=['POST'])
def get_users(server_name):
    """获取指定服务器的用户列表"""
    data = request.get_json()
    admin_password = data.get('admin_password')
    
    # 验证管理员密码
    if not db.verify_admin('admin', admin_password):
        return jsonify({'success': False, 'error': '管理员密码错误'})
    
    # 查找服务器配置
    server = db.get_server_by_name(server_name)
    
    if not server:
        return jsonify({'success': False, 'error': '服务器未找到'})
    
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(
            hostname=server['ip'],
            port=server.get('port', 22),
            username=server['username'],
            password=server['password'],
            timeout=10
        )
        
        # 获取用户列表（排除系统用户）
        stdin, stdout, stderr = ssh.exec_command("getent passwd | awk -F: '$3 >= 1000 && $3 != 65534 {print $1}' | sort")
        users_output = stdout.read().decode('utf-8').strip()
        
        if stderr.read().decode('utf-8'):
            ssh.close()
            return jsonify({'success': False, 'error': '获取用户列表失败'})
        
        users = []
        if users_output:
            user_names = users_output.split('\n')
            
            # 检查每个用户的sudo权限
            for username in user_names:
                if username.strip():
                    # 检查用户是否在sudo组或sudoers文件中
                    stdin, stdout, stderr = ssh.exec_command(f"groups {username} | grep -q sudo && echo 'sudo' || echo 'normal'")
                    sudo_status = stdout.read().decode('utf-8').strip()
                    
                    # 如果不在sudo组，检查sudoers文件
                    if sudo_status == 'normal':
                        stdin, stdout, stderr = ssh.exec_command(f"sudo grep -q '^{username}.*ALL=(ALL.*) ALL' /etc/sudoers /etc/sudoers.d/* 2>/dev/null && echo 'sudo' || echo 'normal'")
                        sudoers_status = stdout.read().decode('utf-8').strip()
                        if sudoers_status == 'sudo':
                            sudo_status = 'sudo'
                    
                    users.append({
                        'username': username,
                        'has_sudo': sudo_status == 'sudo'
                    })
        
        ssh.close()
        return jsonify({'success': True, 'users': users})
        
    except Exception as e:
        return jsonify({'success': False, 'error': f'连接服务器失败: {str(e)}'})

@app.route('/api/delete-user', methods=['POST'])
def delete_user():
    """删除用户"""
    data = request.get_json()
    server_name = data.get('server_name')
    username = data.get('username')
    admin_password = data.get('admin_password')
    
    # 验证管理员密码
    if not db.verify_admin('admin', admin_password):
        return jsonify({'success': False, 'error': '管理员密码错误'})
    
    # 验证用户名
    if not username or username in ['root', 'admin', 'administrator']:
        return jsonify({'success': False, 'error': '无法删除系统用户或管理员用户'})
    
    # 查找服务器配置
    server = db.get_server_by_name(server_name)
    
    if not server:
        return jsonify({'success': False, 'error': '服务器未找到'})
    
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(
            hostname=server['ip'],
            port=server.get('port', 22),
            username=server['username'],
            password=server['password'],
            timeout=10
        )
        
        # 先检查用户是否存在
        stdin, stdout, stderr = ssh.exec_command(f'id {username}')
        if stdout.read().decode('utf-8').strip() == '':
            ssh.close()
            return jsonify({'success': False, 'error': '用户不存在'})
        
        # 删除用户及其家目录，忽略邮件目录错误
        stdin, stdout, stderr = ssh.exec_command(f'sudo userdel -r {username} 2>&1')
        delete_output = stdout.read().decode('utf-8')
        delete_error = stderr.read().decode('utf-8')
        
        ssh.close()
        
        # 检查是否成功删除用户（忽略邮件目录相关警告）
        if 'No such user' in delete_error or 'does not exist' in delete_error:
            return jsonify({'success': False, 'error': '用户不存在'})
        elif 'userdel: user' in delete_error and 'deleted' in delete_error:
            # 成功删除，即使有邮件目录警告
            return jsonify({'success': True, 'message': f'用户 {username} 删除成功'})
        elif 'mail spool' in delete_error or 'not found' in delete_error:
            # 邮件目录相关警告，但用户可能已成功删除，再次检查
            try:
                ssh2 = paramiko.SSHClient()
                ssh2.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh2.connect(
                    hostname=server['ip'],
                    port=server.get('port', 22),
                    username=server['username'],
                    password=server['password'],
                    timeout=5
                )
                
                stdin, stdout, stderr = ssh2.exec_command(f'id {username}')
                if stdout.read().decode('utf-8').strip() == '':
                    ssh2.close()
                    return jsonify({'success': True, 'message': f'用户 {username} 删除成功'})
                else:
                    ssh2.close()
                    return jsonify({'success': False, 'error': f'删除用户失败: 用户仍然存在'})
            except:
                # 如果无法再次连接，假设删除成功（因为邮件目录错误通常是警告）
                return jsonify({'success': True, 'message': f'用户 {username} 删除成功'})
        elif delete_error:
            return jsonify({'success': False, 'error': f'删除用户失败: {delete_error}'})
        else:
            return jsonify({'success': True, 'message': f'用户 {username} 删除成功'})
        
    except Exception as e:
        return jsonify({'success': False, 'error': f'连接服务器失败: {str(e)}'})

@app.route('/api/manage-sudo', methods=['POST'])
def manage_sudo():
    """管理用户sudo权限"""
    data = request.get_json()
    server_name = data.get('server_name')
    username = data.get('username')
    action = data.get('action')  # 'grant' 或 'revoke'
    admin_password = data.get('admin_password')
    
    # 验证管理员密码
    if not db.verify_admin('admin', admin_password):
        return jsonify({'success': False, 'error': '管理员密码错误'})
    
    # 验证参数
    if not username or not action or action not in ['grant', 'revoke']:
        return jsonify({'success': False, 'error': '参数错误'})
    
    # 不能修改root用户权限
    if username == 'root':
        return jsonify({'success': False, 'error': '无法修改root用户权限'})
    
    # 查找服务器配置
    server = db.get_server_by_name(server_name)
    
    if not server:
        return jsonify({'success': False, 'error': '服务器未找到'})
    
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(
            hostname=server['ip'],
            port=server.get('port', 22),
            username=server['username'],
            password=server['password'],
            timeout=10
        )
        
        if action == 'grant':
            # 授予sudo权限：将用户添加到sudo组
            stdin, stdout, stderr = ssh.exec_command(f'sudo usermod -a -G sudo {username}')
            action_text = '授予'
        else:
            # 移除sudo权限：从sudo组移除用户
            stdin, stdout, stderr = ssh.exec_command(f'sudo gpasswd -d {username} sudo')
            action_text = '移除'
        
        output = stdout.read().decode('utf-8')
        error = stderr.read().decode('utf-8')
        
        ssh.close()
        
        if error and 'does not exist' in error:
            return jsonify({'success': False, 'error': '用户不存在'})
        elif error and 'not a member' in error:
            return jsonify({'success': False, 'error': '用户不在sudo组中'})
        elif error:
            return jsonify({'success': False, 'error': f'操作失败: {error}'})
        else:
            return jsonify({'success': True, 'message': f'成功{action_text}用户 {username} 的sudo权限'})
        
    except Exception as e:
        return jsonify({'success': False, 'error': f'连接服务器失败: {str(e)}'})

@app.route('/api/admin/servers', methods=['GET'])
@require_admin
def get_admin_servers():
    """获取所有服务器（管理员）"""
    servers = db.get_all_servers()
    return jsonify({'success': True, 'servers': servers})

@app.route('/api/admin/servers', methods=['POST'])
@require_admin
def add_server():
    """添加服务器（管理员）"""
    data = request.get_json()
    name = data.get('name')
    ip = data.get('ip')
    username = data.get('username')
    password = data.get('password')
    port = data.get('port', 22)
    description = data.get('description', '')
    
    # 验证必填字段
    if not all([name, ip, username, password]):
        return jsonify({'success': False, 'error': '所有字段都是必填的'})
    
    # 验证IP地址格式
    ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
    if not ip_pattern.match(ip):
        return jsonify({'success': False, 'error': '无效的IP地址格式'})
    
    # 验证端口号
    if not isinstance(port, int) or port < 1 or port > 65535:
        return jsonify({'success': False, 'error': '端口号必须在1-65535之间'})
    
    success, message = db.add_server(name, ip, port, username, password, description)
    return jsonify({'success': success, 'message': message if success else message})

@app.route('/api/admin/servers/<int:server_id>', methods=['PUT'])
@require_admin
def update_server(server_id):
    """更新服务器（管理员）"""
    data = request.get_json()
    
    # 验证IP地址格式（如果提供）
    if 'ip' in data:
        ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
        if not ip_pattern.match(data['ip']):
            return jsonify({'success': False, 'error': '无效的IP地址格式'})
    
    # 验证端口号（如果提供）
    if 'port' in data:
        port = data['port']
        if not isinstance(port, int) or port < 1 or port > 65535:
            return jsonify({'success': False, 'error': '端口号必须在1-65535之间'})
    
    success, message = db.update_server(
        server_id,
        name=data.get('name'),
        ip=data.get('ip'),
        port=data.get('port'),
        username=data.get('username'),
        password=data.get('password'),
        description=data.get('description')
    )
    
    return jsonify({'success': success, 'message': message})

@app.route('/api/admin/servers/<int:server_id>', methods=['DELETE'])
@require_admin
def delete_server_endpoint(server_id):
    """删除服务器（管理员）"""
    success, message = db.delete_server(server_id)
    return jsonify({'success': success, 'message': message})

@app.route('/api/admin/servers/<server_name>/users', methods=['GET'])
@require_admin
def get_server_users(server_name):
    """获取指定服务器的用户列表（管理员）"""
    # 查找服务器配置
    server = db.get_server_by_name(server_name)
    
    if not server:
        return jsonify({'success': False, 'error': '服务器未找到'})
    
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(
            hostname=server['ip'],
            port=server.get('port', 22),
            username=server['username'],
            password=server['password'],
            timeout=10
        )
        
        # 获取用户列表（排除系统用户）
        stdin, stdout, stderr = ssh.exec_command("getent passwd | awk -F: '$3 >= 1000 && $3 != 65534 {print $1}' | sort")
        users_output = stdout.read().decode('utf-8').strip()
        
        if stderr.read().decode('utf-8'):
            ssh.close()
            return jsonify({'success': False, 'error': '获取用户列表失败'})
        
        users = []
        if users_output:
            user_names = users_output.split('\n')
            
            # 检查每个用户的sudo权限
            for username in user_names:
                if username.strip():
                    # 检查用户是否在sudo组或sudoers文件中
                    stdin, stdout, stderr = ssh.exec_command(f"groups {username} | grep -q sudo && echo 'sudo' || echo 'normal'")
                    sudo_status = stdout.read().decode('utf-8').strip()
                    
                    # 如果不在sudo组，检查sudoers文件
                    if sudo_status == 'normal':
                        stdin, stdout, stderr = ssh.exec_command(f"sudo grep -q '^{username}.*ALL=(ALL.*) ALL' /etc/sudoers /etc/sudoers.d/* 2>/dev/null && echo 'sudo' || echo 'normal'")
                        sudoers_status = stdout.read().decode('utf-8').strip()
                        if sudoers_status == 'sudo':
                            sudo_status = 'sudo'
                    
                    users.append({
                        'username': username,
                        'has_sudo': sudo_status == 'sudo'
                    })
        
        ssh.close()
        return jsonify({'success': True, 'users': users})
        
    except Exception as e:
        return jsonify({'success': False, 'error': f'连接服务器失败: {str(e)}'})

@app.route('/api/admin/servers/<server_name>/users/<username>', methods=['DELETE'])
@require_admin
def delete_server_user(server_name, username):
    """删除服务器用户（管理员）"""
    # 验证用户名
    if not username or username in ['root', 'admin', 'administrator']:
        return jsonify({'success': False, 'error': '无法删除系统用户或管理员用户'})
    
    # 查找服务器配置
    server = db.get_server_by_name(server_name)
    
    if not server:
        return jsonify({'success': False, 'error': '服务器未找到'})
    
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(
            hostname=server['ip'],
            port=server.get('port', 22),
            username=server['username'],
            password=server['password'],
            timeout=10
        )
        
        # 先检查用户是否存在
        stdin, stdout, stderr = ssh.exec_command(f'id {username}')
        if stdout.read().decode('utf-8').strip() == '':
            ssh.close()
            return jsonify({'success': False, 'error': '用户不存在'})
        
        # 删除用户及其家目录，忽略邮件目录错误
        stdin, stdout, stderr = ssh.exec_command(f'sudo userdel -r {username} 2>&1')
        delete_output = stdout.read().decode('utf-8')
        delete_error = stderr.read().decode('utf-8')
        
        ssh.close()
        
        # 检查是否成功删除用户（忽略邮件目录相关警告）
        if 'No such user' in delete_error or 'does not exist' in delete_error:
            return jsonify({'success': False, 'error': '用户不存在'})
        elif 'userdel: user' in delete_error and 'deleted' in delete_error:
            return jsonify({'success': True, 'message': f'用户 {username} 删除成功'})
        elif 'mail spool' in delete_error or 'not found' in delete_error:
            # 邮件目录相关警告，但用户可能已成功删除
            return jsonify({'success': True, 'message': f'用户 {username} 删除成功'})
        elif delete_error:
            return jsonify({'success': False, 'error': f'删除用户失败: {delete_error}'})
        else:
            return jsonify({'success': True, 'message': f'用户 {username} 删除成功'})
        
    except Exception as e:
        return jsonify({'success': False, 'error': f'连接服务器失败: {str(e)}'})

@app.route('/api/admin/servers/<server_name>/users/<username>/sudo', methods=['PUT'])
@require_admin
def manage_server_user_sudo(server_name, username):
    """管理服务器用户sudo权限（管理员）"""
    data = request.get_json()
    action = data.get('action')  # 'grant' 或 'revoke'
    
    # 验证参数
    if not username or not action or action not in ['grant', 'revoke']:
        return jsonify({'success': False, 'error': '参数错误'})
    
    # 不能修改root用户权限
    if username == 'root':
        return jsonify({'success': False, 'error': '无法修改root用户权限'})
    
    # 查找服务器配置
    server = db.get_server_by_name(server_name)
    
    if not server:
        return jsonify({'success': False, 'error': '服务器未找到'})
    
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(
            hostname=server['ip'],
            port=server.get('port', 22),
            username=server['username'],
            password=server['password'],
            timeout=10
        )
        
        if action == 'grant':
            # 授予sudo权限：将用户添加到sudo组
            stdin, stdout, stderr = ssh.exec_command(f'sudo usermod -a -G sudo {username}')
            action_text = '授予'
        else:
            # 移除sudo权限：从sudo组移除用户
            stdin, stdout, stderr = ssh.exec_command(f'sudo gpasswd -d {username} sudo')
            action_text = '移除'
        
        output = stdout.read().decode('utf-8')
        error = stderr.read().decode('utf-8')
        
        ssh.close()
        
        if error and 'does not exist' in error:
            return jsonify({'success': False, 'error': '用户不存在'})
        elif error and 'not a member' in error:
            return jsonify({'success': False, 'error': '用户不在sudo组中'})
        elif error:
            return jsonify({'success': False, 'error': f'操作失败: {error}'})
        else:
            return jsonify({'success': True, 'message': f'成功{action_text}用户 {username} 的sudo权限'})
        
    except Exception as e:
        return jsonify({'success': False, 'error': f'连接服务器失败: {str(e)}'})

@app.route('/api/download-key/<server_name>/<username>')
def download_key(server_name, username):
    key_id = f"{server_name}_{username}"
    
    if key_id not in user_keys:
        return "私钥文件未找到", 404
    
    # 创建临时文件
    temp_file = tempfile.NamedTemporaryFile(mode='w', delete=False)
    temp_file.write(user_keys[key_id])
    temp_file.close()
    
    # 生成文件名
    filename = f"id_rsa-{server_name}-{username}"
    
    # 下载完成后清理
    def cleanup():
        try:
            os.unlink(temp_file.name)
            if key_id in user_keys:
                del user_keys[key_id]
        except:
            pass
    
    # 延迟清理（给下载一些时间）
    threading.Timer(60, cleanup).start()
    
    return send_file(
        temp_file.name,
        as_attachment=True,
        download_name=filename,
        mimetype='application/octet-stream'
    )

if __name__ == '__main__':
    # 启动后台线程进行定期更新
    update_thread = threading.Thread(target=update_all_servers, daemon=True)
    update_thread.start()
    
    app.run(host='0.0.0.0', port=5000, debug=True) 
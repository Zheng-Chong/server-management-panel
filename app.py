from flask import Flask, render_template, jsonify, request, send_file, session, redirect, url_for
import json
import paramiko
from paramiko.ssh_exception import SSHException
import time
import threading
import os
import tempfile
import re
import secrets
import hashlib
import io
from datetime import datetime, timezone, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError as FutureTimeoutError
from database import DatabaseManager
from collections import defaultdict
from queue import Queue
import logging

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

# 配置日志
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# SSH连接池配置
SSH_CONNECTION_TIMEOUT = 10  # SSH连接超时（秒）
SSH_COMMAND_TIMEOUT = 30  # SSH命令执行超时（秒）
SSH_POOL_MAX_SIZE = 5  # 每个服务器的最大连接池大小
SSH_POOL_IDLE_TIMEOUT = 300  # 连接空闲超时（秒）
SSH_POOL_CLEANUP_INTERVAL = 60  # 连接池清理间隔（秒）

# SSH连接池
class SSHConnectionPool:
    """SSH连接池管理器"""
    def __init__(self):
        self._pools = defaultdict(list)  # server_key -> [ssh_connections]
        self._lock = threading.RLock()
        self._last_used = {}  # server_key -> last_used_time
        self._cleanup_thread = None
        self._running = True
        
    def _get_server_key(self, server):
        """生成服务器唯一标识"""
        return f"{server['ip']}:{server.get('port', 22)}:{server['username']}"
    
    def _is_connection_alive(self, ssh):
        """检查SSH连接是否存活"""
        try:
            transport = ssh.get_transport()
            if transport is None:
                return False
            return transport.is_alive()
        except:
            return False
    
    def get_connection(self, server):
        """从连接池获取SSH连接"""
        server_key = self._get_server_key(server)
        
        with self._lock:
            # 尝试从池中获取可用连接
            while self._pools[server_key]:
                ssh = self._pools[server_key].pop(0)
                if self._is_connection_alive(ssh):
                    self._last_used[server_key] = time.time()
                    return ssh
                else:
                    try:
                        ssh.close()
                    except:
                        pass
            
            # 池中没有可用连接，创建新连接
            return None
    
    def return_connection(self, server, ssh):
        """将SSH连接返回到连接池"""
        if ssh is None:
            return
        
        server_key = self._get_server_key(server)
        
        with self._lock:
            # 检查连接是否存活
            if not self._is_connection_alive(ssh):
                try:
                    ssh.close()
                except:
                    pass
                return
            
            # 检查池大小限制
            if len(self._pools[server_key]) >= SSH_POOL_MAX_SIZE:
                try:
                    ssh.close()
                except:
                    pass
                return
            
            # 将连接返回到池中
            self._pools[server_key].append(ssh)
            self._last_used[server_key] = time.time()
    
    def close_connection(self, server, ssh):
        """关闭并移除连接"""
        if ssh is None:
            return
        
        server_key = self._get_server_key(server)
        
        with self._lock:
            try:
                if ssh in self._pools[server_key]:
                    self._pools[server_key].remove(ssh)
                ssh.close()
            except:
                pass
    
    def cleanup_idle_connections(self):
        """清理空闲连接"""
        current_time = time.time()
        
        with self._lock:
            for server_key in list(self._pools.keys()):
                last_used = self._last_used.get(server_key, 0)
                
                # 如果超过空闲超时时间，清理所有连接
                if current_time - last_used > SSH_POOL_IDLE_TIMEOUT:
                    for ssh in self._pools[server_key]:
                        try:
                            ssh.close()
                        except:
                            pass
                    del self._pools[server_key]
                    if server_key in self._last_used:
                        del self._last_used[server_key]
                else:
                    # 清理不活跃的连接
                    active_connections = []
                    for ssh in self._pools[server_key]:
                        if self._is_connection_alive(ssh):
                            active_connections.append(ssh)
                        else:
                            try:
                                ssh.close()
                            except:
                                pass
                    self._pools[server_key] = active_connections
    
    def start_cleanup_thread(self):
        """启动清理线程"""
        def cleanup_loop():
            while self._running:
                try:
                    self.cleanup_idle_connections()
                    time.sleep(SSH_POOL_CLEANUP_INTERVAL)
                except Exception as e:
                    logger.error(f"连接池清理线程错误: {str(e)}")
        
        self._cleanup_thread = threading.Thread(target=cleanup_loop, daemon=True)
        self._cleanup_thread.start()
    
    def shutdown(self):
        """关闭所有连接"""
        self._running = False
        with self._lock:
            for server_key in list(self._pools.keys()):
                for ssh in self._pools[server_key]:
                    try:
                        ssh.close()
                    except:
                        pass
                del self._pools[server_key]
            self._pools.clear()
            self._last_used.clear()

# 创建全局SSH连接池
ssh_pool = SSHConnectionPool()
ssh_pool.start_cleanup_thread()

# 统一错误处理函数
def create_error_response(error_message, status_code=400, error_code=None):
    """创建统一的错误响应格式"""
    response = {
        'success': False,
        'error': error_message
    }
    if error_code:
        response['error_code'] = error_code
    return jsonify(response), status_code

def create_success_response(data=None, message=None):
    """创建统一的成功响应格式"""
    response = {'success': True}
    if data is not None:
        response['data'] = data
    if message:
        response['message'] = message
    return jsonify(response)

# 验证管理员权限的装饰器
def require_admin(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('admin_logged_in'):
            return create_error_response('需要管理员权限', 401, 'UNAUTHORIZED')
        return f(*args, **kwargs)
    return decorated_function

def load_servers():
    """从数据库加载服务器列表"""
    return db.get_all_servers()

def connect_ssh(server, max_retries=3, delay=5, use_pool=True):
    """统一的SSH连接函数，支持密钥和密码两种方式，带重试机制和连接池"""
    # 尝试从连接池获取连接
    if use_pool:
        ssh = ssh_pool.get_connection(server)
        if ssh is not None:
            return ssh
    
    # 连接池中没有可用连接，创建新连接
    last_exception = None
    
    for attempt in range(max_retries):
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # 支持密钥和密码两种登录方式
            if server.get('private_key'):
                # 使用密钥登录
                try:
                    # 尝试从字符串创建密钥对象（RSA格式）
                    private_key_obj = paramiko.RSAKey.from_private_key(
                        file_obj=io.StringIO(server['private_key'])
                    )
                    ssh.connect(
                        hostname=server['ip'],
                        port=server.get('port', 22),
                        username=server['username'],
                        pkey=private_key_obj,
                        timeout=SSH_CONNECTION_TIMEOUT
                    )
                except Exception:
                    # 如果RSA密钥失败，尝试Ed25519格式
                    try:
                        private_key_obj = paramiko.Ed25519Key.from_private_key(
                            file_obj=io.StringIO(server['private_key'])
                        )
                        ssh.connect(
                            hostname=server['ip'],
                            port=server.get('port', 22),
                            username=server['username'],
                            pkey=private_key_obj,
                            timeout=SSH_CONNECTION_TIMEOUT
                        )
                    except Exception:
                        # 如果都失败，尝试使用密码（如果存在）
                        if server.get('password'):
                            ssh.connect(
                                hostname=server['ip'],
                                port=server.get('port', 22),
                                username=server['username'],
                                password=server['password'],
                                timeout=SSH_CONNECTION_TIMEOUT
                            )
                        else:
                            raise Exception("密钥格式错误且未提供密码")
            elif server.get('password'):
                # 使用密码登录
                ssh.connect(
                    hostname=server['ip'],
                    port=server.get('port', 22),
                    username=server['username'],
                    password=server['password'],
                    timeout=SSH_CONNECTION_TIMEOUT
                )
            else:
                raise Exception("服务器配置错误：密码和密钥至少需要提供一个")
            
            # 连接成功，返回SSH客户端
            return ssh
            
        except (SSHException, EOFError) as e:
            last_exception = e
            if attempt < max_retries - 1:
                logger.warning(f"SSH连接失败 ({str(e)}), 正在进行第 {attempt + 1}/{max_retries} 次重试... (服务器: {server.get('name', server.get('ip'))})")
                time.sleep(delay)
            else:
                logger.error(f"SSH连接失败，已达到最大重试次数 ({max_retries}次) (服务器: {server.get('name', server.get('ip'))})")
        except Exception as e:
            # 对于其他类型的异常（如配置错误），不进行重试，直接抛出
            raise e
    
    # 如果所有重试都失败，抛出最后一个异常
    raise Exception(f"SSH连接失败，已达到最大重试次数 ({max_retries}次): {str(last_exception)}")

def close_ssh(server, ssh, return_to_pool=True):
    """关闭SSH连接，可选择返回到连接池"""
    if ssh is None:
        return
    
    if return_to_pool:
        ssh_pool.return_connection(server, ssh)
    else:
        ssh_pool.close_connection(server, ssh)

def execute_ssh_command(server, command, timeout=SSH_COMMAND_TIMEOUT, use_pool=True):
    """执行SSH命令，支持超时控制和连接池"""
    ssh = None
    try:
        ssh = connect_ssh(server, use_pool=use_pool)
        
        # 执行命令并设置超时
        stdin, stdout, stderr = ssh.exec_command(command, timeout=timeout)
        
        # 等待命令完成，带超时控制
        start_time = time.time()
        while True:
            if time.time() - start_time > timeout:
                raise TimeoutError(f"命令执行超时 ({timeout}秒)")
            
            # 检查通道是否就绪
            if stdout.channel.exit_status_ready():
                break
            
            time.sleep(0.1)
        
        output = stdout.read().decode('utf-8')
        error = stderr.read().decode('utf-8')
        
        # 将连接返回到池中
        close_ssh(server, ssh, return_to_pool=use_pool)
        ssh = None
        
        if error:
            return f"Error: {error}"
        return output
    except TimeoutError as e:
        logger.error(f"SSH命令执行超时: {str(e)} (服务器: {server.get('name', server.get('ip'))}, 命令: {command[:50]})")
        if ssh:
            close_ssh(server, ssh, return_to_pool=False)  # 超时的连接不返回到池中
        return f"Timeout Error: {str(e)}"
    except Exception as e:
        logger.error(f"SSH命令执行错误: {str(e)} (服务器: {server.get('name', server.get('ip'))})")
        if ssh:
            close_ssh(server, ssh, return_to_pool=False)  # 出错的连接不返回到池中
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
    
    # 检查并安装 gpustat（如果未安装）
    check_cmd = 'gpustat --version 2>&1 || which gpustat 2>&1 || command -v gpustat 2>&1'
    check_output = execute_ssh_command(server, check_cmd)
    
    # 如果检查失败（没有找到 gpustat），尝试安装
    if not check_output.strip() or ('not found' in check_output.lower() or 'command not found' in check_output.lower()):
        # gpustat 未安装，尝试使用 pip 安装
        install_cmd = 'pip install gpustat 2>&1 || pip3 install gpustat 2>&1 || python -m pip install gpustat 2>&1 || python3 -m pip install gpustat 2>&1'
        install_output = execute_ssh_command(server, install_cmd)
        # 如果安装失败，记录错误信息
        if 'successfully' not in install_output.lower() and ('error' in install_output.lower() or 'permission denied' in install_output.lower()):
            status['gpu_status'] = f'安装 gpustat 失败: {install_output}'
            return status
    
    # 获取GPU状态
    gpu_output = execute_ssh_command(server, 'gpustat')
    status['gpu_status'] = gpu_output
    
    return status

def update_single_server(server, timeout=SSH_COMMAND_TIMEOUT * 3):
    """更新单个服务器状态（用于并发执行），带超时控制"""
    try:
        status = get_server_status(server)
        return (server['name'], status)
    except TimeoutError as e:
        logger.warning(f"更新服务器 {server['name']} 超时: {str(e)}")
        return (server['name'], {
            'name': server['name'],
            'ip': server['ip'],
            'port': server.get('port', 22),
            'timestamp': datetime.now(CST).strftime('%Y-%m-%d %H:%M:%S'),
            'disk_usage': f'Timeout Error: 操作超时',
            'gpu_status': f'Timeout Error: 操作超时'
        })
    except Exception as e:
        logger.error(f"更新服务器 {server['name']} 时发生错误: {str(e)}")
        # 如果更新失败，返回错误状态
        return (server['name'], {
            'name': server['name'],
            'ip': server['ip'],
            'port': server.get('port', 22),
            'timestamp': datetime.now(CST).strftime('%Y-%m-%d %H:%M:%S'),
            'disk_usage': f'Error: {str(e)}',
            'gpu_status': f'Error: {str(e)}'
        })

def update_all_servers():
    """更新所有服务器状态，带超时控制和连接数限制"""
    global server_status
    
    # 配置参数
    MAX_WORKERS = 10  # 最大并发线程数
    UPDATE_INTERVAL = 30  # 更新间隔（秒）
    SINGLE_SERVER_TIMEOUT = SSH_COMMAND_TIMEOUT * 3  # 单个服务器更新超时（秒）
    BATCH_TIMEOUT = 120  # 整批更新超时（秒）
    
    # 创建线程池（在循环外创建以提高效率）
    executor = ThreadPoolExecutor(max_workers=MAX_WORKERS)
    
    try:
        while True:
            try:
                start_time = time.time()
                servers = load_servers()  # 每次循环重新加载服务器列表
                current_server_names = {server['name'] for server in servers}
                
                # 清理已删除的服务器状态
                for server_name in list(server_status.keys()):
                    if server_name not in current_server_names:
                        del server_status[server_name]
                
                if not servers:
                    logger.info("没有服务器需要更新")
                    time.sleep(UPDATE_INTERVAL)
                    continue
                
                logger.info(f"开始更新 {len(servers)} 台服务器状态...")
                
                # 并发更新所有服务器状态，带超时控制
                future_to_server = {}
                for server in servers:
                    future = executor.submit(update_single_server, server, SINGLE_SERVER_TIMEOUT)
                    future_to_server[future] = server
                
                # 收集更新结果，带整体超时控制
                completed_count = 0
                timeout_futures = []
                
                for future in as_completed(future_to_server, timeout=BATCH_TIMEOUT):
                    try:
                        server_name, status = future.result(timeout=1)  # 快速获取结果
                        server_status[server_name] = status
                        completed_count += 1
                    except FutureTimeoutError:
                        # 单个future超时，记录但继续处理其他
                        server = future_to_server[future]
                        logger.warning(f"获取服务器 {server['name']} 更新结果超时")
                        timeout_futures.append(future)
                    except Exception as e:
                        server = future_to_server[future]
                        logger.error(f"更新服务器 {server['name']} 时发生错误: {str(e)}")
                        # 设置错误状态
                        server_status[server['name']] = {
                            'name': server['name'],
                            'ip': server['ip'],
                            'port': server.get('port', 22),
                            'timestamp': datetime.now(CST).strftime('%Y-%m-%d %H:%M:%S'),
                            'disk_usage': f'Error: {str(e)}',
                            'gpu_status': f'Error: {str(e)}'
                        }
                
                # 处理超时的future
                for future in timeout_futures:
                    server = future_to_server[future]
                    logger.warning(f"取消超时的服务器更新任务: {server['name']}")
                    future.cancel()
                    # 设置超时状态
                    server_status[server['name']] = {
                        'name': server['name'],
                        'ip': server['ip'],
                        'port': server.get('port', 22),
                        'timestamp': datetime.now(CST).strftime('%Y-%m-%d %H:%M:%S'),
                        'disk_usage': 'Timeout Error: 更新超时',
                        'gpu_status': 'Timeout Error: 更新超时'
                    }
                
                elapsed_time = time.time() - start_time
                logger.info(f"完成更新 {completed_count}/{len(servers)} 台服务器，耗时 {elapsed_time:.2f} 秒")
                
            except Exception as e:
                logger.error(f"更新服务器状态时发生严重错误: {str(e)}", exc_info=True)
            
            time.sleep(UPDATE_INTERVAL)  # 每30秒更新一次
            
    finally:
        logger.info("关闭服务器状态更新线程池")
        executor.shutdown(wait=True)

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
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        
        if not username or not password:
            return create_error_response('用户名和密码不能为空', 400, 'MISSING_CREDENTIALS')
        
        if db.verify_admin(username, password):
            session['admin_logged_in'] = True
            session['admin_username'] = username
            return create_success_response(message='登录成功')
        else:
            return create_error_response('用户名或密码错误', 401, 'INVALID_CREDENTIALS')
    except Exception as e:
        logger.error(f"管理员登录错误: {str(e)}", exc_info=True)
        return create_error_response('登录过程中发生错误', 500, 'INTERNAL_ERROR')

@app.route('/api/admin/logout', methods=['POST'])
def admin_logout():
    """管理员退出登录"""
    session.pop('admin_logged_in', None)
    session.pop('admin_username', None)
    return jsonify({'success': True, 'message': '退出成功'})

@app.route('/api/admin/change-password', methods=['POST'])
@require_admin
def change_admin_password():
    """修改管理员密码，统一错误处理"""
    try:
        data = request.get_json()
        old_password = data.get('old_password')
        new_password = data.get('new_password')
        
        if not old_password or not new_password:
            return create_error_response('旧密码和新密码不能为空', 400, 'MISSING_PASSWORD')
        
        # 验证旧密码
        if not db.verify_admin('admin', old_password):
            return create_error_response('当前密码不正确', 401, 'INVALID_PASSWORD')
        
        # 验证新密码长度
        if len(new_password) < 6:
            return create_error_response('新密码长度至少6位', 400, 'PASSWORD_TOO_SHORT')
        
        # 更新密码
        success, message = db.update_admin_password('admin', new_password)
        
        if success:
            return create_success_response(message='密码修改成功')
        else:
            return create_error_response(message, 400, 'PASSWORD_UPDATE_FAILED')
    except Exception as e:
        logger.error(f"修改管理员密码错误: {str(e)}", exc_info=True)
        return create_error_response('修改密码时发生错误', 500, 'INTERNAL_ERROR')

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
        ssh = connect_ssh(server)
        
        # 创建用户命令序列
        commands = [
            f'echo "{admin_password}" | sudo -S useradd -s /bin/bash -m {username}',
            f'echo "{admin_password}" | sudo -S -u {username} ssh-keygen -t rsa -m PEM -f /home/{username}/.ssh/id_rsa -N ""',
            f'echo "{admin_password}" | sudo -S -u {username} cp /home/{username}/.ssh/id_rsa.pub /home/{username}/.ssh/authorized_keys',
            f'echo "{admin_password}" | sudo -S chmod 600 /home/{username}/.ssh/authorized_keys',
            f'echo "{admin_password}" | sudo -S chown {username}:{username} /home/{username}/.ssh/authorized_keys',
            f'echo "{admin_password}" | sudo -S bash -c "echo \'{username}:{username}\' | chpasswd"'  # 正确的密码设置方式
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
    """创建用户，统一错误处理"""
    try:
        data = request.get_json()
        server_name = data.get('server_name')
        username = data.get('username')
        auth_code = data.get('auth_code')
        
        # 查找服务器配置
        server = db.get_server_by_name(server_name)
        
        if not server:
            return create_error_response('服务器未找到', 404, 'SERVER_NOT_FOUND')
        
        # 检查是否设置了专用密码
        if server.get('dedicated_password'):
            # 如果设置了专用密码，验证输入的授权码是否等于专用密码
            if auth_code != server.get('dedicated_password'):
                return create_error_response('专用密码错误', 401, 'INVALID_PASSWORD')
        else:
            # 如果没有设置专用密码，使用正常的授权码验证
            if not verify_auth_code(auth_code):
                return create_error_response('授权码无效或已过期', 401, 'INVALID_AUTH_CODE')
            
            # 立即删除授权码（单次有效）
            if auth_code in auth_codes:
                del auth_codes[auth_code]
        
        # 验证用户名格式
        if not re.match(r'^[a-zA-Z][a-zA-Z0-9_-]{0,31}$', username):
            return create_error_response('用户名格式无效', 400, 'INVALID_USERNAME_FORMAT')
        
        # 创建用户（使用固定的管理员密码）
        success, message, private_key = create_user_on_server(server, username, '123456')
        
        if success and private_key:
            # 存储私钥到临时文件
            key_id = f"{server_name}_{username}"
            user_keys[key_id] = private_key
            
            # 生成私钥文件名
            filename = f"id_rsa-{server_name}-{username}"
            
            return create_success_response({
                'message': message,
                'ssh_command': f'ssh {username}@{server["ip"]} -p {server.get("port", 22)}',
                'key_filename': filename
            }, message=message)
        else:
            return create_error_response(message, 500, 'USER_CREATION_FAILED')
    except Exception as e:
        logger.error(f"创建用户错误: {str(e)}", exc_info=True)
        return create_error_response(f'创建用户时发生错误: {str(e)}', 500, 'INTERNAL_ERROR')

@app.route('/api/get-users/<server_name>', methods=['POST'])
def get_users(server_name):
    """获取指定服务器的用户列表，统一错误处理"""
    try:
        data = request.get_json()
        admin_password = data.get('admin_password')
        
        # 验证管理员密码
        if not db.verify_admin('admin', admin_password):
            return create_error_response('管理员密码错误', 401, 'INVALID_PASSWORD')
        
        # 查找服务器配置
        server = db.get_server_by_name(server_name)
        
        if not server:
            return create_error_response('服务器未找到', 404, 'SERVER_NOT_FOUND')
        
        ssh = None
        try:
            ssh = connect_ssh(server, use_pool=True)
            
            # 获取用户列表（排除系统用户）
            stdin, stdout, stderr = ssh.exec_command("getent passwd | awk -F: '$3 >= 1000 && $3 != 65534 {print $1}' | sort", timeout=SSH_COMMAND_TIMEOUT)
            users_output = stdout.read().decode('utf-8').strip()
            error_output = stderr.read().decode('utf-8')
            
            if error_output:
                close_ssh(server, ssh, return_to_pool=False)
                return create_error_response('获取用户列表失败', 500, 'COMMAND_FAILED')
            
            users = []
            if users_output:
                user_names = users_output.split('\n')
                
                # 检查每个用户的sudo权限
                for username in user_names:
                    if username.strip():
                        # 检查用户是否在sudo组或sudoers文件中
                        stdin, stdout, stderr = ssh.exec_command(f"groups {username} | grep -q sudo && echo 'sudo' || echo 'normal'", timeout=SSH_COMMAND_TIMEOUT)
                        sudo_status = stdout.read().decode('utf-8').strip()
                        
                        # 如果不在sudo组，检查sudoers文件
                        if sudo_status == 'normal':
                            stdin, stdout, stderr = ssh.exec_command(f"sudo grep -q '^{username}.*ALL=(ALL.*) ALL' /etc/sudoers /etc/sudoers.d/* 2>/dev/null && echo 'sudo' || echo 'normal'", timeout=SSH_COMMAND_TIMEOUT)
                            sudoers_status = stdout.read().decode('utf-8').strip()
                            if sudoers_status == 'sudo':
                                sudo_status = 'sudo'
                        
                        users.append({
                            'username': username,
                            'has_sudo': sudo_status == 'sudo'
                        })
            
            close_ssh(server, ssh, return_to_pool=True)
            return create_success_response({'users': users})
            
        except TimeoutError as e:
            if ssh:
                close_ssh(server, ssh, return_to_pool=False)
            logger.error(f"获取用户列表超时: {str(e)}")
            return create_error_response('获取用户列表超时', 504, 'TIMEOUT')
        except Exception as e:
            if ssh:
                close_ssh(server, ssh, return_to_pool=False)
            logger.error(f"获取用户列表错误: {str(e)}", exc_info=True)
            return create_error_response(f'连接服务器失败: {str(e)}', 500, 'CONNECTION_ERROR')
    except Exception as e:
        logger.error(f"获取用户列表异常: {str(e)}", exc_info=True)
        return create_error_response('获取用户列表时发生错误', 500, 'INTERNAL_ERROR')

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
        ssh = connect_ssh(server)
        
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
                ssh2 = connect_ssh(server)
                
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
        ssh = connect_ssh(server)
        
        if action == 'grant':
            # 授予sudo权限：将用户添加到sudo组
            stdin, stdout, stderr = ssh.exec_command(f'sudo usermod -a -G sudo {username}')
            action_text = '授予'
        else:
            # 移除sudo权限：使用更可靠的方法
            stdin, stdout, stderr = ssh.exec_command(f'sudo deluser {username} sudo 2>/dev/null || sudo gpasswd -d {username} sudo')
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
    """添加服务器（管理员），统一错误处理"""
    try:
        data = request.get_json()
        name = data.get('name')
        ip = data.get('ip')
        username = data.get('username')
        password = data.get('password')
        private_key = data.get('private_key')
        port = data.get('port', 22)
        description = data.get('description', '')
        dedicated_password = data.get('dedicated_password')
        group = data.get('group', '')
        
        # 验证必填字段
        if not all([name, ip, username]):
            return create_error_response('名称、IP地址和用户名是必填的', 400, 'MISSING_REQUIRED_FIELDS')
        
        # 验证密码和密钥至少提供一个
        if not password and not private_key:
            return create_error_response('密码和密钥至少需要提供一个', 400, 'MISSING_CREDENTIALS')
        
        # 验证IP地址格式
        ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
        if not ip_pattern.match(ip):
            return create_error_response('无效的IP地址格式', 400, 'INVALID_IP_FORMAT')
        
        # 验证端口号
        if not isinstance(port, int) or port < 1 or port > 65535:
            return create_error_response('端口号必须在1-65535之间', 400, 'INVALID_PORT')
        
        success, message = db.add_server(name, ip, port, username, password, description, dedicated_password, private_key, group)
        if success:
            return create_success_response(message=message)
        else:
            return create_error_response(message, 400, 'ADD_SERVER_FAILED')
    except Exception as e:
        logger.error(f"添加服务器错误: {str(e)}", exc_info=True)
        return create_error_response('添加服务器时发生错误', 500, 'INTERNAL_ERROR')

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
        private_key=data.get('private_key'),
        description=data.get('description'),
        dedicated_password=data.get('dedicated_password'),
        group=data.get('group')
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
        ssh = connect_ssh(server)
        
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
        ssh = connect_ssh(server)
        
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
        ssh = connect_ssh(server)
        
        if action == 'grant':
            # 授予sudo权限：将用户添加到sudo组，同时设置密码为用户名
            commands = [
                f'sudo usermod -a -G sudo {username}',
                f'echo "{username}:{username}" | sudo chpasswd'  # 使用chpasswd设置密码
            ]
            action_text = '授予'
            
            # 执行所有命令
            all_success = True
            error_messages = []
            
            for cmd in commands:
                stdin, stdout, stderr = ssh.exec_command(cmd)
                output = stdout.read().decode('utf-8')
                error = stderr.read().decode('utf-8')
                
                if error and 'does not exist' in error:
                    ssh.close()
                    return jsonify({'success': False, 'error': '用户不存在'})
                elif error and 'chpasswd' not in cmd:  # 非密码设置命令的错误
                    all_success = False
                    error_messages.append(error)
            
            ssh.close()
            
            if all_success:
                return jsonify({'success': True, 'message': f'成功{action_text}用户 {username} 的sudo权限并设置密码为用户名'})
            else:
                return jsonify({'success': True, 'message': f'成功{action_text}用户 {username} 的sudo权限，但密码设置可能失败'})
                
        else:
            # 移除sudo权限：使用更可靠的方法
            stdin, stdout, stderr = ssh.exec_command(f'sudo deluser {username} sudo 2>/dev/null || sudo gpasswd -d {username} sudo')
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
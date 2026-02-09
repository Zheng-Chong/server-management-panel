# 配置文件示例
# 复制此文件为 config.py 并修改相应配置

import os

class Config:
    # Flask 配置
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'your-secret-key-here-change-in-production'
    
    # 数据库配置
    DATABASE_PATH = 'server_management.db'
    ENCRYPTION_KEY_PATH = 'encryption.key'
    
    # 安全配置
    SESSION_PERMANENT = False
    SESSION_USE_SIGNER = True
    
    # 授权码配置
    AUTH_CODE_EXPIRY = 1800  # 30分钟 (秒)
    
    # SSH配置
    SSH_TIMEOUT = 10  # SSH连接超时时间 (秒)
    
    # 日志配置
    LOG_LEVEL = 'INFO'
    LOG_FILE = 'app.log'

class DevelopmentConfig(Config):
    DEBUG = True
    LOG_LEVEL = 'DEBUG'

class ProductionConfig(Config):
    DEBUG = False
    # 生产环境必须设置环境变量 SECRET_KEY
    if not os.environ.get('SECRET_KEY'):
        raise ValueError("生产环境必须设置 SECRET_KEY 环境变量")

# 根据环境变量选择配置
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}

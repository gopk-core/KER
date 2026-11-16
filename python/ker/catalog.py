"""Built-in permission keys and custom-authorization types."""
from __future__ import annotations

BUILTIN = [
    ('rootuser', 'root account login', '登录 root 账号', '登入 root 帳號'),
    ('rootsu', 'execute with root privilege', '以 root 权限执行', '以 root 權限執行'),
    ('read', 'file read', '文件读取', '檔案讀取'),
    ('write', 'file write', '文件改写', '檔案改寫'),
    ('run', 'command execution', '执行命令', '執行命令'),
    ('network', 'network connections', '网络连接', '網路連線'),
    ('boot', 'system boot', '系统启动', '系統啟動'),
    ('ssh', 'SSH connections', 'SSH 连接', 'SSH 連線'),
]
BUILTIN_IDS = [item[0] for item in BUILTIN]

CUSTOM_TYPES = [
    'file_read', 'file_write', 'file_exec',
    'command', 'login', 'network', 'service', 'device',
]
GRANT_MODES = ['grant', 'lock', 'replace']

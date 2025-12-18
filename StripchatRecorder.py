import time
import datetime
import os
import threading
import sys
import configparser
import subprocess
import queue
import shlex
import tempfile
import socket
import requests
import streamlink
import shutil
import hashlib
import base64
import re
from urllib.parse import urljoin
from typing import Optional
from flask import Flask, render_template, request, redirect, url_for

if os.name == 'nt':
    import ctypes

    kernel32 = ctypes.windll.kernel32
    kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)

mainDir = os.path.abspath(sys.path[0])
Config = configparser.ConfigParser()
setting = {}

recording = []

hilos = []

# 共享状态/列表锁（hilos/recording/app_state 读写都尽量走这里）
state_lock = threading.RLock()

# 日志文件锁（避免多线程写入交叉）
log_lock = threading.Lock()
LOG_PATH = os.path.join(mainDir, 'log.log')

# 录制相关默认值
STREAM_READ_SIZE = 64 * 1024  # 单次读取字节数，过小会导致高CPU
MIN_FILE_SIZE_BYTES = 1024
ONLINE_CHECK_INTERVAL_SECONDS = 30
FILE_LINK_CHECK_INTERVAL_SECONDS = 5
FIRST_DATA_TIMEOUT_SECONDS = 20
NO_DATA_TIMEOUT_SECONDS = 45
MAX_NO_DATA_RESTARTS = 3

# requests 默认头，减少被拦截概率
DEFAULT_HEADERS = {
    'User-Agent': (
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
        'AppleWebKit/537.36 (KHTML, like Gecko) '
        'Chrome/120.0.0.0 Safari/537.36'
    ),
    'Accept': 'application/x-mpegURL,application/vnd.apple.mpegurl,application/json,text/xml,text/html,application/xhtml+xml,image/webp,text/plain,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    'Origin': 'https://stripchat.com',
    'Referer': 'https://stripchat.com/',
    'Sec-Fetch-Dest': 'empty',
    'Sec-Fetch-Mode': 'cors',
    'Sec-Fetch-Site': 'cross-site',
    'Pragma': 'no-cache',
    'Cache-Control': 'no-cache',
}

# MOUFLON Static Keys - from GitHub issue discussion
# https://github.com/lossless1024/StreaMonitor/issues/290
MOUFLON_KEYS = {
    "Zeechoej4aleeshi": "ubahjae7goPoodi6",
}

def mouflon_decode(encrypted_b64: str, key: str) -> str:
    """Decode an encrypted segment URL using XOR with SHA256 of key."""
    hash_bytes = hashlib.sha256(key.encode("utf-8")).digest()
    hash_len = len(hash_bytes)
    
    # Try with and without padding
    for padded in [encrypted_b64, encrypted_b64 + "=", encrypted_b64 + "=="]:
        try:
            encrypted_data = base64.b64decode(padded)
            decrypted_bytes = bytearray()
            for i, cipher_byte in enumerate(encrypted_data):
                key_byte = hash_bytes[i % hash_len]
                decrypted_byte = cipher_byte ^ key_byte
                decrypted_bytes.append(decrypted_byte)
            
            plaintext = decrypted_bytes.decode("utf-8", errors='replace')
            return plaintext
        except Exception:
            continue
    return None

def get_mouflon_pkeys(m3u8_content: str) -> list:
    """Extract all psch/pkey pairs from m3u8 content."""
    keys = []
    for line in m3u8_content.splitlines():
        if line.startswith('#EXT-X-MOUFLON:PSCH:'):
            parts = line.split(':')
            if len(parts) >= 4:
                psch = parts[2]  # v1 or v2
                pkey = parts[3].strip()
                keys.append((psch, pkey))
    return keys

def get_mouflon_file_entries(m3u8_content: str) -> list:
    """Extract all MOUFLON:FILE encrypted entries from m3u8 content."""
    entries = []
    for line in m3u8_content.splitlines():
        if line.startswith('#EXT-X-MOUFLON:FILE:'):
            encrypted = line.split(':', 2)[2].strip()
            entries.append(encrypted)
    return entries

def pick_best_variant_url(master_m3u8: str, master_url: str) -> Optional[str]:
    """Pick the highest quality variant from a master m3u8."""
    best_url = None
    best_score = (-1, -1, -1)  # (height, width, bandwidth)
    lines = (master_m3u8 or "").splitlines()
    i = 0
    while i < len(lines):
        line = (lines[i] or "").strip()
        if line.startswith("#EXT-X-STREAM-INF:"):
            attrs = line.split(":", 1)[1]
            bw = 0
            width = 0
            height = 0

            m = re.search(r"BANDWIDTH=(\d+)", attrs)
            if m:
                bw = int(m.group(1))

            m = re.search(r"RESOLUTION=(\d+)x(\d+)", attrs)
            if m:
                width = int(m.group(1))
                height = int(m.group(2))

            j = i + 1
            while j < len(lines) and (lines[j] or "").strip().startswith("#"):
                j += 1
            if j < len(lines):
                candidate = (lines[j] or "").strip()
                if candidate:
                    score = (height, width, bw)
                    if score > best_score:
                        best_score = score
                        best_url = candidate if candidate.startswith("http") else urljoin(master_url, candidate)
                i = j
        i += 1
    return best_url

# postProcess 队列在 main 中按需创建
processingQueue = None

def get_effective_proxy() -> str:
    """获取代理设置：优先 SC_PROXY，其次 config.conf 的 settings.proxy，最后跟随 HTTP(S)_PROXY。"""
    proxy = (os.environ.get('SC_PROXY') or os.environ.get('sc_proxy') or '').strip()
    if not proxy:
        proxy = str(setting.get('proxy') or '').strip()
    if not proxy:
        proxy = (
            os.environ.get('HTTPS_PROXY')
            or os.environ.get('https_proxy')
            or os.environ.get('HTTP_PROXY')
            or os.environ.get('http_proxy')
            or ''
        ).strip()
    if not proxy:
        return ''

    parsed = urlparse(proxy)
    if not parsed.scheme:
        # 允许直接写 host:port
        proxy = f'http://{proxy}'
    return proxy

def _now_str():
    return datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")

def log_event(message: str):
    """线程安全写入 log.log（自动添加时间戳）。"""
    if not message:
        return
    if message.endswith("\n"):
        message = message[:-1]
    line = f'\n{_now_str()} {message}\n'
    with log_lock:
        with open(LOG_PATH, 'a+', encoding='utf-8') as f:
            f.write(line)

def normalize_path(path: str) -> str:
    """将配置中的路径规范化为绝对路径（相对路径按脚本目录解析）。"""
    path = os.path.expandvars(os.path.expanduser((path or '').strip()))
    if not path:
        return path
    if not os.path.isabs(path):
        path = os.path.join(mainDir, path)
    return os.path.abspath(os.path.normpath(path))

def atomic_write_text(path: str, content: str, encoding: str = 'utf-8'):
    """原子写文件，避免 Web 编辑 wanted.txt 时被读取到半截内容。"""
    target = normalize_path(path)
    directory = os.path.dirname(target) or mainDir
    os.makedirs(directory, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(prefix='.tmp_', dir=directory)
    try:
        with os.fdopen(fd, 'w', encoding=encoding) as f:
            f.write(content)
        os.replace(tmp_path, target)
    finally:
        try:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        except OSError:
            pass

# 创建Flask应用
app = Flask(__name__)

# 添加共享状态
app_state = {
    "repeatedModels": [],
    "counterModel": 0,
    "port": 8080,  # 添加端口状态
    "web_status": "初始化中...",  # 添加web状态信息
    "storage_info": {},  # 添加存储空间信息
    "segment_duration": 30,  # 分段录制时长，默认30分钟
    "segment_duration_overridden": False,  # Web 运行时覆盖，避免被 readConfig 周期性重置
}

# 获取存储空间信息
def get_storage_info():
    """获取存储空间使用情况"""
    storage_info = {}
    
    # 优先显示录制目录所在磁盘的空间
    check_path = setting.get('save_directory') or mainDir or "/"
    try:
        total, used, free = shutil.disk_usage(check_path)
    except Exception:
        total, used, free = shutil.disk_usage("/")
    storage_info["local"] = {
        "total": total // (2**30),  # 转换为GB
        "used": used // (2**30),
        "free": free // (2**30),
        "percent_used": used * 100 // total
    }
    
    # 如果有配置远程存储，也可以添加
    # 这里需要根据实际情况调整
    
    return storage_info

# Flask路由
@app.route('/')
def index():
    """主页，显示当前状态"""
    # 更新存储空间信息
    storage = get_storage_info()
    with state_lock:
        app_state["storage_info"] = storage
        repeated_models = list(app_state.get("repeatedModels", []))
        counter_model = int(app_state.get("counterModel", 0))
        port = int(app_state.get("port", 8080))
        web_status = str(app_state.get("web_status", ""))
        segment_duration = int(app_state.get("segment_duration", 30))
        storage_info = dict(app_state.get("storage_info", {}))

    with state_lock:
        hilos_snapshot = list(hilos)
        recording_snapshot = list(recording)

    # 计算录制时长
    recording_info = []
    current_time = time.time()
    for model in recording_snapshot:
        elapsed_seconds = 0
        if hasattr(model, 'recording_start_time') and model.recording_start_time:
            elapsed_seconds = int(current_time - model.recording_start_time)
        
        # 格式化时长 HH:MM:SS
        hours, remainder = divmod(elapsed_seconds, 3600)
        minutes, seconds = divmod(remainder, 60)
        elapsed_formatted = f"{hours:02d}:{minutes:02d}:{seconds:02d}"
        
        recording_info.append({
            "name": model.modelo,
            "file": os.path.basename(model.file) if model.file else "N/A",
            "elapsed_time": elapsed_formatted
        })

    return render_template('index.html',
                           hilos=hilos_snapshot,
                           recording_info=recording_info, # 传递包含时长的新列表
                           repeatedModels=repeated_models,
                           counterModel=counter_model,
                           port=port,
                           web_status=web_status, # 传递web状态
                           segment_duration=segment_duration,
                           storage_info=storage_info,
                           up_directory=setting.get('up_directory', '未配置')) # 传递上传目录

@app.route('/edit_wanted', methods=['GET', 'POST'])
def edit_wanted():
    """查看和编辑wanted.txt文件"""
    if request.method == 'POST':
        # 保存更新后的内容到wanted.txt
        atomic_write_text(setting['wishlist'], request.form.get('content', ''))
        return redirect(url_for('index'))
    
    # 读取wanted.txt内容
    try:
        with open(setting['wishlist'], 'r', encoding='utf-8') as f:
            content = f.read()
    except FileNotFoundError:
        content = ""
    
    return render_template('edit_wanted.html', content=content)

# 添加停止录制路由
@app.route('/stop_recording/<model_name>', methods=['POST'])
def stop_recording(model_name):
    """停止特定模特的录制"""
    with state_lock:
        recording_snapshot = list(recording)
    for modelo in recording_snapshot:  # 使用快照遍历，避免在遍历过程中修改
        if modelo.modelo == model_name:
            modelo.stop()
            # 记录停止事件
            log_event(f'通过Web界面停止录制: {model_name}')
            break
    return redirect(url_for('index'))

# 添加设置分段录制时长的路由
@app.route('/set_segment_duration', methods=['POST'])
def set_segment_duration():
    """设置分段录制时长"""
    try:
        new_duration = int(request.form['duration'])
        if new_duration > 0:
            with state_lock:
                app_state["segment_duration"] = new_duration
                app_state["segment_duration_overridden"] = True
            # 记录到日志
            log_event(f'分段录制时长已更新为: {new_duration}分钟')
    except (ValueError, KeyError):
        pass  # 忽略无效输入
    return redirect(url_for('index'))

# 添加启动web服务器的函数
def start_web_server():
    """在单独的线程中启动Flask应用"""
    # 创建templates目录
    os.makedirs(os.path.join(mainDir, 'templates'), exist_ok=True)
    
    # 创建模板文件
    create_templates()
    
    # 尝试不同端口启动网页服务器
    port = 8080
    max_port = 8090  # 最大尝试端口
    
    while port <= max_port:
        try:
            with state_lock:
                app_state["port"] = port  # 更新当前使用的端口
                # 更新web状态信息
                app_state["web_status"] = f"Web服务器正在启动，端口: {port}..."
            print(f"\n[Web服务] 正在端口 {port} 上启动Web界面...")
            
            # 先检查端口是否被占用
            import socket
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                result = sock.connect_ex(('127.0.0.1', port))
            
            if result == 0:  # 端口已被占用
                raise OSError(f"端口 {port} 已被占用")
            
            # 尝试启动服务器
            success_msg = f"[Web服务] Web界面运行中: http://localhost:{port} 或 http://服务器IP:{port}"
            print(success_msg)
            with state_lock:
                app_state["web_status"] = success_msg
            log_event(success_msg)
            app.run(host='0.0.0.0', port=port, debug=False, use_reloader=False, threaded=True)
            return  # app.run 阻塞，正常情况下不会返回
        except Exception as e:
            # 捕获所有异常，不仅仅是OSError
            error_type = type(e).__name__
            error_msg = str(e)
            print(f"[Web服务] 端口 {port} 启动失败: {error_type} - {error_msg}")
            print(f"[Web服务] 尝试端口 {port+1}")
            
            # 记录到日志文件
            log_event(f'Web服务启动错误: 端口={port}, 错误类型={error_type}, 错误信息={error_msg}')
            
            port += 1
            if port > max_port:
                final_error_msg = f"[Web服务] 无法找到可用端口（{8080}-{max_port}），Web界面未启动"
                print(final_error_msg)
                with state_lock:
                    app_state["web_status"] = final_error_msg
                
                # 记录到日志文件
                log_event(final_error_msg)
                break

def create_templates():
    """创建HTML模板"""
    index_html = """<!DOCTYPE html>
<html>
<head>
    <title>StripchatRecorder 状态</title>
    <meta charset="UTF-8">
    <meta http-equiv="refresh" content="15"> <!-- Refresh interval 15 seconds -->
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 20px; background-color: #f4f7f6; color: #333; }
        .container { max-width: 1000px; margin: 0 auto; display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; }
        .card { background-color: #fff; border-radius: 8px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); padding: 20px; }
        .card h2 { margin-top: 0; color: #0056b3; border-bottom: 2px solid #eee; padding-bottom: 10px; font-size: 1.2em; }
        .card h3 { margin-top: 15px; margin-bottom: 10px; color: #333; font-size: 1.1em; }
        table { width: 100%; border-collapse: collapse; margin-top: 15px; }
        th, td { padding: 10px 12px; text-align: left; border-bottom: 1px solid #eee; font-size: 0.95em; }
        th { background-color: #f8f9fa; color: #555; font-weight: 600; }
        td { vertical-align: middle; }
        .button { display: inline-block; padding: 10px 18px; background-color: #28a745; 
                 color: white; text-decoration: none; border-radius: 5px; margin-top: 20px; border: none; cursor: pointer; font-size: 1em; }
        .button:hover { background-color: #218838; }
        .btn-edit { background-color: #007bff; }
        .btn-edit:hover { background-color: #0056b3; }
        .btn-stop { background-color: #dc3545; color: white; padding: 6px 12px; 
                  border: none; cursor: pointer; border-radius: 4px; font-size: 0.9em; }
        .btn-stop:hover { background-color: #c82333; }
        .info, .warning { border-left-width: 5px; border-left-style: solid; padding: 12px 15px; margin: 15px 0; border-radius: 4px; }
        .info { background-color: #e7f3fe; border-left-color: #2196F3; }
        .warning { background-color: #fff3cd; border-left-color: #ffc107; }
        .danger { background-color: #f8d7da; border-left-color: #dc3545; }
        .progress-bar { height: 22px; background-color: #e9ecef; border-radius: 5px; overflow: hidden; margin-top: 5px; }
        .progress { height: 100%; background-color: #28a745; display: flex; align-items: center; justify-content: center; color: white; font-size: 0.8em; font-weight: bold; }
        .progress.warning { background-color: #ffc107; color: #333; }
        .progress.danger { background-color: #dc3545; }
        .settings-form { background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin-top: 20px; border: 1px solid #ddd; }
        .settings-form label { margin-right: 10px; }
        .settings-form input[type="number"] { padding: 8px; width: 80px; border: 1px solid #ccc; border-radius: 4px; }
        .settings-form button { padding: 8px 15px; background-color: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; margin-left: 10px; }
        .settings-form button:hover { background-color: #0056b3; }
        .full-width { grid-column: 1 / -1; } /* Span across all columns */
        .overview-item { margin-bottom: 8px; font-size: 0.95em; }
        .overview-item strong { color: #0056b3; }
        code { background-color: #e9ecef; padding: 2px 5px; border-radius: 3px; font-family: monospace; }
    </style>
    <script>
        function confirmStop(modelName) {
            return confirm('确定要停止录制模特 "' + modelName + '" 吗？');
        }
    </script>
</head>
<body>
    <div class="container">
        <div class="card full-width">
            <h2>StripchatRecorder 状态监控</h2>
        </div>

        <div class="card">
            <h2>概览</h2>
            <div class="overview-item">Web 界面端口: <strong>{{ port }}</strong></div>
            <div class="overview-item">Web 服务状态: <strong>{{ web_status }}</strong></div>
            <div class="overview-item">上传目录 (up): <code>{{ up_directory }}</code></div>
             {% if repeatedModels %}
            <div class="warning overview-item">
                重复模特: {{ repeatedModels|join(', ') }}
            </div>
            {% endif %}
        </div>

        <div class="card">
            <h2>统计</h2>
            <div class="overview-item">活跃检测线程: <strong>{{ hilos|length }}</strong></div>
            <div class="overview-item">正在录制模特: <strong>{{ recording_info|length }}</strong></div>
            <div class="overview-item">Wanted 列表总数: <strong>{{ counterModel }}</strong></div>
            <a href="/edit_wanted" class="button btn-edit">编辑 Wanted 列表</a>
        </div>

        <div class="card">
            <h2>分段录制设置</h2>
            <form action="/set_segment_duration" method="post" class="settings-form">
                <label for="duration">分段时长 (分钟):</label>
                <input type="number" id="duration" name="duration" value="{{ segment_duration }}" min="1" required>
                <button type="submit">保存</button>
            </form>
            <p style="margin-top: 10px; font-size: 0.9em;">当前: 每 <strong>{{ segment_duration }}</strong> 分钟自动分段。</p>
        </div>

        <div class="card">
            <h2>存储空间 (本地)</h2>
            <table>
                <tr><th>总容量</th><td>{{ storage_info.local.total }} GB</td></tr>
                <tr><th>已使用</th><td>{{ storage_info.local.used }} GB</td></tr>
                <tr><th>剩   余</th><td>{{ storage_info.local.free }} GB</td></tr>
                <tr>
                    <th>使用率</th>
                    <td>
                        <div class="progress-bar">
                            <div class="progress {% if storage_info.local.percent_used > 90 %}danger{% elif storage_info.local.percent_used > 70 %}warning{% endif %}" 
                                 style="width: {{ storage_info.local.percent_used }}%">{{ storage_info.local.percent_used }}%</div>
                        </div>
                    </td>
                </tr>
            </table>
        </div>
        
        {% if recording_info %}
        <div class="card full-width">
            <h2>当前正在录制的模特 ({{ recording_info|length }})</h2>
            <table>
                <thead>
                    <tr>
                        <th>模特名</th>
                        <th>当前文件名</th>
                        <th>已录制时长</th>
                        <th>操作</th>
                    </tr>
                </thead>
                <tbody>
                {% for model in recording_info %}
                <tr>
                    <td>{{ model.name }}</td>
                    <td>{{ model.file }}</td>
                    <td>{{ model.elapsed_time }}</td>
                    <td>
                        <form action="/stop_recording/{{ model.name }}" method="post" style="display: inline;">
                            <button type="submit" class="btn-stop" onclick="return confirmStop('{{ model.name }}');">停止录制</button>
                        </form>
                    </td>
                </tr>
                {% endfor %}
                </tbody>
            </table>
        </div>
        {% else %}
        <div class="card full-width info">
            <p>当前没有模特正在录制</p>
        </div>
        {% endif %}
        
    </div>
</body>
</html>"""

    edit_html = """<!DOCTYPE html>
<html>
<head>
    <title>编辑 Wanted 列表</title>
    <meta charset="UTF-8">
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 20px; background-color: #f4f7f6; color: #333; }
        .container { max-width: 900px; margin: 20px auto; background-color: #fff; padding: 30px; border-radius: 8px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        h1 { color: #0056b3; border-bottom: 2px solid #eee; padding-bottom: 10px; }
        textarea { width: 100%; height: 400px; margin-top: 20px; padding: 15px; border: 1px solid #ccc; border-radius: 5px; font-size: 1em; box-sizing: border-box; }
        .button { display: inline-block; padding: 12px 20px; background-color: #28a745; 
                 color: white; text-decoration: none; border-radius: 5px; margin-top: 15px;
                 border: none; cursor: pointer; font-size: 1em; transition: background-color 0.2s ease; }
        .button:hover { background-color: #218838; }
        .cancel { background-color: #6c757d; margin-left: 10px; }
        .cancel:hover { background-color: #5a6268; }
        .button-group { margin-top: 20px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>编辑 Wanted 列表</h1>
        <p>每行输入一个模特名称。保存后将自动重新加载列表。</p>
        
        <form method="post">
            <textarea name="content" placeholder="在此输入模特名...">{{ content }}</textarea>
            <div class="button-group">
                <button type="submit" class="button">保存更改</button>
                <a href="/" class="button cancel">取消</a>
            </div>
        </form>
    </div>
</body>
</html>"""

    # 写入模板文件
    templates_dir = os.path.join(mainDir, 'templates')
    os.makedirs(templates_dir, exist_ok=True)
    with open(os.path.join(templates_dir, 'index.html'), 'w', encoding='utf-8') as f:
        f.write(index_html)
    
    with open(os.path.join(templates_dir, 'edit_wanted.html'), 'w', encoding='utf-8') as f:
        f.write(edit_html)

def firstRun():
    script = os.path.join(mainDir, 't.sh')
    if os.path.isfile(script):
        subprocess.call(['bash', script], cwd=mainDir)


def cls():
    os.system('cls' if os.name == 'nt' else 'clear')


def readConfig():
    global setting

    config_path = os.path.join(mainDir, 'config.conf')
    Config.read(config_path)

    save_directory = normalize_path(Config.get('paths', 'save_directory', fallback='./captures'))
    wishlist = normalize_path(Config.get('paths', 'wishlist', fallback='./wanted.txt'))
    proxy = (Config.get('settings', 'proxy', fallback='') or '').strip()

    try:
        interval = int(Config.get('settings', 'checkInterval', fallback='20'))
    except ValueError:
        interval = 20

    post_cmd = Config.get('settings', 'postProcessingCommand', fallback='').strip()
    try:
        post_threads = int(Config.get('settings', 'postProcessingThreads', fallback='1'))
    except ValueError:
        post_threads = 1

    if not post_cmd:
        post_threads = 0
    else:
        post_threads = max(1, post_threads)

    setting = {
        'save_directory': save_directory,
        'wishlist': wishlist,
        'interval': interval,
        'postProcessingCommand': post_cmd,
        'postProcessingThreads': post_threads,
        'proxy': proxy,
    }
    
    try:
        segment_duration = int(Config.get('settings', 'segmentDuration', fallback='0'))
        if segment_duration > 0:
            with state_lock:
                if not app_state.get("segment_duration_overridden", False):
                    app_state["segment_duration"] = segment_duration
    except ValueError:
        pass  # 值无效则忽略，沿用当前设置
        
    log_event(f'配置加载完毕.')

    os.makedirs(setting["save_directory"], exist_ok=True)
    
    # 创建与captures平级的up文件夹，用于存放待上传的已完成录制
    captures_parent_dir = os.path.dirname(setting['save_directory'])
    up_dir = os.path.join(captures_parent_dir, 'up')
    setting['up_directory'] = up_dir  # 保存到设置中方便其他函数使用
    os.makedirs(up_dir, exist_ok=True)


def process_existing_captures():
    """处理已经存在于captures目录中的录制文件，将它们移动到up目录"""
    import glob
    
    captures_dir = setting.get('save_directory')
    up_dir = setting.get('up_directory')  # 使用保存在设置中的up目录路径
    if not captures_dir or not os.path.isdir(captures_dir) or not up_dir:
        return
    
    # 查找所有模特子目录
    model_dirs = [d for d in os.listdir(captures_dir) if os.path.isdir(os.path.join(captures_dir, d)) and d != 'up']
    
    moved_count = 0
    for model_dir in model_dirs:
        model_path = os.path.join(captures_dir, model_dir)
        # 查找所有MP4文件
        mp4_files = glob.glob(os.path.join(model_path, '*.mp4'))
        
        for file_path in mp4_files:
            # 检查文件是否大于1KB
            if os.path.getsize(file_path) > MIN_FILE_SIZE_BYTES:
                try:
                    # 创建模特名称对应的up子目录
                    model_up_dir = os.path.join(up_dir, model_dir)
                    os.makedirs(model_up_dir, exist_ok=True)
                    
                    filename = os.path.basename(file_path)
                    dest_path = os.path.join(model_up_dir, filename)
                    # 移动文件
                    shutil.move(file_path, dest_path)
                    moved_count += 1
                    # 记录日志
                    log_event(f'已存在的文件已移动到上传文件夹: {dest_path}')
                except Exception as e:
                    log_event(f'移动已存在文件时出错: {file_path} -> {e}')
    
    if moved_count > 0:
        print(f"[初始化] 已将 {moved_count} 个现有录制文件移动到上传文件夹")


def postProcess():
    log_event('[线程] 后处理线程 postProcess 已启动。')

    while True:
        try:
            if processingQueue is None:
                time.sleep(1)
                continue

            try:
                parameters = processingQueue.get(timeout=1)
            except queue.Empty:
                continue

            try:
                model = parameters.get('model', '未知模型')
                path = parameters.get('path')

                if not path or not os.path.isfile(path):
                    log_event(f'[错误][postProcess] 从队列获取的任务无效或文件不存在: {parameters}')
                    continue

                filename = os.path.basename(path)
                directory = os.path.dirname(path)
                file_base = os.path.splitext(filename)[0]

                log_event(f'[postProcess] 开始处理文件: {filename} (来自队列)')

                post_cmd_str = (setting.get('postProcessingCommand') or '').strip()
                if post_cmd_str:
                    cmd_list = shlex.split(post_cmd_str) + [path, filename, directory, model, file_base, 'cam4']
                    log_event(f'[postProcess] 准备调用命令: {" ".join(cmd_list)}')

                    timeout_seconds = 600
                    try:
                        result = subprocess.run(
                            cmd_list,
                            check=False,
                            capture_output=True,
                            text=True,
                            timeout=timeout_seconds,
                            cwd=mainDir,
                        )
                        if result.returncode == 0:
                            log_event(f'[postProcess] 命令成功完成 (退出码 0): {filename}')
                        else:
                            log_event(
                                f'[错误][postProcess] 命令执行失败 (退出码 {result.returncode}) for {filename}:\n'
                                f'  命令: {" ".join(cmd_list)}\n'
                                f'  Stdout: {result.stdout.strip()}\n'
                                f'  Stderr: {result.stderr.strip()}'
                            )
                    except subprocess.TimeoutExpired:
                        log_event(f'[错误][postProcess] 命令执行超时 ({timeout_seconds}秒): {" ".join(cmd_list)} for {filename}')
                    except FileNotFoundError:
                        log_event(f'[错误][postProcess] 命令未找到 (请检查路径): {cmd_list[0]} for {filename}')
                    except Exception as e:
                        log_event(
                            f'[错误][postProcess] 调用命令时发生未知异常 for {filename}: {e}\n'
                            f'  命令: {" ".join(cmd_list)}'
                        )
                else:
                    log_event(f'[警告][postProcess] 未配置 postProcessingCommand，跳过后处理步骤 for {filename}')
            finally:
                processingQueue.task_done()
        except Exception as e:
            log_event(f'[致命错误][postProcess] 后处理线程遇到意外错误: {e}')
            time.sleep(5)


class Modelo(threading.Thread):
    def __init__(self, modelo):
        super().__init__()
        self.modelo = modelo
        self._stopevent = threading.Event()
        self.file = None
        self.online = None
        self.segment_start_time = time.time()  # 记录片段开始时间
        self.recording_start_time = None      # 新增：记录本次录制开始时间
        self.http = requests.Session()
        self.http.headers.update(DEFAULT_HEADERS)
        self._applied_proxy = None

    def _refresh_proxy(self):
        """根据配置/环境变量更新 requests 代理（避免 isOnline 调用时崩溃）。"""
        proxy = (os.environ.get("SC_PROXY") or setting.get("proxy") or "").strip()
        if proxy == self._applied_proxy:
            return
        self._applied_proxy = proxy

        if not proxy:
            self.http.proxies = {}
            return

        # requests 使用字典形式配置代理
        self.http.proxies = {
            "http": proxy,
            "https": proxy,
        }

    def run_mouflon(self, stream_name: str, psch: str, pkey: str, decrypt_key: str):
        """MOUFLON-aware HLS recording using authenticated URLs and segment decryption."""
        global recording, hilos
        
        log_event(f'[MOUFLON] 开始录制 {self.modelo} (streamName={stream_name}, pkey={pkey})')
        
        try:
            # Create output directory and file
            os.makedirs(os.path.join(setting['save_directory'], self.modelo), exist_ok=True)
            self.create_new_file()
            
            with state_lock:
                if self not in recording:
                    recording.append(self)
                hilos[:] = [t for t in hilos if t.modelo != self.modelo]
            
            self.online = True
            self.recording_start_time = time.time()
            self.segment_start_time = self.recording_start_time
            
            # Get variant playlist URL (prefer highest quality)
            master_url = f'https://edge-hls.doppiocdn.com/hls/{stream_name}/master/{stream_name}_auto.m3u8'
            master_resp = self.http.get(master_url, timeout=15)
            
            if master_resp.status_code != 200:
                log_event(f'[MOUFLON] 获取主播放列表失败: {self.modelo} (status={master_resp.status_code})')
                return
            
            # Prefer highest quality variant
            variant_url = pick_best_variant_url(master_resp.text, master_url)
            if not variant_url:
                # Fallback: pick first absolute URL if parsing fails
                variant_urls = re.findall(r'(https://media-hls[^\s]+\.m3u8)', master_resp.text)
                variant_url = variant_urls[0] if variant_urls else None
            
            if not variant_url:
                log_event(f'[MOUFLON] 未找到变体播放列表: {self.modelo}')
                return
            
            # Add authentication params
            auth_variant_url = f"{variant_url}?psch={psch}&pkey={pkey}&playlistType=lowLatency"
            
            print(f"[开始录制] 开始 MOUFLON 录制模特 {self.modelo} 到文件 {os.path.basename(self.file)}")
            log_event(f'开始 MOUFLON 录制: {self.modelo} -> {self.file}')
            
            seen_segments = set()
            current_file = open(self.file, 'wb', buffering=1024 * 1024)
            last_online_check = time.time()
            
            try:
                segment_duration_seconds = int(app_state.get("segment_duration", 30)) * 60
            except Exception:
                segment_duration_seconds = 30 * 60
            
            init_downloaded = False
            
            while not self._stopevent.is_set():
                current_time = time.time()
                
                # Period online check
                if current_time - last_online_check >= ONLINE_CHECK_INTERVAL_SECONDS:
                    if not self.isOnline():
                        log_event(f'模特已下线，停止录制: {self.modelo}')
                        break
                    last_online_check = current_time
                
                # File segmentation
                if segment_duration_seconds and (current_time - self.segment_start_time >= segment_duration_seconds):
                    current_file.close()
                    completed_file = self.file
                    self._handle_completed_file(completed_file, use_postprocess=False, label='分段')
                    
                    self.segment_start_time = current_time
                    self.create_new_file()
                    current_file = open(self.file, 'wb', buffering=1024 * 1024)
                    init_downloaded = False  # Need to re-download init for new file
                    log_event(f'[分段] 创建新文件: {self.file}')
                
                # Fetch variant playlist
                try:
                    resp = self.http.get(auth_variant_url, timeout=10)
                    if resp.status_code != 200:
                        log_event(f'[MOUFLON] 获取变体播放列表失败: {resp.status_code}')
                        time.sleep(2)
                        continue
                except Exception as e:
                    log_event(f'[MOUFLON] 请求失败: {e}')
                    time.sleep(2)
                    continue
                
                playlist_content = resp.text
                
                # Download init segment if not yet done
                if not init_downloaded:
                    init_match = re.search(r'#EXT-X-MAP:URI="([^"]+)"', playlist_content)
                    if init_match:
                        init_url = init_match.group(1)
                        try:
                            init_resp = self.http.get(init_url, timeout=15)
                            if init_resp.status_code == 200:
                                current_file.write(init_resp.content)
                                init_downloaded = True
                                log_event(f'[MOUFLON] 下载 init 段成功: {len(init_resp.content)} bytes')
                        except Exception as e:
                            log_event(f'[MOUFLON] 下载 init 段失败: {e}')
                
                # Extract and decrypt MOUFLON:FILE entries
                mouflon_files = get_mouflon_file_entries(playlist_content)
                
                for encrypted in mouflon_files:
                    if encrypted in seen_segments:
                        continue
                    
                    # Decrypt to get real segment filename
                    decrypted_filename = mouflon_decode(encrypted, decrypt_key)
                    if not decrypted_filename or '\ufffd' in decrypted_filename:
                        continue  # Decryption failed
                    
                    # Construct full segment URL
                    base_url = variant_url.rsplit('/', 1)[0]
                    segment_url = f"{base_url}/{decrypted_filename}"
                    
                    try:
                        seg_resp = self.http.get(segment_url, timeout=15)
                        if seg_resp.status_code == 200:
                            current_file.write(seg_resp.content)
                            seen_segments.add(encrypted)
                        else:
                            log_event(f'[MOUFLON] 分段下载失败: {seg_resp.status_code} - {decrypted_filename[:50]}')
                    except Exception as e:
                        log_event(f'[MOUFLON] 分段请求异常: {e}')
                
                # Short sleep before next playlist refresh
                time.sleep(0.5)
            
            # Cleanup
            current_file.close()
            self._handle_completed_file(self.file, use_postprocess=True)
            
        except Exception as e:
            log_event(f'[MOUFLON] 录制异常: {self.modelo} - {e}')
        finally:
            with state_lock:
                if self in recording:
                    recording.remove(self)
            self.online = False

    def _try_mouflon_recording(self):
        """
        Try to use MOUFLON-based recording if static keys are available.
        Returns True if MOUFLON recording was attempted (success or fail).
        Returns None if MOUFLON is not available (fallback to Streamlink).
        """
        try:
            # Get stream info from API
            url = f'https://stripchat.com/api/front/v2/models/username/{self.modelo}/cam'
            resp = self.http.get(url, timeout=10)
            resp.raise_for_status()
            data = resp.json()
            
            if not isinstance(data, dict) or 'cam' not in data:
                return None  # Fallback to Streamlink
            
            cam = data['cam']
            if not cam.get('isCamAvailable') or not cam.get('streamName'):
                return None  # Not online, fallback
            
            stream_name = cam['streamName']
            
            # Get master m3u8 to find available pkeys
            master_url = f'https://edge-hls.doppiocdn.com/hls/{stream_name}/master/{stream_name}_auto.m3u8'
            master_resp = self.http.get(master_url, timeout=10)
            
            if master_resp.status_code != 200:
                log_event(f'[MOUFLON] 无法获取主播放列表，回退到 Streamlink: {self.modelo}')
                return None  # Fallback
            
            pkey_pairs = get_mouflon_pkeys(master_resp.text)
            
            # Find a pkey that we have a static key for
            for psch, pkey in pkey_pairs:
                if pkey in MOUFLON_KEYS:
                    decrypt_key = MOUFLON_KEYS[pkey]
                    log_event(f'[MOUFLON] 找到匹配的静态密钥: pkey={pkey}')
                    self.run_mouflon(stream_name, psch, pkey, decrypt_key)
                    return True  # MOUFLON recording was attempted
            
            # No matching keys found
            log_event(f'[MOUFLON] 没有找到匹配的静态密钥，回退到 Streamlink: {self.modelo}')
            return None  # Fallback
            
        except Exception as e:
            log_event(f'[MOUFLON] 检测失败，回退到 Streamlink: {self.modelo} - {e}')
            return None  # Fallback

    def run(self):
        global recording, hilos
        started_recording = False
        fd = None
        sl_session = None
        current_file = None

        try:
            # First, try to use MOUFLON recording if keys are available
            mouflon_result = self._try_mouflon_recording()
            if mouflon_result is not None:
                return  # MOUFLON recording handled (success or fail), don't continue
            
            # Fall back to Streamlink-based recording
            hls_url = self.isOnline()
            if not hls_url:
                self.online = False
                return

            self.online = True

            # 确保目录存在
            os.makedirs(os.path.join(setting['save_directory'], self.modelo), exist_ok=True)

            # 录制开始前创建初始文件路径
            self.create_new_file()

            session = streamlink.Streamlink()
            
            # 构造 Streamlink Headers
            sl_headers = DEFAULT_HEADERS.copy()
            session.set_option("http-headers", sl_headers)
            
            # 传递 Cookies (Standard Jar)
            if self.http.cookies:
                session.set_option("http-cookies", self.http.cookies.get_dict())

            if 'stripchat.com' in hls_url: # 是 Profile URL
                log_event(f'使用 Streamlink 插件处理 Profile URL: {hls_url}')
                try:
                    streams = session.streams(hls_url)
                except Exception as e:
                    log_event(f'Streamlink 获取流异常: {self.modelo} - {e}')
                    # import traceback
                    # log_event(traceback.format_exc())
                    streams = None
            else: # 是 HLS URL
                streams = session.streams(f'hlsvariant://{hls_url}')
                
            if not streams:
                log_event(f'Streamlink 未获取到流: {self.modelo}')
                self.online = False
                return

            # 打开流并等待第一段数据（避免写空文件）
            sl_session, fd, first_data, _ = self._open_streamlink_fd(stream_name)
            if fd is None or not first_data:
                self.online = False
                return

            # 真正开始录制：收到第一段数据后再创建文件
            self.recording_start_time = time.time()
            self.segment_start_time = self.recording_start_time

            self.create_new_file()
            current_file = open(self.file, 'wb', buffering=1024 * 1024)
            current_file.write(first_data)
            started_recording = True

            # 从 hilos 转入 recording（仅在真正开始写入后）
            with state_lock:
                if self not in recording:
                    recording.append(self)
                hilos[:] = [t for t in hilos if t.modelo != self.modelo]

            print(f"[开始录制] 开始录制模特 {self.modelo} 到文件 {os.path.basename(self.file)}")
            log_event(f'开始录制: {self.modelo} -> {self.file}')

            last_online_check = time.time()
            last_link_check = time.time()
            last_data_time = time.time()
            no_data_restarts = 0

            try:
                segment_duration_seconds = int(app_state.get("segment_duration", 30)) * 60
            except Exception:
                segment_duration_seconds = 30 * 60

            while not self._stopevent.is_set():
                current_time = time.time()

                # 降低 fstat 调用频率（每圈读写一次会很耗CPU）
                if current_time - last_link_check >= FILE_LINK_CHECK_INTERVAL_SECONDS:
                    try:
                        if os.fstat(current_file.fileno()).st_nlink == 0:
                            break
                    except OSError:
                        break
                    last_link_check = current_time

                # 每 N 秒检查一次在线状态（并顺带刷新分段配置）
                if current_time - last_online_check >= ONLINE_CHECK_INTERVAL_SECONDS:
                    if not self.isOnline():
                        print(f"[检测] 模特 {self.modelo} 已经下线，停止录制")
                        log_event(f'模特已下线，停止录制: {self.modelo}')
                        break
                    last_online_check = current_time
                    try:
                        segment_duration_seconds = int(app_state.get("segment_duration", 30)) * 60
                    except Exception:
                        segment_duration_seconds = 30 * 60

                # 分段
                if segment_duration_seconds and (current_time - self.segment_start_time >= segment_duration_seconds):
                    current_file.close()
                    completed_file = self.file
                    self._handle_completed_file(completed_file, use_postprocess=False, label='分段')

                    self.segment_start_time = current_time
                    self.create_new_file()
                    current_file = open(self.file, 'wb', buffering=1024 * 1024)
                    print(f"[分段录制] 创建新录制文件 {os.path.basename(self.file)} 用于模特 {self.modelo}")
                    log_event(f'创建新录制片段: {self.file}')

                # 读流（提高 chunk，显著降低CPU占用）
                # HLS 流可能暂时没有新数据（等待下一个 segment），尝试几次快速重读
                data = None
                for read_attempt in range(3):
                    try:
                        data = fd.read(STREAM_READ_SIZE)
                    except Exception as e:
                        # 读取异常可能是流断开，记录并退出读取循环
                        log_event(f'读取流数据异常: {self.modelo} - {e}')
                        break
                    if data:
                        break
                    time.sleep(0.3)  # 短暂等待后重试

                if not data:
                    # 没数据先等一会儿；超时则尝试重连，避免一直写空文件
                    if current_time - last_data_time >= NO_DATA_TIMEOUT_SECONDS:
                        no_data_restarts += 1
                        log_event(
                            f'长时间无数据，尝试重连({no_data_restarts}/{MAX_NO_DATA_RESTARTS}): {self.modelo}'
                        )

                        if not self.isOnline():
                            print(f"[检测] 模特 {self.modelo} 已经下线，停止录制")
                            log_event(f'模特已下线，停止录制: {self.modelo}')
                            break

                        stream_name = self.stream_name or stream_name

                        try:
                            if fd:
                                fd.close()
                        except Exception:
                            pass

                        try:
                            if sl_session:
                                sl_session = None
                        except Exception:
                            pass

                        sl_session, fd, first_data, _ = self._open_streamlink_fd(stream_name)
                        if fd is None or not first_data:
                            if no_data_restarts >= MAX_NO_DATA_RESTARTS:
                                log_event(f'重连失败次数过多，停止录制: {self.modelo}')
                                break
                            last_data_time = current_time
                            time.sleep(1)
                            continue

                        current_file.write(first_data)
                        last_data_time = time.time()
                        continue

                    time.sleep(0.5)
                    continue

                current_file.write(data)
                last_data_time = current_time
                no_data_restarts = 0

        except streamlink.exceptions.NoPluginError:
            log_event(f'Streamlink 无法找到插件处理 URL: {self.modelo}')
            self.online = False
        except streamlink.exceptions.PluginError as e:
            log_event(f'Streamlink 插件错误: {self.modelo} - {e}')
            self.online = False
        except Exception as e:
            log_event(f'录制线程启动/运行异常: {self.modelo} - {type(e).__name__}: {e}')
            self.online = False
        finally:
            # 关闭资源
            try:
                if current_file and not current_file.closed:
                    current_file.close()
            except Exception:
                pass
            try:
                if fd:
                    fd.close()
            except Exception:
                pass
            try:
                if sl_session:
                    sl_session = None
            except Exception:
                pass
            try:
                self.http.close()
            except Exception:
                pass

            # 处理最后一个文件
            if started_recording and self.file:
                print(f"[停止录制] 停止录制模特 {self.modelo}, 文件: {os.path.basename(self.file)}")
                log_event(f'停止录制: {self.modelo}, 文件: {self.file}')
                self._handle_completed_file(self.file, use_postprocess=True, label='最终')

            # 确保从 recording 列表中移除
            with state_lock:
                if self in recording:
                    recording.remove(self)
            self.online = False

    def _handle_completed_file(self, file_path, use_postprocess: bool, label: str = ''):
        """分段/结束时处理文件：过小删除，否则 move 或入队 postProcess。"""
        if not file_path or not os.path.isfile(file_path):
            return

        try:
            size = os.path.getsize(file_path)
        except OSError:
            return

        if size <= MIN_FILE_SIZE_BYTES:
            try:
                os.remove(file_path)
                log_event(f'删除过小{label}文件: {file_path}')
            except OSError as e:
                log_event(f'删除过小{label}文件失败: {e}')
            return

        post_cmd = (setting.get('postProcessingCommand') or '').strip()
        if use_postprocess and post_cmd and processingQueue is not None:
            log_event(f'[队列] 准备将文件加入后处理队列: {file_path}')
            try:
                processingQueue.put({'model': self.modelo, 'path': file_path})
                log_event(f'[队列] 文件已加入后处理队列: {file_path}')
            except Exception as e:
                log_event(f'[错误][队列] 加入后处理队列失败，改为移动文件: {file_path} - {e}')
                self.move_file_to_up(file_path)
            return

        # 未配置后处理命令（或不使用后处理）：直接 move
        self.move_file_to_up(file_path)

    def create_new_file(self):
        """创建新的录制文件路径"""
        self.file = os.path.join(setting['save_directory'], self.modelo,
                                f'{datetime.datetime.fromtimestamp(time.time()).strftime("%Y.%m.%d_%H.%M.%S")}_{self.modelo}.mp4')
    
    def move_file_to_up(self, file_path):
        """将文件移动到up文件夹"""
        try:
            up_dir = setting.get('up_directory')
            if not up_dir:
                return
            filename = os.path.basename(file_path)
            model_up_dir = os.path.join(up_dir, self.modelo)
            dest_path = os.path.join(model_up_dir, filename)

            # 确保目标目录存在 (关键修改)
            os.makedirs(model_up_dir, exist_ok=True)

            shutil.move(file_path, dest_path)
            print(f"[文件移动] {filename} 已移动到上传文件夹: {model_up_dir}")
            log_event(f'文件已移动到上传文件夹: {dest_path}')
        except Exception as e:
            log_event(f'移动文件到上传文件夹时出错: {e}')

    def exceptionHandler(self):
        """兼容旧逻辑：标记停止并清理全局状态。"""
        self.stop()
        self.online = False
        with state_lock:
            if self in recording:
                recording.remove(self)
            hilos[:] = [t for t in hilos if t is not self]

    def isOnline(self):
        try:
            self._refresh_proxy()
            url = f'https://stripchat.com/api/front/v2/models/username/{self.modelo}/cam'
            resp = self.http.get(url, timeout=10)
            resp.raise_for_status()
            data = resp.json()
            
            # 检查响应类型
            if isinstance(data, list):
                # 如果返回的是列表，说明可能是错误响应
                log_event(f'API返回列表而不是预期的字典: {self.modelo}')
                return False
                
            hls_url = ''
            if 'cam' in data.keys():
                if {'isCamAvailable', 'streamName'} <= data['cam'].keys():
                    if data['cam']['isCamAvailable'] and data['cam']['streamName']:
                        # 尝试获取 viewServers 中的 HLS 地址
                        if 'viewServers' in data['cam'] and 'flashphoner-hls' in data['cam']['viewServers']:
                           hls_url = f'https://{data["cam"]["viewServers"]["flashphoner-hls"]}/hls/{data["cam"]["streamName"]}/playlist.m3u8'
                        elif 'hlsUrl' in data['cam']: # 备选方案: 直接使用 hlsUrl
                           hls_url = data['cam']['hlsUrl']
                        else: 
                           # 新备选: edge-hls / master playlist (verified 2024-12)
                           hls_url = f'https://edge-hls.doppiocdn.live/hls/{data["cam"]["streamName"]}/master/{data["cam"]["streamName"]}_auto.m3u8'
                           
                           # 如果没有 viewServers 和 hlsUrl，说明是 WebRTC 或受保护流。
                           # 返回 Profile URL 让 Streamlink 插件尝试处理 (需配合正确 Headers)
                           if not hls_url: # Should not happen if we use edge-hls fallback
                               log_event(f'无 HLS 地址，尝试使用 Profile URL: {self.modelo}')
                               return f'https://stripchat.com/{self.modelo}'

            if len(hls_url):
                # 验证URL是否有效 (带 Cookies)
                try:
                    # 使用 Session (含 Cookies) 发送 HEAD 请求
                    with self.http.head(hls_url, timeout=5, allow_redirects=True) as r:
                         if r.status_code >= 400:
                             log_event(f'HLS URL无效 (Status {r.status_code}): {self.modelo} - {hls_url}')
                             # 如果无效，以前是回退到 Profile URL，但现在 Profile URL 也不行 (NoPlugin)
                             # 只有当 Streamlink 有 stripchat 插件时才回退到 Profile。
                             # 现在我们相信 cookies 能解决 403，所以这里的 403 可能是 cookies 失效。
                             # 但如果用户提供了 cookies，我们应该尝试用 cookies 去录制 HLS。
                             # 可是如果 HEAD 都 403，streamlink 可能也会 403。
                             # 无论如何，返回 HLS URL 让 Streamlink 试一把（它也会带 cookies）。
                             pass # 忽略 403，让 run() 里的 streamlink 带 cookie 再试一次
                             
                except Exception as e:
                    log_event(f'验证HLS URL失败: {self.modelo} - {e}')
                    # 网络错误可能导致误判，保守返回 URL
                
                return hls_url
            else:
                return False

            stream_name = cam.get('streamName')
            is_available = bool(cam.get('isCamAvailable'))
            if not is_available or not stream_name:
                return False

            self.stream_name = str(stream_name)

            # 根据 broadcastSettings.presets 生成 suffix 优先级（高->低）
            try:
                suffixes = ['']  # source（无 suffix）放最前，能用则优先
                broadcast = cam.get('broadcastSettings') if isinstance(cam, dict) else None
                presets = (broadcast or {}).get('presets') if isinstance(broadcast, dict) else None
                default_presets = (presets or {}).get('default') if isinstance(presets, dict) else None
                for p in (default_presets or []):
                    if not p:
                        continue
                    s = str(p).strip()
                    if not s:
                        continue
                    if not s.startswith('_'):
                        s = f'_{s}'
                    if s not in suffixes:
                        suffixes.append(s)
                self._hls_suffixes = suffixes or ['']
            except Exception:
                self._hls_suffixes = ['']

            # 新版 HLS master URL（edge-hls.* + /hls/{streamName}/master/{streamName}.m3u8）
            # 直接返回一个默认可用的 host；如失败，run() 会自动轮询其它 host。
            if not self._hls_cdn_host:
                self._hls_cdn_host = "doppiocdn.live"
            return HLS_MASTER_URL_TEMPLATE.format(cdn_host=self._hls_cdn_host, stream_name=self.stream_name, suffix='')
        except requests.exceptions.RequestException as e: # 更具体的异常捕获
             log_event(f'网络请求错误 (isOnline): {self.modelo} - {e}')
             return False
        except Exception as e:
             log_event(f'检查在线状态时出错 (isOnline): {self.modelo} - {e}')
             return False

    def stop(self):
        self._stopevent.set()


class CleaningThread(threading.Thread):
    def __init__(self):
        super().__init__()
        self.interval = 0

    def run(self):
        global hilos, recording
        while True:
            with state_lock:
                hilos[:] = [hilo for hilo in hilos if hilo.is_alive() or hilo.online]
            for i in range(10, 0, -1):
                self.interval = i
                time.sleep(1)


class AddModelsThread(threading.Thread):
    def __init__(self):
        super().__init__()
        self.wanted = []
        self.repeatedModels = []
        self.counterModel = 0

    def run(self):
        global hilos, recording, app_state
        wishlist_path = setting.get('wishlist')
        if not wishlist_path:
            return

        try:
            with open(wishlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.read().splitlines()
        except Exception as e:
            log_event(f'读取 wanted 列表失败: {wishlist_path} - {e}')
            return

        raw_models = [line.strip() for line in lines if line.strip()]

        seen = set()
        unique_models = []
        repeated = []
        for name in raw_models:
            model = name.lower()
            if model in seen:
                repeated.append(model)
            else:
                seen.add(model)
                unique_models.append(model)

        self.wanted = unique_models
        self.repeatedModels = repeated
        self.counterModel = len(unique_models)

        # 需要启动的线程与需要停止的录制线程（避免持锁时 start/stop）
        threads_to_start = []
        threads_to_stop = []

        with state_lock:
            active_models = {t.modelo for t in hilos} | {t.modelo for t in recording}
            for model in unique_models:
                if model not in active_models:
                    thread = Modelo(model)
                    hilos.append(thread)  # 先 append 再 start，避免竞态导致同时出现在 hilos/recording
                    threads_to_start.append(thread)
                    active_models.add(model)

            for hilo in recording:
                if hilo.modelo not in seen:
                    threads_to_stop.append(hilo)

            # 更新应用状态
            app_state["repeatedModels"] = self.repeatedModels
            app_state["counterModel"] = self.counterModel

        for thread in threads_to_start:
            thread.start()
        for thread in threads_to_stop:
            thread.stop()


if __name__ == '__main__':
    firstRun()
    readConfig()
    
    # 处理已有的captures文件
    process_existing_captures()
    
    if setting['postProcessingCommand']:
        processingQueue = queue.Queue()
        postprocessingWorkers = []
        for i in range(0, setting['postProcessingThreads']):
            t = threading.Thread(target=postProcess)
            postprocessingWorkers.append(t)
            t.start()
    cleaningThread = CleaningThread()
    cleaningThread.start()
    
    # 启动web服务器
    print("[Web服务] 正在后台启动Web界面...")
    web_thread = threading.Thread(target=start_web_server)
    web_thread.daemon = True  # 设置为守护线程，这样主程序退出时，web服务器也会退出
    web_thread.start()
    
    while True:
        try:
            readConfig()
            addModelsThread = AddModelsThread()
            addModelsThread.start()
            i = 1
            for i in range(setting['interval'], 0, -1):
                cls()
                # 显示Web状态信息
                with state_lock:
                    web_status = app_state.get('web_status', '')
                    hilos_len = len(hilos)
                    recording_snapshot = list(recording)
                print(f"[Web服务状态] {web_status}")
                print("=" * 50)
                
                if len(addModelsThread.repeatedModels): print(
                    'The following models are more than once in wanted: [\'' + ', '.join(
                        modelo for modelo in addModelsThread.repeatedModels) + '\']')
                print(
                    f'{hilos_len:02d} alive Threads (1 Thread per non-recording model), cleaning dead/not-online Threads in {cleaningThread.interval:02d} seconds, {addModelsThread.counterModel:02d} models in wanted')
                print(f'Online Threads (models): {len(recording_snapshot):02d}')
                print('The following models are being recorded:')
                for hiloModelo in recording_snapshot: print(
                    f'  Model: {hiloModelo.modelo}  -->  File: {os.path.basename(hiloModelo.file)}')
                print(f'Next check in {i:02d} seconds\r', end='')
                time.sleep(1)
            addModelsThread.join()
            del addModelsThread, i
        except:
            break

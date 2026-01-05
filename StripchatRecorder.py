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
import signal

# 全局停止事件
stop_requested = threading.Event()

def signal_handler(signum, frame):
    """处理退出信号"""
    print(f"\n[退出] 收到信号 {signum}，正在通知所有线程退出...")
    stop_requested.set()

# 注册信号处理程序
signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)
from urllib.parse import urljoin
from typing import Optional
import hashlib
import base64
import re
from urllib.parse import urljoin
from typing import Optional
from flask import Flask, render_template, request, redirect, url_for, jsonify

if os.name == 'nt':
    import ctypes

    kernel32 = ctypes.windll.kernel32
    kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)

mainDir = os.path.abspath(sys.path[0])
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
    "segment_duration": 30,  # 分段录制时长，默认30分钟
    "segment_duration_overridden": False,  # Web 运行时覆盖，避免被 readConfig 周期性重置
    "model_status": {}, # 模特状态缓存
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
def get_file_size_str(file_path):
    try:
        if not file_path or not os.path.exists(file_path):
            return "0B"
        size = os.path.getsize(file_path)
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} TB"
    except:
        return "0B"

def get_system_status_data():
    # 更新存储空间信息
    storage = get_storage_info()
    with state_lock:
        app_state["storage_info"] = storage
        # basic info
        repeated_models = list(app_state.get("repeatedModels", []))
        counter_model = int(app_state.get("counterModel", 0))
        port = int(app_state.get("port", 8080))
        web_status = str(app_state.get("web_status", ""))
        segment_duration = int(app_state.get("segment_duration", 30))
        storage_info = dict(app_state.get("storage_info", {}))
        
        # hilos/recording snapshots
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
            "elapsed_time": elapsed_formatted,
            "size": get_file_size_str(model.file) if model.file else "0B"
        })

    return {
        "port": port,
        "web_status": web_status,
        "storage_info": storage_info,
        "repeatedModels": repeated_models,
        "hilos_count": len(hilos_snapshot),
        "recording_info": recording_info,
        "counterModel": counter_model,
        "segment_duration": segment_duration,
        "up_directory": setting.get('up_directory', '未配置'),
        "model_status": dict(app_state.get("model_status", {})),
    }

@app.route('/api/status')
def api_status():
    """返回JSON格式的系统状态"""
    return jsonify(get_system_status_data())

@app.route('/')
def index():
    """主页，显示当前状态"""
    data = get_system_status_data()
    return render_template('index.html', **data)

@app.route('/edit_wanted', methods=['GET'])
def edit_wanted():
    """查看和编辑wanted.txt文件"""
    return render_template('edit_wanted.html')

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

@app.route('/api/wanted', methods=['GET'])
def get_wanted():
    """获取wanted列表"""
    try:
        if not os.path.exists(setting['wishlist']):
             return jsonify({'wanted': []})
        with open(setting['wishlist'], 'r', encoding='utf-8') as f:
            wanted = [line.strip() for line in f if line.strip()]
        return jsonify({'wanted': wanted})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/wanted', methods=['POST'])
def add_wanted():
    """添加模特到wanted列表"""
    data = request.json
    if not data or 'model' not in data:
        return jsonify({'error': 'Invalid data'}), 400
    
    new_model = data['model'].strip().lower()
    if not new_model:
        return jsonify({'error': 'Empty model name'}), 400
        
    try:
        current_wanted = []
        if os.path.exists(setting['wishlist']):
            with open(setting['wishlist'], 'r', encoding='utf-8') as f:
                current_wanted = [line.strip() for line in f if line.strip()]
        
        if new_model in [m.lower() for m in current_wanted]:
            return jsonify({'error': 'Model already exists'}), 409
            
        current_wanted.append(new_model)
        atomic_write_text(setting['wishlist'], '\n'.join(current_wanted))
        log_event(f'API添加模特: {new_model}')
        return jsonify({'success': True, 'model': new_model})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/wanted', methods=['DELETE'])
def delete_wanted():
    """从wanted列表删除模特"""
    data = request.json
    if not data or 'model' not in data:
        return jsonify({'error': 'Invalid data'}), 400
        
    target = data['model'].strip().lower()
    
    try:
        if not os.path.exists(setting['wishlist']):
            return jsonify({'error': 'List empty'}), 404
            
        with open(setting['wishlist'], 'r', encoding='utf-8') as f:
            current_wanted = [line.strip() for line in f if line.strip()]
        
        original_len = len(current_wanted)
        new_wanted = [m for m in current_wanted if m.lower() != target]
        
        if len(new_wanted) < original_len:
            atomic_write_text(setting['wishlist'], '\n'.join(new_wanted))
            log_event(f'API删除模特: {target}')
            return jsonify({'success': True})
        else:
            return jsonify({'error': 'Model not found'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500

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
            
            port += 1
            if port > max_port:
                final_error_msg = f"[Web服务] 无法找到可用端口（{8080}-{max_port}），Web界面未启动"
                print(final_error_msg)
                with state_lock:
                    app_state["web_status"] = final_error_msg
                with state_lock:
                    app_state["web_status"] = final_error_msg
                
                # 记录到日志文件
                log_event(final_error_msg)
                log_event(final_error_msg)
                break

def create_templates():
    """创建HTML模板"""
    index_html = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>StripchatRecorder 控制台</title>
    <!-- Google Fonts -->
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --primary: #6366f1;
            --primary-hover: #4f46e5;
            --bg-dark: #0f172a;
            --card-bg: rgba(30, 41, 59, 0.7);
            --text-main: #f8fafc;
            --text-sub: #94a3b8;
            --success: #10b981;
            --warning: #f59e0b;
            --danger: #ef4444;
            --border: rgba(148, 163, 184, 0.1);
        }
        
        body {
            font-family: 'Inter', sans-serif;
            background-color: var(--bg-dark);
            background-image: 
                radial-gradient(at 0% 0%, rgba(99, 102, 241, 0.15) 0px, transparent 50%),
                radial-gradient(at 100% 0%, rgba(16, 185, 129, 0.15) 0px, transparent 50%);
            color: var(--text-main);
            margin: 0;
            padding: 20px;
            min-height: 100vh;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 24px;
        }

        .full-width {
            grid-column: 1 / -1;
        }

        .card {
            background: var(--card-bg);
            backdrop-filter: blur(12px);
            -webkit-backdrop-filter: blur(12px);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 24px;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
            transition: transform 0.2s ease;
        }
        
        .card:hover {
            transform: translateY(-2px);
        }

        h2 {
            margin-top: 0;
            font-size: 1.25rem;
            font-weight: 600;
            color: var(--text-main);
            border-bottom: 1px solid var(--border);
            padding-bottom: 16px;
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .stat-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 12px;
            font-size: 0.95rem;
        }

        .stat-label {
            color: var(--text-sub);
        }

        .stat-value {
            font-weight: 600;
            color: var(--text-main);
        }
        
        code {
            background: rgba(0,0,0,0.3);
            padding: 2px 6px;
            border-radius: 4px;
            font-family: 'Menlo', monospace;
            font-size: 0.9em;
            color: #e2e8f0;
        }

        /* Buttons */
        .btn {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            padding: 8px 16px;
            border-radius: 8px;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.2s;
            border: none;
            text-decoration: none;
            font-size: 0.9rem;
        }

        .btn-primary {
            background: var(--primary);
            color: white;
        }
        .btn-primary:hover { background: var(--primary-hover); }

        .btn-danger {
            background: rgba(239, 68, 68, 0.1);
            color: var(--danger);
            border: 1px solid rgba(239, 68, 68, 0.2);
        }
        .btn-danger:hover {
            background: rgba(239, 68, 68, 0.2);
        }

        /* Forms */
        input[type="number"] {
            background: rgba(0,0,0,0.2);
            border: 1px solid var(--border);
            color: white;
            padding: 8px 12px;
            border-radius: 6px;
            width: 80px;
        }
        
        input[type="number"]:focus {
            outline: none;
            border-color: var(--primary);
        }

        /* Progress Bar */
        .progress-bg {
            background: rgba(255,255,255,0.1);
            height: 8px;
            border-radius: 4px;
            overflow: hidden;
            margin-top: 8px;
        }
        
        .progress-fill {
            height: 100%;
            background: var(--success);
            transition: width 0.3s ease;
        }
        
        .progress-fill.warning { background: var(--warning); }
        .progress-fill.danger { background: var(--danger); }

        /* Table */
        .table-container {
            overflow-x: auto;
        }
        
        table {
            width: 100%;
            border-collapse: separate;
            border-spacing: 0;
        }
        
        th {
            text-align: left;
            color: var(--text-sub);
            padding: 12px 16px;
            font-weight: 500;
            border-bottom: 1px solid var(--border);
        }
        
        td {
            padding: 16px;
            border-bottom: 1px solid var(--border);
            color: var(--text-main);
        }
        
        tr:last-child td { border-bottom: none; }
        
        .status-badge {
            display: inline-flex;
            align-items: center;
            padding: 4px 8px;
            border-radius: 12px;
            font-size: 0.75rem;
            font-weight: 600;
            background: rgba(16, 185, 129, 0.1);
            color: var(--success);
            max-width: 200px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }
        
        .status-dot {
            width: 6px;
            height: 6px;
            border-radius: 50%;
            background: currentColor;
            margin-right: 6px;
            animation: pulse 2s infinite;
        }

        @keyframes pulse {
            0% { opacity: 1; }
            50% { opacity: 0.5; }
            100% { opacity: 1; }
        }
        
        .empty-state {
            text-align: center;
            padding: 40px;
            color: var(--text-sub);
        }

        /* Header Styles */
        .header-card { overflow: hidden; }
        .header-content {
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 12px;
        }
        .header-title {
            margin: 0;
            font-size: 1.5rem;
            background: linear-gradient(to right, #818cf8, #34d399);
            -webkit-background-clip: text;
            background-clip: text;
            -webkit-text-fill-color: transparent;
            flex-shrink: 0;
        }
        .header-meta {
            display: flex;
            align-items: center;
            gap: 12px;
            flex-wrap: wrap;
        }
        .header-clock {
            color: var(--text-sub);
            font-family: 'Menlo', monospace;
            font-size: 0.9rem;
            flex-shrink: 0;
        }

        /* Mobile Responsive */
        @media (max-width: 768px) {
            body { padding: 12px; }
            .header-content { flex-direction: column; align-items: flex-start; }
            .header-meta { width: 100%; justify-content: space-between; }
            .status-badge { max-width: 60%; }
            .container { grid-template-columns: 1fr; gap: 16px; }
            #recording-table thead { display: none; }
            #recording-table tbody { display: block; }
            #recording-table tbody tr {
                display: block;
                background: rgba(0,0,0,0.2);
                border-radius: 12px;
                padding: 16px;
                margin-bottom: 12px;
                border: 1px solid var(--border);
            }
            #recording-table td {
                display: flex;
                justify-content: space-between;
                align-items: center;
                padding: 8px 0;
                border-bottom: 1px solid var(--border);
            }
            #recording-table td:last-child { border-bottom: none; }
            #recording-table td::before {
                content: attr(data-label);
                font-weight: 500;
                color: var(--text-sub);
                flex-shrink: 0;
                margin-right: 12px;
            }
            h2 { font-size: 1.1rem; }
            .card { padding: 16px; }
            .stat-item { font-size: 0.9rem; }
            .segment-form { flex-direction: column !important; align-items: stretch !important; }
            .segment-form input[type="number"] { width: 100% !important; box-sizing: border-box; }
            .segment-form .btn { width: 100%; }
        }
        @media (max-width: 480px) {
            body { padding: 8px; }
            .header-title { font-size: 1.2rem !important; }
            .card { padding: 12px; }
        }

        /* Grid */
        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
            gap: 20px;
        }

    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <div class="card full-width header-card">
            <div class="header-content">
                <h1 class="header-title">StripchatRecorder Monitor</h1>
                <div class="header-meta">
                    <span id="web-status-badge" class="status-badge" title="Running">
                        <span class="status-dot"></span>
                        <span id="web-status-text">Running</span>
                    </span>
                    <span id="clock" class="header-clock">--:--:--</span>
                </div>
            </div>
        </div>

        <!-- Overview -->
        <div class="card">
            <h2>运行概览</h2>
            <div class="stat-item">
                <span class="stat-label">Web 端口</span>
                <span class="stat-value" id="port">{{ port }}</span>
            </div>
            <div class="stat-item">
                <span class="stat-label">上传目录</span>
                <code id="up-dir">{{ up_directory }}</code>
            </div>
            <div class="stat-item">
                <span class="stat-label">重复模特</span>
                <span class="stat-value" id="repeated-models" style="color: var(--warning)">-</span>
            </div>
        </div>

        <!-- Stats -->
        <div class="card">
            <h2>统计数据</h2>
            <div class="stat-item">
                <span class="stat-label">活跃检测线程</span>
                <span class="stat-value" id="hilos-count">-</span>
            </div>
            <div class="stat-item">
                <span class="stat-label">正在录制</span>
                <span class="stat-value" id="recording-count">-</span>
            </div>
            <div class="stat-item">
                <span class="stat-label">Wanted 列表</span>
                <span class="stat-value" id="wanted-count">-</span>
            </div>
            <a href="/edit_wanted" class="btn btn-primary" style="width: 100%; margin-top: 10px; box-sizing: border-box;">编辑 Wanted 列表</a>
        </div>

        <!-- Storage -->
        <div class="card">
            <h2>本地存储</h2>
            <div class="stat-item">
                <span class="stat-label">已使用 / 总容量</span>
                <span class="stat-value"><span id="storage-used">-</span> / <span id="storage-total">-</span> GB</span>
            </div>
            <div class="stat-item">
                <span class="stat-label">剩余空间</span>
                <span class="stat-value" id="storage-free">-</span> GB
            </div>
            <div style="margin-top: 10px;">
                <div style="display: flex; justify-content: space-between; font-size: 0.8rem; margin-bottom: 4px;">
                    <span class="stat-label">使用率</span>
                    <span class="stat-value" id="storage-percent">-</span>
                </div>
                <div class="progress-bg">
                    <div id="storage-bar" class="progress-fill" style="width: 0%"></div>
                </div>
            </div>
        </div>
        
        <!-- Monitor Status List -->
        <div class="card full-width">
             <h2>监控状态 (<span id="monitor-count">Live Status</span>)</h2>
             <div id="monitor-list">
                 <div style="text-align:center; padding:20px; color:var(--text-sub);">加载中...</div>
             </div>
        </div>

        <!-- Settings -->
        <div class="card">
            <h2>分段录制设置</h2>
            <form action="/set_segment_duration" method="post" class="segment-form" style="display: flex; gap: 10px; align-items: center;">
                <label for="duration" class="stat-label">时长(分钟):</label>
                <input type="number" id="duration" name="duration" value="{{ segment_duration }}" min="1" required>
                <button type="submit" class="btn btn-primary">保存</button>
            </form>
            <p style="margin-top: 12px; font-size: 0.85rem; color: var(--text-sub);">
                当前: 每 <strong id="current-segment" style="color: var(--text-main)">{{ segment_duration }}</strong> 分钟自动分段。
            </p>
        </div>

        <!-- Recording List -->
        <div class="card full-width">
            <h2>正在录制 (<span id="list-count">0</span>)</h2>
            <div class="table-container">
                <table id="recording-table">
                    <thead>
                        <tr>
                            <th>模特名</th>
                            <th>文件名</th>
                            <th>大小</th>
                            <th>已录制时长</th>
                            <th>操作</th>
                        </tr>
                    </thead>
                    <tbody id="recording-tbody">
                        <!-- Content injected by JS -->
                    </tbody>
                </table>
                <div id="empty-state" class="empty-state" style="display: none;">
                    当前没有模特正在录制
                </div>
            </div>
        </div>
    </div>

    <script>
        function updateClock() {
            const now = new Date();
            document.getElementById('clock').innerText = now.toLocaleTimeString();
        }
        setInterval(updateClock, 1000);
        updateClock();

        function formatBytes(bytes, decimals = 2) {
            if (bytes === 0) return '0 Bytes';
            const k = 1024;
            const dm = decimals < 0 ? 0 : decimals;
            const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
        }

        async function fetchStatus() {
            try {
                const response = await fetch('/api/status');
                const data = await response.json();
                
                // Update basic stats
                document.getElementById('web-status-text').innerText = data.web_status || 'Running';
                document.getElementById('port').innerText = data.port;
                document.getElementById('up-dir').innerText = data.up_directory;
                
                const repeated = data.repeatedModels.length > 0 ? data.repeatedModels.join(', ') : '无';
                document.getElementById('repeated-models').innerText = repeated;
                
                document.getElementById('hilos-count').innerText = data.hilos_count;
                document.getElementById('recording-count').innerText = data.recording_info.length;
                document.getElementById('list-count').innerText = data.recording_info.length;
                document.getElementById('wanted-count').innerText = data.counterModel;
                
                // Update storage
                const s = data.storage_info.local;
                if (s) {
                    document.getElementById('storage-used').innerText = s.used;
                    document.getElementById('storage-total').innerText = s.total;
                    document.getElementById('storage-free').innerText = s.free;
                    document.getElementById('storage-percent').innerText = s.percent_used + '%';
                    
                    const bar = document.getElementById('storage-bar');
                    bar.style.width = s.percent_used + '%';
                    bar.className = 'progress-fill';
                    if (s.percent_used > 90) bar.classList.add('danger');
                    else if (s.percent_used > 70) bar.classList.add('warning');
                }

                // Update settings text
                document.getElementById('current-segment').innerText = data.segment_duration;

                // Update table
                const tbody = document.getElementById('recording-tbody');
                const emptyState = document.getElementById('empty-state');
                const table = document.getElementById('recording-table');

                if (data.recording_info.length === 0) {
                    table.style.display = 'none';
                    emptyState.style.display = 'block';
                } else {
                    table.style.display = 'table';
                    emptyState.style.display = 'none';
                    
                    // Rebuild table rows
                    let html = '';
                    data.recording_info.forEach(model => {
                        html += `
                            <tr>
                                <td>
                                    <div style="font-weight: 500;">${model.name}</div>
                                </td>
                                <td style="color: var(--text-sub); font-size: 0.9em;">
                                    ${model.file}
                                </td>
                                <td><span style="font-family: monospace;">${model.size}</span></td>
                                <td>
                                    <span class="status-badge">
                                        <span class="status-dot"></span>
                                        ${model.elapsed_time}
                                    </span>
                                </td>
                                <td>
                                    <form action="/stop_recording/${model.name}" method="post" onsubmit="return confirm('确定停止 ${model.name}?');">
                                        <button type="submit" class="btn btn-danger" style="padding: 4px 10px; font-size: 0.8rem;">停止</button>
                                    </form>
                                </td>
                            </tr>
                        `;
                    });
                    tbody.innerHTML = html;
                }
                
                // Update Monitor List (New Section)
                const monitorDiv = document.getElementById('monitor-list');
                const modelStatus = data.model_status || {};
                // Combine wanted list with status
                // We don't have the full wanted list in this API response, but repeatedModels + recording + hilos roughly covers active checks.
                // Better to fetch wanted list? No, let's use what we have in model_status which accumulates all checked models.
                
                if (monitorDiv) {
                    const statusKeys = Object.keys(modelStatus).sort();
                    if (statusKeys.length === 0) {
                        monitorDiv.innerHTML = '<div style="color:var(--text-sub); padding:10px;">暂无监控数据</div>';
                    } else {
                        let monHtml = '<div class="grid" style="grid-template-columns: repeat(auto-fill, minmax(180px, 1fr)); gap: 12px;">';
                        statusKeys.forEach(model => {
                            const st = modelStatus[model];
                            let badgeClass = 'status-badge'; // default green-ish
                            let colorStyle = '';
                            
                            if (st === 'public') {
                                colorStyle = 'background: rgba(16, 185, 129, 0.1); color: #10b981;';
                            } else if (st === 'private' || st === 'group') {
                                colorStyle = 'background: rgba(245, 158, 11, 0.1); color: #f59e0b;';
                            } else if (st === 'off' || st === 'offline') {
                                colorStyle = 'background: rgba(148, 163, 184, 0.1); color: #94a3b8;';
                            } else {
                                colorStyle = 'background: rgba(99, 102, 241, 0.1); color: #6366f1;';
                            }
                            
                            monHtml += `
                                <div style="background: rgba(255,255,255,0.05); padding: 10px; border-radius: 8px; font-size: 0.9rem; display: flex; justify-content: space-between; align-items: center;">
                                    <span style="font-weight: 500; overflow:hidden; text-overflow:ellipsis;">${model}</span>
                                    <span style="padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: 600; ${colorStyle}">
                                        ${st}
                                    </span>
                                </div>
                            `;
                        });
                        monHtml += '</div>';
                        monitorDiv.innerHTML = monHtml;
                    }
                }

            } catch (err) {
                console.error('Update failed', err);
            }
        }

        // Poll every 2 seconds
        setInterval(fetchStatus, 2000);
        fetchStatus(); // Initial load
    </script>
</body>
</html>"""

    edit_html = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>管理 Wanted 列表</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --primary: #6366f1;
            --primary-hover: #4f46e5;
            --bg-dark: #0f172a;
            --card-bg: rgba(30, 41, 59, 0.7);
            --text-main: #f8fafc;
            --text-sub: #94a3b8;
            --border: rgba(148, 163, 184, 0.1);
            --danger: #ef4444;
            --success: #10b981;
        }
        body {
            font-family: 'Inter', sans-serif;
            background-color: var(--bg-dark);
            color: var(--text-main);
            margin: 0;
            padding: 20px;
            min-height: 100vh;
        }
        .container {
            max-width: 1000px;
            margin: 0 auto;
        }
        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 30px;
        }
        .back-btn {
            color: var(--text-sub);
            text-decoration: none;
            display: flex;
            align-items: center;
            gap: 6px;
            font-size: 0.9rem;
            transition: color 0.2s;
        }
        .back-btn:hover { color: var(--text-main); }
        
        .add-card {
            background: var(--card-bg);
            backdrop-filter: blur(12px);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 20px;
            margin-bottom: 30px;
            display: flex;
            gap: 12px;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
        }
        
        input[type="text"] {
            flex: 1;
            background: rgba(0,0,0,0.2);
            border: 1px solid var(--border);
            color: white;
            padding: 12px 16px;
            border-radius: 8px;
            font-size: 1rem;
            transition: border-color 0.2s;
        }
        input[type="text"]:focus {
            outline: none;
            border-color: var(--primary);
        }
        
        .btn {
            padding: 12px 24px;
            border-radius: 8px;
            border: none;
            cursor: pointer;
            font-weight: 600;
            transition: all 0.2s;
            font-size: 0.95rem;
        }
        .btn-primary {
            background: var(--primary);
            color: white;
        }
        .btn-primary:hover { background: var(--primary-hover); transform: translateY(-1px); }
        .btn-primary:active { transform: translateY(0); }
        
        /* Grid Layout */
        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
            gap: 20px;
        }
        
        .model-card {
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 16px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            transition: transform 0.2s, border-color 0.2s;
            position: relative;
            overflow: hidden;
        }
        .model-card:hover {
            transform: translateY(-2px);
            border-color: rgba(99, 102, 241, 0.3);
        }
        
        .model-name {
            font-weight: 600;
            font-size: 1.05rem;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }
        
        .delete-btn {
            background: rgba(239, 68, 68, 0.1);
            color: var(--danger);
            border: none;
            width: 32px;
            height: 32px;
            border-radius: 6px;
            display: flex;
            align-items: center;
            justify-content: center;
            cursor: pointer;
            transition: all 0.2s;
        }
        .delete-btn:hover {
            background: var(--danger);
            color: white;
        }

        .toast {
            position: fixed;
            bottom: 20px;
            right: 20px;
            padding: 12px 24px;
            border-radius: 8px;
            color: white;
            font-weight: 500;
            opacity: 0;
            transform: translateY(20px);
            transition: all 0.3s;
            z-index: 100;
        }
        .toast.show { opacity: 1; transform: translateY(0); }
        .toast.success { background: var(--success); }
        .toast.error { background: var(--danger); }
        
        .loading {
            text-align: center;
            color: var(--text-sub);
            grid-column: 1 / -1;
            padding: 40px;
        }
        
        /* Add status indicator */
        .status-dot {
            width: 6px;
            height: 6px;
            border-radius: 50%;
            background: var(--text-sub);
            display: inline-block;
            margin-right: 6px;
        }
        .online .status-dot { background: var(--success); box-shadow: 0 0 8px var(--success); }

        /* Mobile Responsive */
        @media (max-width: 768px) {
            body { padding: 12px; }
            .header { flex-direction: column; align-items: flex-start !important; gap: 10px; }
            .add-card { flex-direction: column; }
            .add-card input[type="text"] { width: 100%; box-sizing: border-box; }
            .add-card .btn { width: 100%; }
            .grid { grid-template-columns: 1fr !important; gap: 12px; }
            .model-card { padding: 14px; }
            .model-name { font-size: 1rem; }
        }
        @media (max-width: 480px) {
            body { padding: 8px; }
            h1 { font-size: 1.3rem; }
            .add-card { padding: 16px; }
        }

    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <a href="/" class="back-btn">← 返回仪表盘</a>
                <h1 style="margin: 10px 0 0 0;">管理 Wanted 列表</h1>
            </div>
            <div style="color: var(--text-sub);">
                共 <span id="total-count" style="color: var(--text-main); font-weight: bold;">0</span> 个模特
            </div>
        </div>

        <div class="add-card">
            <input type="text" id="model-input" placeholder="输入模特名称 (例如: nana_wilson)" autocomplete="off">
            <button class="btn btn-primary" onclick="addModel()">+ 添加模特</button>
        </div>

        <div id="model-grid" class="grid">
            <div class="loading">加载列表...</div>
        </div>
    </div>

    <div id="toast" class="toast"></div>

    <script>
        // Store models locally to avoid rapid fetching
        let models = [];

        async function fetchModels() {
            try {
                const res = await fetch('/api/wanted');
                const data = await res.json();
                if (data.wanted) {
                    models = data.wanted;
                    render();
                }
            } catch (e) {
                showToast('加载列表失败', 'error');
            }
        }

        async function addModel() {
            const input = document.getElementById('model-input');
            const name = input.value.trim();
            if (!name) return;

            try {
                const res = await fetch('/api/wanted', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({model: name})
                });
                const data = await res.json();
                
                if (data.success) {
                    models.push(data.model);
                    render();
                    input.value = '';
                    showToast(`已添加: ${data.model}`, 'success');
                } else {
                    showToast(data.error || '添加失败', 'error');
                }
            } catch (e) {
                showToast('网络请求失败', 'error');
            }
        }

        async function deleteModel(name) {
            if (!confirm(`确定要移除 ${name} 吗?`)) return;

            try {
                const res = await fetch('/api/wanted', {
                    method: 'DELETE',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({model: name})
                });
                const data = await res.json();

                if (data.success) {
                    models = models.filter(m => m.toLowerCase() !== name.toLowerCase());
                    render();
                    showToast(`已移除: ${name}`, 'success');
                } else {
                    showToast(data.error || '删除失败', 'error');
                }
            } catch (e) {
                showToast('网络请求失败', 'error');
            }
        }

        function render() {
            const grid = document.getElementById('model-grid');
            document.getElementById('total-count').innerText = models.length;
            
            if (models.length === 0) {
                grid.innerHTML = '<div class="loading">列表为空</div>';
                return;
            }

            grid.innerHTML = models.map(name => `
                <div class="model-card">
                    <div style="display: flex; align-items: center;">
                        <span class="status-dot"></span>
                        <span class="model-name" title="${name}">${name}</span>
                    </div>
                    <button class="delete-btn" onclick="deleteModel('${name}')" title="移除">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M3 6h18M19 6v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6m3 0V4a2 2 0 012-2h4a2 2 0 012 2v2"></path>
                        </svg>
                    </button>
                </div>
            `).join('');
            
            // Add shortcut for Enter key
            document.getElementById('model-input').onkeypress = function(e) {
                if (e.key === 'Enter') addModel();
            };
        }

        function showToast(msg, type = 'success') {
            const toast = document.getElementById('toast');
            toast.className = `toast ${type} show`;
            toast.innerText = msg;
            setTimeout(() => {
                toast.classList.remove('show');
            }, 3000);
        }

        fetchModels();
    </script>
</body>
</html>"""


    # 写入模板文件（仅在不存在时创建，作为 fallback）
    templates_dir = os.path.join(mainDir, 'templates')
    os.makedirs(templates_dir, exist_ok=True)
    
    index_path = os.path.join(templates_dir, 'index.html')
    if not os.path.exists(index_path):
        with open(index_path, 'w', encoding='utf-8') as f:
            f.write(index_html)
    
    edit_path = os.path.join(templates_dir, 'edit_wanted.html')
    if not os.path.exists(edit_path):
        with open(edit_path, 'w', encoding='utf-8') as f:
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

    while not stop_requested.is_set():
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
            
            # 检查是否需要重写 URL (参考 CodersRepository 修复)
            # From: https://media-hls.doppiocdn.com/b-hls-25/189420462/189420462.m3u8
            # To:   https://b-hls-25.doppiocdn.live/hls/189420462/189420462.m3u8
            match = re.match(r'https://media-hls\.doppiocdn\.\w+/(b-hls-\d+)/(\d+)/(.+)', variant_url)
            if match:
                b_hls_server = match.group(1)  # e.g., b-hls-25
                stream_id = match.group(2)      # e.g., 189420462
                filename = match.group(3)       # e.g., 189420462.m3u8
                
                # 去除可能的查询参数
                if '?' in filename:
                    filename = filename.split('?')[0]
                    
                variant_url = f"https://{b_hls_server}.doppiocdn.live/hls/{stream_id}/{filename}"
                log_event(f'[MOUFLON] 重写变体 URL: {variant_url}')

            # 变体 URL 必须添加认证参数才能获取真实内容（否则返回广告）
            # 关键：使用 psch=v1（不是 v2）并添加 pdkey 参数
            auth_variant_url = f"{variant_url}?psch=v1&pkey={pkey}&pdkey={decrypt_key}"
            
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
                
                # Fetch variant playlist (带认证参数)
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
                
                # 检查是否是广告内容
                if 'MOUFLON-ADVERT' in playlist_content or '/cpa/' in playlist_content:
                    log_event(f'[MOUFLON] 收到广告内容，认证可能已失效: {self.modelo}')
                    time.sleep(2)
                    continue
                
                # Download init segment if not yet done
                if not init_downloaded:
                    init_match = re.search(r'#EXT-X-MAP:URI="([^"]+)"', playlist_content)
                    if init_match:
                        init_url = init_match.group(1)
                        try:
                            init_resp = self.http.get(init_url, timeout=15)
                            if init_resp.status_code == 200:
                                current_file.write(init_resp.content)
                                current_file.flush()  # 确保 init 段写入磁盘
                                init_downloaded = True
                                log_event(f'[MOUFLON] 下载 init 段成功: {len(init_resp.content)} bytes')
                        except Exception as e:
                            log_event(f'[MOUFLON] 下载 init 段失败: {e}')
                
                # 提取 #EXT-X-MOUFLON:FILE: 加密条目
                mouflon_files = get_mouflon_file_entries(playlist_content)
                
                base_url = variant_url.rsplit('/', 1)[0]
                segments_downloaded = 0
                
                if mouflon_files:
                    # 使用 MOUFLON:FILE 方式（需要解密文件名）
                    for encrypted in mouflon_files:
                        if encrypted in seen_segments:
                            continue
                        
                        # Decrypt to get real segment filename using pdkey
                        decrypted_filename = mouflon_decode(encrypted, decrypt_key)
                        if not decrypted_filename:
                            # 尝试再次解密（有时可能需要重试或 padding 不同）
                            log_event(f'[MOUFLON] 解密失败: {encrypted[:20]}...')
                            continue
                        
                        # 构造完整 URL
                        segment_url = f"{base_url}/{decrypted_filename}"
                        
                        try:
                            seg_resp = self.http.get(segment_url, timeout=15)
                            if seg_resp.status_code == 200:
                                current_file.write(seg_resp.content)
                                seen_segments.add(encrypted)
                                segments_downloaded += 1
                                # log_event(f'[MOUFLON] 分段下载成功: {decrypted_filename}')
                            else:
                                log_event(f'[MOUFLON] 分段下载失败: {seg_resp.status_code} - {decrypted_filename}')
                        except Exception as e:
                            log_event(f'[MOUFLON] 分段请求异常: {e}')
                else:
                    # 回退：使用普通 HLS 方式（提取 EXTINF 后的段 URL）
                    lines = playlist_content.splitlines()
                    for i, line in enumerate(lines):
                        if line.startswith('#EXTINF:') and i + 1 < len(lines):
                            seg_line = lines[i + 1].strip()
                            # 跳过 #EXT-X-MOUFLON:URI 行，取下一行
                            if seg_line.startswith('#EXT-X-MOUFLON:URI:'):
                                if i + 2 < len(lines):
                                    seg_line = lines[i + 2].strip()
                                else:
                                    continue
                            
                            if seg_line and not seg_line.startswith('#'):
                                if seg_line in seen_segments:
                                    continue
                                
                                # 处理相对/绝对 URL
                                if seg_line.startswith('http'):
                                    segment_url = seg_line
                                else:
                                    segment_url = f"{base_url}/{seg_line}"
                                
                                try:
                                    seg_resp = self.http.get(segment_url, timeout=15)
                                    if seg_resp.status_code == 200:
                                        current_file.write(seg_resp.content)
                                        seen_segments.add(seg_line)
                                        segments_downloaded += 1
                                    else:
                                        log_event(f'[HLS] 分段下载失败: {seg_resp.status_code}')
                                except Exception as e:
                                    log_event(f'[HLS] 分段请求异常: {e}')
                
                # 定期刷新文件到磁盘
                if segments_downloaded > 0:
                    current_file.flush()
                
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
            # cam 可能是空列表（离线时）或字典（在线时）
            if not isinstance(cam, dict):
                return None  # Not online, fallback
            
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
            # 尝试使用 MOUFLON 录制（需要静态密钥）
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

            # 选择最佳质量的流
            stream_quality = 'best'
            if stream_quality not in streams:
                available = list(streams.keys())
                if available:
                    stream_quality = available[-1]  # 通常最后一个是最高质量
                else:
                    log_event(f'Streamlink 无可用流: {self.modelo}')
                    self.online = False
                    return
            
            stream = streams[stream_quality]
            log_event(f'使用流质量 {stream_quality}: {self.modelo}')
            
            # 打开流
            try:
                fd = stream.open()
            except Exception as e:
                log_event(f'Streamlink 打开流失败: {self.modelo} - {e}')
                self.online = False
                return
            
            # 等待并读取第一段数据（确认流是有效的）
            first_data = None
            for attempt in range(5):
                try:
                    first_data = fd.read(STREAM_READ_SIZE)
                    if first_data:
                        break
                except Exception as e:
                    log_event(f'读取首段数据失败: {self.modelo} - {e}')
                time.sleep(0.5)
            
            if not first_data:
                log_event(f'Streamlink 无法读取数据: {self.modelo}')
                fd.close()
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

                        stream_name = self.stream_name

                        try:
                            if fd:
                                fd.close()
                        except Exception:
                            pass

                        # 重新获取流并打开
                        try:
                            hls_url = self.isOnline()
                            if not hls_url:
                                if no_data_restarts >= MAX_NO_DATA_RESTARTS:
                                    log_event(f'重连失败次数过多，停止录制: {self.modelo}')
                                    break
                                last_data_time = current_time
                                time.sleep(1)
                                continue
                            
                            new_session = streamlink.Streamlink()
                            new_session.set_option("http-headers", DEFAULT_HEADERS.copy())
                            
                            if 'stripchat.com' in hls_url:
                                new_streams = new_session.streams(hls_url)
                            else:
                                new_streams = new_session.streams(f'hlsvariant://{hls_url}')
                            
                            if new_streams and 'best' in new_streams:
                                new_stream = new_streams['best']
                                fd = new_stream.open()
                                first_data = fd.read(STREAM_READ_SIZE)
                                if first_data:
                                    current_file.write(first_data)
                                    last_data_time = time.time()
                                    log_event(f'重连成功: {self.modelo}')
                                    continue
                        except Exception as e:
                            log_event(f'重连异常: {self.modelo} - {e}')
                        
                        if no_data_restarts >= MAX_NO_DATA_RESTARTS:
                            log_event(f'重连失败次数过多，停止录制: {self.modelo}')
                            break
                        last_data_time = current_time
                        time.sleep(1)
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
            print(f"[文件移动] {filename} 已移动到上传文件夹: {model_up_dir}")
            log_event(f'文件已移动到上传文件夹: {dest_path}')
        except Exception as e:
            log_event(f'移动文件到上传文件夹时出错: {e}')
            log_event(f'移动文件到上传文件夹时出错: {e}')

    def exceptionHandler(self):
        """兼容旧逻辑：标记停止并清理全局状态。"""
        """兼容旧逻辑：标记停止并清理全局状态。"""
        self.stop()
        self.online = False
        with state_lock:
            if self in recording:
                recording.remove(self)
            hilos[:] = [t for t in hilos if t is not self]
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
                
            if not isinstance(data, dict) or 'cam' not in data:
                return False
                
            cam = data['cam']
            # cam 可能是空列表（离线时）或字典（在线时）
            if not isinstance(cam, dict):
                return False
            
            # 提取并更新房间状态
            status_val = 'unknown'
            try:
                # 尝试从 user.user.status 获取
                if 'user' in data and 'user' in data['user'] and 'status' in data['user']['user']:
                    status_val = data['user']['user']['status']
            except Exception:
                pass
            
            # 如果是 unknown，尝试推断 (例如: 有 cam 但 status unknown -> 可能是 public)
            # 但为了安全，只认 'public'
            
            # 更新全局状态
            with state_lock:
                if "model_status" not in app_state:
                    app_state["model_status"] = {}
                app_state["model_status"][self.modelo] = status_val
            
            # 强制过滤：必须是 public 才下载
            if status_val != 'public':
                # 即使 isCamAvailable 为 True，如果状态不是 public (例如 private, p2p, group)，也不下载
                # log_event(f'跳过非公开房间: {self.modelo} (Status: {status_val})')
                return False

            hls_url = ''
            if {'isCamAvailable', 'streamName'} <= cam.keys():
                if cam['isCamAvailable'] and cam['streamName']:
                    stream_name = cam['streamName']
                    self.stream_name = str(stream_name)
                    
                    # 尝试获取 viewServers 中的 HLS 地址
                    if 'viewServers' in cam and 'flashphoner-hls' in cam['viewServers']:
                        hls_url = f'https://{cam["viewServers"]["flashphoner-hls"]}/hls/{stream_name}/playlist.m3u8'
                    elif 'hlsUrl' in cam:  # 备选方案: 直接使用 hlsUrl
                        hls_url = cam['hlsUrl']
                    else: 
                        # 新备选: edge-hls / master playlist (verified 2024-12)
                        hls_url = f'https://edge-hls.doppiocdn.com/hls/{stream_name}/master/{stream_name}_auto.m3u8'

            if hls_url:
                # 验证URL是否有效 (带 Cookies)
                try:
                    # 使用 Session (含 Cookies) 发送 HEAD 请求
                    with self.http.head(hls_url, timeout=5, allow_redirects=True) as r:
                        if r.status_code >= 400:
                            log_event(f'HLS URL无效 (Status {r.status_code}): {self.modelo} - {hls_url}')
                            # 忽略 403，让 run() 里的 streamlink 带 cookie 再试一次
                            pass
                             
                except Exception as e:
                    log_event(f'验证HLS URL失败: {self.modelo} - {e}')
                    # 网络错误可能导致误判，保守返回 URL
                
                return hls_url
            else:
                return False
        except requests.exceptions.RequestException as e: # 更具体的异常捕获
             log_event(f'网络请求错误 (isOnline): {self.modelo} - {e}')
             log_event(f'网络请求错误 (isOnline): {self.modelo} - {e}')
             return False
        except Exception as e:
             log_event(f'检查在线状态时出错 (isOnline): {self.modelo} - {e}')
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
        while not stop_requested.is_set():
            with state_lock:
                hilos[:] = [hilo for hilo in hilos if hilo.is_alive() or hilo.online]
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
    
    while not stop_requested.is_set():
        try:
            readConfig()
            addModelsThread = AddModelsThread()
            addModelsThread.start()
            i = 1
            # 使用较小的步长循环 sleep，以便更快响应停止请求
            for i in range(setting['interval'], 0, -1):
                if stop_requested.is_set():
                    break
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
                print(f'Next check in {i:02d} seconds (Ctrl+C to stop)\r', end='')
                time.sleep(1)
            
            # 如果收到停止请求，不需要等待 addModelsThread 完成，但最好还是 join 一下
            addModelsThread.join(timeout=1.0) 
            del addModelsThread, i

        except KeyboardInterrupt:
            # 这里的 KeyboardInterrupt 可能会被 signal_handler 捕获，
            # 但如果它发生在 sleep 期间，有时还是会抛出。
            stop_requested.set()
            break
        except BrokenPipeError:
            # 终端断开连接时忽略此错误
            pass
        except Exception as e:
            log_event(f"Main loop error: {e}")
            time.sleep(1)
    
    # === 退出清理逻辑 ===
    print("\n[退出] 正在停止所有任务，请稍候...")
    log_event("收到退出指令，正在关闭所有线程...")

    # 1. 停止 AddModelsThread (它本身运行很快，主要是 join) - 已经在循环里 join 了

    # 2. 停止所有录制线程 (Modelo) 和检测线程
    with state_lock:
        all_threads = hilos + recording
    
    for t in all_threads:
        if isinstance(t, Modelo):
            t.stop()
    
    # 3. 停止后处理线程 (通过 global event)
    # processingQueue 里的任务如果不重要可以不等待，或者等待直到空
    
    print("[退出] 等待所有线程结束...")
    
    # 简单的等待逻辑，避免无限死等
    wait_start = time.time()
    while time.time() - wait_start < 10:
        with state_lock:
             if not any(t.is_alive() for t in hilos + recording):
                 break
        time.sleep(0.5)

    print("[退出] 程序已结束。Bye!")
    log_event("程序已正常退出。")
    sys.exit(0)

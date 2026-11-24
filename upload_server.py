#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
文件上传服务（Python 2.7 单文件实现，无第三方依赖，代码同时兼容 Python 3 便于本地自测）

功能：
  * 浏览器拖拽 / 多选上传，分片流式写入，文件大小不限（不受内存与单请求体积限制）
  * 页面实时显示每个文件的上传进度与速度、总速度、剩余时间
  * 上传目录可配置（默认 /file），无数据库，直接读取目录生成文件列表
  * 页面右上角「改密」可修改登录用户名与密码（需当前密码验证，带盐哈希持久化）
  * 忘记密码：python upload_server.py --reset-password 交互式重置，或删除 upload_dir.json 恢复默认账号
  * 文件列表支持下载、删除

用法：
  python upload_server.py                     # 默认目录 /file，端口 8000
  python upload_server.py --dir /data/files --port 9000 --host 0.0.0.0

环境变量：
  UPLOAD_DIR       上传目录（等价于 --dir）
  UPLOAD_CHUNK_MB  分片大小，单位 MB（等价于 --chunk-size）
"""

from __future__ import print_function

import argparse
import binascii
import hashlib
import json
import mimetypes
import os
import random
import sys
import threading
import time

try:
    from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
    from SocketServer import ThreadingMixIn
    from urllib import quote as url_quote
except ImportError:  # Python 3 兼容（仅为方便本地调试）
    from http.server import BaseHTTPRequestHandler, HTTPServer
    from socketserver import ThreadingMixIn
    from urllib.parse import quote as url_quote

READ_BLOCK = 256 * 1024

# 禁止通过页面切换到这些系统目录（仅匹配目录本身，其子目录不受限制）
BLOCKED_DIRS = {b'/', b'/bin', b'/boot', b'/dev', b'/etc', b'/lib', b'/lib64',
                b'/proc', b'/sbin', b'/sys', b'/usr', b'/root'}

UPLOAD_DIR = None
TMP_DIR = None
CHUNK_SIZE = 8 * 1024 * 1024
MAX_CHUNK = CHUNK_SIZE + 1024 * 1024

# ---------------------------------------------------------------------------
# 登录鉴权 / 会话 / 验证码
# ---------------------------------------------------------------------------
AUTH_USER = 'admin'
AUTH_PASSWORD = 'Kingsha@2026'
AUTH_HASH = None               # 非空时表示已自定义密码（sha256$盐$摘要 格式）
SESSION_TTL = 12 * 3600        # 会话有效期 12 小时
CAPTCHA_TTL = 300              # 验证码有效期 5 分钟
SESSIONS = {}                  # token -> 过期时间戳
CAPTCHAS = {}                  # cid -> (验证码文本, 过期时间戳)
STORE_LOCK = threading.Lock()
START_TIME = time.time()       # 服务启动时间，用于页面显示运行时长
STATE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'upload_dir.json')
CAPTCHA_CHARS = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'  # 去掉易混淆字符


def _valid_upload_dir(norm):
    if not norm or not isinstance(norm, bytes):
        return False
    if norm in BLOCKED_DIRS:
        return False
    return os.path.isdir(norm)


def load_state():
    """读取状态文件（目录 + 账号），异常时返回空 dict"""
    try:
        with open(STATE_FILE, 'rb') as fp:
            data = json.loads(fp.read().decode('utf-8'))
    except (IOError, OSError, ValueError, UnicodeDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def load_saved_dir():
    """启动时读取上次保存的目录（目录切换持久化）"""
    data = load_state()
    raw = data.get('dir') or ''
    if isinstance(raw, bytes):
        raw = raw.decode('utf-8', 'replace')
    elif not isinstance(raw, str):
        raw = raw.encode('utf-8', 'replace').decode('utf-8', 'replace')
    text = raw.strip()
    if not text.startswith('/'):
        return None
    norm = os.path.normpath(text)
    if not isinstance(norm, bytes):
        try:
            norm = norm.encode(sys.getfilesystemencoding() or 'utf-8')
        except UnicodeEncodeError:
            return None
    return norm if _valid_upload_dir(norm) else None


def save_state():
    """把当前目录与账号写入状态文件"""
    data = {'dir': display_text(UPLOAD_DIR)}
    if AUTH_HASH:
        data['user'] = AUTH_USER if isinstance(AUTH_USER, str) else AUTH_USER.decode('utf-8', 'replace')
        data['pwd_hash'] = AUTH_HASH
    try:
        body = json.dumps(data, ensure_ascii=False)
        if not isinstance(body, bytes):
            body = body.encode('utf-8')
        with open(STATE_FILE, 'wb') as fp:
            fp.write(body)
        return True
    except (IOError, OSError):
        return False


def new_token():
    token = binascii.hexlify(os.urandom(24))
    if not isinstance(token, str):
        token = token.decode('ascii')
    return token


def cleanup_store(now):
    """清理过期的会话与验证码"""
    with STORE_LOCK:
        for tok in [t for t, exp in SESSIONS.items() if exp <= now]:
            del SESSIONS[tok]
        for cid in [c for c, entry in CAPTCHAS.items() if entry[1] <= now]:
            del CAPTCHAS[cid]


def _norm_bytes(text):
    if isinstance(text, bytes):
        return text
    if not isinstance(text, str):
        text = text.encode('utf-8', 'replace')
    return text.encode('utf-8')


def _compare(a, b):
    """常量时间比较，防止时序攻击"""
    try:
        from hmac import compare_digest
        return compare_digest(a, b)
    except ImportError:
        return a == b


def hash_password(password, salt=None):
    """带盐 SHA-256，返回 'sha256$盐$摘要' 格式"""
    pw = _norm_bytes(password)
    if salt is None:
        salt = binascii.hexlify(os.urandom(16))
        if not isinstance(salt, str):
            salt = salt.decode('ascii')
    digest = hashlib.sha256(salt.encode('ascii') + pw).hexdigest()
    return 'sha256$%s$%s' % (salt, digest)


def check_hash(password, stored):
    try:
        algo, salt, digest = stored.split('$', 2)
    except (ValueError, AttributeError):
        return False
    if algo != 'sha256' or len(digest) != 64:
        return False
    return _compare(hash_password(password, salt).split('$', 2)[2], digest)


def verify_password(user, password):
    if not _compare(_norm_bytes(user), _norm_bytes(AUTH_USER)):
        return False
    if AUTH_HASH:
        return check_hash(password, AUTH_HASH)
    return _compare(_norm_bytes(password), _norm_bytes(AUTH_PASSWORD))


def gen_captcha_svg(code):
    """生成带干扰线/噪点的 SVG 动态验证码"""
    width, height = 132, 44
    palette = ['#2f5fe0', '#5b3fd4', '#1f8f6a', '#c2483b', '#8a6d1f']
    noise = ['#9db4e8', '#b7a4e8', '#8fc7b0', '#d8a4a4']
    parts = ['<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" viewBox="0 0 %d %d">'
             % (width, height, width, height)]
    parts.append('<rect width="100%%" height="100%%" fill="#f4f6fb"/>')
    for _ in range(4):
        parts.append('<line x1="%d" y1="%d" x2="%d" y2="%d" stroke="%s" stroke-width="1" opacity="0.55"/>'
                     % (random.randint(0, width), random.randint(0, height),
                        random.randint(0, width), random.randint(0, height),
                        random.choice(noise)))
    for _ in range(28):
        parts.append('<circle cx="%d" cy="%d" r="1" fill="%s" opacity="0.5"/>'
                     % (random.randint(0, width), random.randint(0, height),
                        random.choice(['#98a2b3', '#667085'])))
    x = 12
    for ch in code:
        y = random.randint(28, 36)
        rot = random.randint(-20, 20)
        size = random.randint(24, 30)
        parts.append('<text x="%d" y="%d" font-family="Georgia, \'Times New Roman\', serif" '
                     'font-size="%d" font-weight="bold" fill="%s" '
                     'transform="rotate(%d %d %d)">%s</text>'
                     % (x, y, size, random.choice(palette), rot, x, y, ch))
        x += random.randint(20, 26)
    parts.append('</svg>')
    return ''.join(parts)


# ---------------------------------------------------------------------------
# 工具函数
# ---------------------------------------------------------------------------

def unquote_bytes(raw):
    """对 bytes 做 URL 解码，返回 bytes（py2 / py3 行为一致）"""
    out = bytearray()
    i = 0
    n = len(raw)
    while i < n:
        ch = raw[i:i + 1]
        if ch == b'%' and i + 2 < n:
            try:
                out.append(int(raw[i + 1:i + 3], 16))
                i += 3
                continue
            except ValueError:
                pass
        if ch == b'+':
            out.append(0x20)
        else:
            out.append(ord(ch))
        i += 1
    return bytes(out)


def parse_query(query):
    params = {}
    if not query:
        return params
    for pair in query.split(b'&'):
        if not pair:
            continue
        if b'=' in pair:
            key, value = pair.split(b'=', 1)
        else:
            key, value = pair, b''
        params[unquote_bytes(key)] = unquote_bytes(value)
    return params


def safe_name(raw):
    """只保留文件名本身，拒绝空名、. / .. 与路径穿越"""
    if not raw:
        return None
    name = raw.replace(b'\\', b'/').split(b'/')[-1].strip()
    if not name or name in (b'.', b'..') or b'\x00' in name:
        return None
    return name


def valid_uid(uid):
    if not uid or len(uid) < 6 or len(uid) > 64:
        return False
    allowed = set(b'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-')
    for ch in uid:
        if ch not in allowed:
            return False
    return True


def display_text(raw):
    return raw.decode('utf-8', 'replace')


def log_text(raw):
    """日志输出用：py2 直接输出原始字节，py3 输出可读文本"""
    if sys.version_info[0] < 3:
        return raw
    return raw.decode('utf-8', 'replace')


def list_files():
    items = []
    for raw in os.listdir(UPLOAD_DIR):
        if raw.startswith(b'.'):
            continue
        path = os.path.join(UPLOAD_DIR, raw)
        if not os.path.isfile(path):
            continue
        st = os.stat(path)
        items.append({
            'name': display_text(raw),
            'size': int(st.st_size),
            'mtime': int(st.st_mtime),
        })
    items.sort(key=lambda x: x['mtime'], reverse=True)
    return items


def cleanup_tmp(max_age=12 * 3600):
    """清理异常中断遗留的分片临时文件"""
    now = time.time()
    try:
        names = os.listdir(TMP_DIR)
    except OSError:
        return
    for raw in names:
        path = os.path.join(TMP_DIR, raw)
        try:
            if os.path.isfile(path) and now - os.stat(path).st_mtime > max_age:
                os.remove(path)
        except OSError:
            pass


# ---------------------------------------------------------------------------
# HTTP 处理
# ---------------------------------------------------------------------------

class UploadHandler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    timeout = 600
    server_version = 'UploadServer/1.0'

    # -- 基础响应 ---------------------------------------------------------
    def _write_out(self, data_bytes):
        buf = getattr(sys.stdout, 'buffer', None)
        if buf is not None:
            buf.write(data_bytes)
        else:  # Python 2 无 buffer 属性，stdout 本身可写字节
            sys.stdout.write(data_bytes)

    def log_message(self, fmt, *args):
        line = fmt % args
        if not isinstance(line, bytes):
            line = line.encode('utf-8', 'replace')
        prefix = ('[%s] ' % time.strftime('%Y-%m-%d %H:%M:%S')).encode('utf-8')
        self._write_out(prefix + line + b'\n')
        sys.stdout.flush()

    def _send_bytes(self, code, content_type, body, extra_headers=None):
        self.send_response(code)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        if extra_headers:
            for key, value in extra_headers:
                self.send_header(key, value)
        self.end_headers()
        if self.command != 'HEAD':
            self.wfile.write(body)

    def _send_json(self, obj, code=200):
        body = json.dumps(obj, ensure_ascii=False)
        if not isinstance(body, bytes):
            body = body.encode('utf-8')
        self._send_bytes(code, 'application/json; charset=utf-8', body)

    def _fail(self, code, message):
        self._send_json({'ok': False, 'error': message}, code)

    def _path_and_query(self):
        raw = self.path
        if not isinstance(raw, bytes):
            raw = raw.encode('utf-8')
        if b'?' in raw:
            path, query = raw.split(b'?', 1)
        else:
            path, query = raw, b''
        return path, parse_query(query)

    def _read_body(self, limit):
        try:
            length = int(self.headers.get('Content-Length') or 0)
        except (TypeError, ValueError):
            return None
        if length < 0 or length > limit:
            return None
        chunks = []
        remaining = length
        while remaining > 0:
            block = self.rfile.read(min(READ_BLOCK, remaining))
            if not block:
                return None
            chunks.append(block)
            remaining -= len(block)
        return b''.join(chunks)

    def _auth_ok(self, params):
        token = self.headers.get('X-Auth-Token')
        if not token and params:
            raw = params.get(b'token', b'')
            if raw:
                token = raw.decode('ascii', 'replace')
        if not token:
            return False
        now = time.time()
        with STORE_LOCK:
            exp = SESSIONS.get(token)
            if exp and exp > now:
                SESSIONS[token] = now + SESSION_TTL  # 滑动续期
                return True
        return False

    def _unauthorized(self):
        self._send_json({'ok': False, 'error': u'未登录或会话已过期'}, 401)

    def _captcha(self, params):
        cid = params.get(b'cid', b'').decode('ascii', 'replace')
        if not cid or len(cid) > 64:
            return self._fail(400, u'验证码标识不合法')
        code = ''.join(random.choice(CAPTCHA_CHARS) for _ in range(4))
        cleanup_store(time.time())
        with STORE_LOCK:
            CAPTCHAS[cid] = (code, time.time() + CAPTCHA_TTL)
        svg = gen_captcha_svg(code)
        if not isinstance(svg, bytes):
            svg = svg.encode('utf-8')
        self._send_bytes(200, 'image/svg+xml; charset=utf-8', svg)

    def _login(self):
        body = self._read_body(64 * 1024)
        if body is None:
            return self._fail(400, u'请求体不合法')
        try:
            data = json.loads(body.decode('utf-8'))
        except (ValueError, UnicodeDecodeError):
            return self._fail(400, u'JSON 解析失败')
        data = data or {}

        cid = data.get('cid') or ''
        if isinstance(cid, bytes):
            cid = cid.decode('ascii', 'replace')
        captcha = data.get('captcha') or ''
        if isinstance(captcha, bytes):
            captcha = captcha.decode('ascii', 'replace')
        captcha = captcha.strip().upper()

        with STORE_LOCK:
            entry = CAPTCHAS.pop(cid, None)
        if not entry or entry[1] <= time.time():
            return self._fail(400, u'验证码已过期，请刷新后重试')
        if entry[0].upper() != captcha:
            return self._fail(400, u'验证码错误')

        user = data.get('user') or ''
        password = data.get('password') or ''
        if not verify_password(user, password):
            self.log_message('login failed for user %s', user)
            return self._fail(401, u'用户名或密码错误')

        token = new_token()
        with STORE_LOCK:
            SESSIONS[token] = time.time() + SESSION_TTL
        self.log_message('login ok, user %s', user)
        return self._send_json({'ok': True, 'token': token, 'ttl': SESSION_TTL})

    def _logout(self):
        token = self.headers.get('X-Auth-Token')
        if token:
            with STORE_LOCK:
                SESSIONS.pop(token, None)
        return self._send_json({'ok': True})

    # -- 修改账号密码 -----------------------------------------------------
    def _passwd(self):
        global AUTH_USER, AUTH_HASH
        body = self._read_body(64 * 1024)
        if body is None:
            return self._fail(400, u'请求体不合法')
        try:
            data = json.loads(body.decode('utf-8'))
        except (ValueError, UnicodeDecodeError):
            return self._fail(400, u'JSON 解析失败')
        data = data or {}

        old_pwd = data.get('old_password') or ''
        new_user = data.get('new_user') or ''
        if isinstance(new_user, bytes):
            new_user = new_user.decode('utf-8', 'replace')
        new_user = new_user.strip()
        new_pwd = data.get('new_password') or ''

        if not verify_password(AUTH_USER, old_pwd):
            return self._fail(401, u'当前密码错误')
        if not new_pwd or len(new_pwd) < 6:
            return self._fail(400, u'新密码至少需要 6 位')
        if len(new_pwd) > 128:
            return self._fail(400, u'新密码过长（最多 128 位）')
        if new_user and (len(new_user) > 64 or new_user.startswith(' ')):
            return self._fail(400, u'用户名不合法（最长 64 位）')

        if new_user:
            AUTH_USER = new_user
        AUTH_HASH = hash_password(new_pwd)
        persisted = save_state()
        self.log_message('login account updated, user %s%s', AUTH_USER,
                         '' if persisted else ' (persist failed)')
        return self._send_json({'ok': True, 'user': AUTH_USER, 'persisted': persisted})

    # -- 路由 -------------------------------------------------------------
    def do_GET(self):
        try:
            path, params = self._path_and_query()
            if path in (b'/', b'/index.html'):
                page_body = PAGE
                if not isinstance(page_body, bytes):
                    page_body = page_body.encode('utf-8')
                self._send_bytes(200, 'text/html; charset=utf-8', page_body)
            elif path == b'/api/captcha':
                self._captcha(params)
            elif not self._auth_ok(params):
                self._unauthorized()
            elif path == b'/api/info':
                self._send_json({
                    'dir': display_text(UPLOAD_DIR),
                    'chunk_size': CHUNK_SIZE,
                    'uptime': int(time.time() - START_TIME),
                })
            elif path == b'/api/files':
                items = list_files()
                self._send_json({
                    'files': items,
                    'count': len(items),
                    'total_size': sum(i['size'] for i in items),
                })
            elif path == b'/download':
                self._download(params)
            else:
                self._fail(404, 'Not Found')
        except Exception as exc:  # noqa: BLE001 - 单请求异常不应拖垮连接
            self.log_message('GET error: %s', exc)
            self.close_connection = True

    def do_HEAD(self):
        self.do_GET()

    def do_POST(self):
        try:
            path, params = self._path_and_query()
            if path == b'/api/login':
                self._login()
            elif path == b'/api/logout':
                self._logout()
            elif not self._auth_ok(params):
                self._unauthorized()
            elif path == b'/api/upload':
                self._upload(params)
            elif path == b'/api/delete':
                self._delete()
            elif path == b'/api/setdir':
                self._setdir()
            elif path == b'/api/passwd':
                self._passwd()
            else:
                self._fail(404, 'Not Found')
        except Exception as exc:  # noqa: BLE001
            self.log_message('POST error: %s', exc)
            self.close_connection = True

    # -- 上传 -------------------------------------------------------------
    def _upload(self, params):
        name = safe_name(params.get(b'name', b''))
        uid = params.get(b'uid', b'')

        if not name:
            return self._fail(400, '文件名不合法')
        if not valid_uid(uid):
            return self._fail(400, '上传标识不合法')

        try:
            index = int(params.get(b'index', b'0') or b'0')
            total = int(params.get(b'total', b'1') or b'1')
            length = int(self.headers.get('Content-Length') or 0)
        except (TypeError, ValueError):
            return self._fail(400, '参数不合法')

        if index < 0 or total < 1 or index >= total:
            return self._fail(400, '分片序号不合法')
        if length > MAX_CHUNK:
            return self._fail(413, '单个分片过大')
        if length == 0 and not (total == 1 and index == 0):
            return self._fail(400, '请求体为空')

        part_path = os.path.join(TMP_DIR, uid + b'.part')
        mode = 'wb' if index == 0 else 'ab'

        try:
            with open(part_path, mode) as fp:
                remaining = length
                while remaining > 0:
                    block = self.rfile.read(min(READ_BLOCK, remaining))
                    if not block:
                        raise IOError('客户端连接中断')
                    fp.write(block)
                    remaining -= len(block)
        except (IOError, OSError) as exc:
            try:
                os.remove(part_path)
            except OSError:
                pass
            return self._fail(400, '写入失败：%s' % exc)

        if index + 1 < total:
            return self._send_json({'ok': True, 'index': index, 'received': length})

        target = os.path.join(UPLOAD_DIR, name)
        try:
            os.rename(part_path, target)
        except OSError as exc:
            try:
                os.remove(part_path)
            except OSError:
                pass
            return self._fail(500, '保存失败：%s' % exc)

        size = os.path.getsize(target)
        self.log_message('saved %s (%d bytes)', log_text(name), size)
        return self._send_json({'ok': True, 'name': display_text(name), 'size': size})

    # -- 删除 -------------------------------------------------------------
    def _delete(self):
        body = self._read_body(64 * 1024)
        if body is None:
            return self._fail(400, '请求体不合法')
        try:
            data = json.loads(body.decode('utf-8'))
        except (ValueError, UnicodeDecodeError):
            return self._fail(400, 'JSON 解析失败')

        raw_name = (data or {}).get('name') or ''
        if isinstance(raw_name, bytes):
            name_bytes = raw_name
        else:
            name_bytes = raw_name.encode('utf-8')

        name = safe_name(name_bytes)
        if not name:
            return self._fail(400, '文件名不合法')

        target = os.path.join(UPLOAD_DIR, name)
        if not os.path.isfile(target):
            return self._fail(404, '文件不存在')

        try:
            os.remove(target)
        except OSError as exc:
            return self._fail(500, '删除失败：%s' % exc)

        self.log_message('deleted %s', log_text(name))
        return self._send_json({'ok': True})

    # -- 切换保存目录 -----------------------------------------------------
    def _setdir(self):
        body = self._read_body(64 * 1024)
        if body is None:
            return self._fail(400, '请求体不合法')
        try:
            data = json.loads(body.decode('utf-8'))
        except (ValueError, UnicodeDecodeError):
            return self._fail(400, 'JSON 解析失败')

        raw_dir = (data or {}).get('dir') or ''
        if isinstance(raw_dir, bytes):
            raw_dir = raw_dir.decode('utf-8', 'replace')
        elif not isinstance(raw_dir, str):
            # Python 2 的 unicode 类型
            raw_dir = raw_dir.encode('utf-8', 'replace').decode('utf-8', 'replace')
        text = raw_dir.strip()

        if not text:
            return self._fail(400, u'目录不能为空')
        if not text.startswith('/') or '\x00' in text:
            return self._fail(400, u'必须是服务器上的绝对路径（以 / 开头）')

        norm = os.path.normpath(text)
        if not isinstance(norm, bytes):
            try:
                norm = norm.encode(sys.getfilesystemencoding() or 'utf-8')
            except UnicodeEncodeError:
                return self._fail(400, u'路径编码不合法')
        if norm in BLOCKED_DIRS:
            return self._fail(400, u'不允许切换到系统目录 %s' % display_text(norm))

        try:
            if not os.path.isdir(norm):
                os.makedirs(norm)
            probe = os.path.join(norm, b'.write_test')
            with open(probe, 'w') as fp:
                fp.write('ok')
            os.remove(probe)
        except (IOError, OSError) as exc:
            msg = str(exc)
            if not isinstance(msg, bytes):
                msg = msg.encode('utf-8', 'replace')
            return self._fail(400, u'目录不可用：%s' % msg.decode('utf-8', 'replace'))

        global UPLOAD_DIR, TMP_DIR
        UPLOAD_DIR = norm
        TMP_DIR = os.path.join(norm, b'.tmp')
        try:
            if not os.path.isdir(TMP_DIR):
                os.makedirs(TMP_DIR)
        except OSError as exc:
            return self._fail(500, '临时目录创建失败：%s' % exc)

        self.log_message('upload dir changed to %s', log_text(UPLOAD_DIR))
        if not save_state():
            return self._send_json({'ok': True, 'dir': display_text(UPLOAD_DIR),
                                    'persisted': False,
                                    'warn': u'目录已切换，但持久化失败（状态文件不可写）'})
        return self._send_json({'ok': True, 'dir': display_text(UPLOAD_DIR)})

    # -- 下载 -------------------------------------------------------------
    def _download(self, params):
        name = safe_name(params.get(b'name', b''))
        if not name:
            return self._fail(400, '文件名不合法')

        target = os.path.join(UPLOAD_DIR, name)
        if not os.path.isfile(target):
            return self._fail(404, '文件不存在')

        size = os.path.getsize(target)
        name_text = display_text(name)
        try:
            ctype = mimetypes.guess_type(name_text)[0] or 'application/octet-stream'
        except (UnicodeError, TypeError):
            ctype = 'application/octet-stream'
        fallback = name_text.encode('ascii', 'replace').decode('ascii').replace('"', '_')
        disposition = 'attachment; filename="%s"; filename*=UTF-8\'\'%s' % (
            fallback, url_quote(name, safe=''))

        self.send_response(200)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(size))
        self.send_header('Content-Disposition', disposition)
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()

        if self.command == 'HEAD':
            return

        try:
            with open(target, 'rb') as fp:
                while True:
                    block = fp.read(READ_BLOCK)
                    if not block:
                        break
                    self.wfile.write(block)
        except (IOError, OSError):
            self.close_connection = True


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 128


# ---------------------------------------------------------------------------
# 页面
# ---------------------------------------------------------------------------

PAGE = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>文件上传</title>
<style>
:root{
  --bg:#f2f2f7;
  --card:#ffffff;
  --line:rgba(60,60,67,.12);
  --hair:rgba(60,60,67,.10);
  --text:#1c1c1e;
  --muted:rgba(60,60,67,.60);
  --faint:rgba(60,60,67,.36);
  --accent:#007aff;
  --accent-soft:rgba(0,122,255,.10);
  --danger:#ff3b30;
  --danger-soft:rgba(255,59,48,.10);
  --ok:#34c759;
  --ok-soft:rgba(52,199,89,.14);
  --orange:#ff9500;
  --fill:rgba(120,120,128,.12);
  --fill2:rgba(120,120,128,.07);
  --radius:18px;
}
*{box-sizing:border-box}
html,body{margin:0}
html{background:var(--bg)}
body{
  background:transparent;
  color:var(--text);
  font:15px/1.55 -apple-system,BlinkMacSystemFont,"SF Pro Text","SF Pro SC","Segoe UI","PingFang SC","Hiragino Sans GB","Microsoft YaHei",sans-serif;
  min-height:100vh;
  -webkit-font-smoothing:antialiased;
}
.wrap{max-width:920px;margin:0 auto;padding:18px 24px 72px}
.app{display:flex;min-height:100vh}
.sidebar{position:fixed;left:0;top:0;bottom:0;width:224px;box-sizing:border-box;
  background:rgba(255,255,255,.72);backdrop-filter:blur(24px) saturate(180%);
  -webkit-backdrop-filter:blur(24px) saturate(180%);
  border-right:1px solid var(--hair);padding:20px 14px 16px;display:flex;flex-direction:column;
  gap:16px;overflow-y:auto;z-index:10}
.main{margin-left:224px;min-width:0;flex:1}
.topbar{display:flex;align-items:center;justify-content:space-between;gap:14px;flex-wrap:wrap;
  padding:16px 0 4px}
.topbar-right{display:flex;align-items:center;gap:9px;flex-wrap:wrap}
.brand{display:flex;align-items:center;gap:12px;padding:4px 4px 0}
.logo{width:44px;height:44px;border-radius:12px;display:flex;align-items:center;justify-content:center;
  color:#fff;flex:0 0 auto;background:linear-gradient(180deg,#0a84ff,#0060df);
  box-shadow:0 6px 14px rgba(0,96,223,.30)}
h1{font-size:17px;font-weight:600;margin:0;letter-spacing:-.2px}
.sub{margin:1px 0 0;font-size:12px;color:var(--muted);letter-spacing:0}
.nav{display:flex;flex-direction:column;gap:2px}
.nav-item{display:flex;align-items:center;gap:10px;padding:9px 12px;border-radius:11px;
  font-size:13.5px;font-weight:500;color:var(--text);text-decoration:none;cursor:pointer;
  transition:background .18s,color .18s}
.nav-item:hover{background:var(--fill2)}
.nav-item.active{background:var(--accent-soft);color:var(--accent)}
.side-group{background:#fff;border-radius:14px;padding:12px 12px;box-shadow:0 1px 2px rgba(0,0,0,.04)}
.side-label{font-size:11px;font-weight:600;color:var(--faint);margin:0 4px 8px;
  text-transform:uppercase;letter-spacing:.6px}
.side-sec{display:flex;flex-direction:column}
.sidebar .dir{width:100%;box-sizing:border-box;flex-wrap:wrap}
.sidebar .dir code{max-width:100%}
.sidebar .dir-input{flex:1 1 100%;width:100%;max-width:100%;margin-top:8px}
.sidebar .dir-btn{flex:1}
.side-foot{margin-top:auto;display:flex;flex-direction:column;gap:8px}
.side-btn{width:100%;justify-content:center;display:flex;align-items:center;border:none;
  background:var(--accent-soft);color:var(--accent);font-weight:600}
.side-btn:hover{background:rgba(0,122,255,.18);color:var(--accent)}
.side-btn.danger{background:var(--danger-soft);color:var(--danger)}
.side-btn.danger:hover{background:rgba(255,59,48,.18);color:var(--danger)}
.clock,.svc{font-size:12.5px;font-weight:500;color:var(--text);
  background:rgba(255,255,255,.72);backdrop-filter:blur(20px) saturate(180%);
  -webkit-backdrop-filter:blur(20px) saturate(180%);
  border:1px solid var(--hair);padding:6px 12px;border-radius:999px;white-space:nowrap}
.clock{font-family:ui-monospace,"SF Mono",SFMono-Regular,Menlo,Consolas,monospace;font-size:12px}
.dot{width:8px;height:8px;border-radius:50%;background:#8e8e93;flex:0 0 auto}
.dot.on{background:var(--ok);box-shadow:0 0 6px rgba(52,199,89,.6)}
.dot.off{background:var(--danger);box-shadow:0 0 6px rgba(255,59,48,.5)}
@media (max-width:820px){
  .app{flex-direction:column}
  .sidebar{position:static;width:100%;height:auto;flex-direction:row;flex-wrap:wrap;
    align-items:center;border-right:none;border-bottom:1px solid var(--hair);gap:10px;padding:12px 16px}
  .main{margin-left:0}
  .nav{flex-direction:row}
  .side-group{flex:1;min-width:200px}
  .side-foot{margin-top:0;flex-direction:row}
  .side-btn{width:auto;padding:8px 14px}
}
.dir{display:flex;align-items:center;gap:8px;background:var(--fill2);
  padding:8px 11px;border-radius:12px;font-size:12.5px;font-weight:500;color:var(--muted);
  cursor:pointer;transition:background .18s}
.dir:hover{background:var(--fill)}
.dir code{font-family:ui-monospace,"SF Mono",SFMono-Regular,Menlo,Consolas,monospace;color:var(--text);
  background:transparent;padding:0;max-width:44vw;overflow:hidden;
  text-overflow:ellipsis;white-space:nowrap;font-weight:500}
.dir.editing code{display:flex;align-items:center;gap:6px;overflow:visible;flex-wrap:wrap}
.dir-input{width:200px;max-width:44vw;border:none;border-radius:9px;padding:5px 9px;
  font-family:ui-monospace,"SF Mono",SFMono-Regular,Menlo,Consolas,monospace;font-size:12px;
  color:var(--text);background:#fff;outline:none;box-shadow:0 0 0 2px var(--accent-soft)}
.dir-input:focus{box-shadow:0 0 0 2.5px rgba(0,122,255,.35)}
.dir-btn{border:none;background:var(--accent-soft);color:var(--accent);border-radius:8px;padding:4px 11px;
  font-size:12px;font-weight:600;cursor:pointer;font-family:inherit;flex:0 0 auto;transition:background .18s}
.dir-btn:hover{background:rgba(0,122,255,.18)}
.dir-btn:disabled{opacity:.5;cursor:default}

/* 登录遮罩（iOS 弹窗风格） */
.login-mask{position:fixed;inset:0;z-index:100;display:flex;align-items:center;justify-content:center;
  background:rgba(0,0,0,.40);backdrop-filter:blur(20px) saturate(120%);
  -webkit-backdrop-filter:blur(20px) saturate(120%)}
.login-mask[hidden]{display:none}
.login-card{width:330px;max-width:calc(100vw - 40px);background:rgba(255,255,255,.94);
  backdrop-filter:blur(30px) saturate(180%);-webkit-backdrop-filter:blur(30px) saturate(180%);
  border-radius:20px;box-shadow:0 24px 70px rgba(0,0,0,.30);padding:26px 24px 22px;
  display:flex;flex-direction:column;gap:13px}
.login-logo{width:48px;height:48px;border-radius:13px;margin:0 auto;
  background:linear-gradient(180deg,#0a84ff,#0060df);color:#fff;
  display:flex;align-items:center;justify-content:center;
  box-shadow:0 8px 18px rgba(0,96,223,.32)}
.login-card h2{margin:2px 0 0;font-size:17px;font-weight:600;text-align:center;letter-spacing:-.2px}
.login-sub{margin:0;text-align:center;font-size:12.5px;color:var(--muted)}
.login-field{display:flex;flex-direction:column;gap:6px;font-size:12.5px;font-weight:500;color:var(--muted)}
.login-field input{width:100%;border:none;border-radius:12px;padding:10px 13px;
  font-size:14px;font-family:inherit;color:var(--text);outline:none;transition:box-shadow .18s;
  background:var(--fill)}
.login-field input::placeholder{color:var(--faint)}
.login-field input:focus{background:#fff;box-shadow:0 0 0 2.5px rgba(0,122,255,.35)}
.cap-row{display:flex;gap:8px;align-items:stretch}
.cap-row input{flex:1;min-width:0}
.cap-img{flex:0 0 auto;width:132px;height:44px;border-radius:12px;cursor:pointer;
  border:none;display:block;background:var(--fill2)}
.login-err{background:var(--danger-soft);color:var(--danger);font-size:12.5px;font-weight:500;
  padding:9px 13px;border-radius:11px}
.login-btn{margin-top:2px;width:100%;padding:11px 0;font-size:15px;font-weight:600}
.login-btn + .login-btn{margin-top:0;background:var(--fill);color:var(--text)}
.login-btn + .login-btn:hover{background:rgba(120,120,128,.20)}
#pwdForm h2{margin-bottom:4px}
@media (max-width:640px){.login-card{padding:22px 18px 18px}}
.card{background:var(--card);border-radius:var(--radius);box-shadow:0 1px 3px rgba(0,0,0,.07)}
.card+.card{margin-top:16px}

.drop{position:relative;padding:42px 24px 36px;display:flex;flex-direction:column;align-items:center;
  gap:9px;text-align:center;border:1.5px dashed rgba(0,122,255,.30);
  background:#fff;cursor:pointer;
  transition:border-color .18s, background .18s, transform .18s}
.drop:hover,.drop.drag{border-color:var(--accent);background:#f5f9ff;transform:translateY(-1px)}
.drop.drag{box-shadow:0 0 0 5px rgba(0,122,255,.08)}
.cloud{width:66px;height:66px;border-radius:50%;display:flex;align-items:center;justify-content:center;
  background:var(--accent-soft);color:var(--accent);margin-bottom:2px}
.drop h2{font-size:16px;font-weight:600;margin:0;letter-spacing:-.2px}
.drop p{margin:0;font-size:12.5px;color:var(--muted)}
.drop .tip{font-size:12px;color:var(--faint)}
.btn{border:none;background:var(--fill);color:var(--text);padding:8px 15px;border-radius:12px;
  font-size:13px;font-weight:500;cursor:pointer;transition:background .18s,color .18s;font-family:inherit}
.btn:hover{background:rgba(120,120,128,.20);color:var(--text)}
.btn:disabled{opacity:.5;cursor:default}
.btn.primary{margin-top:12px;background:var(--accent);color:#fff;
  padding:10px 22px;box-shadow:0 5px 14px rgba(0,122,255,.30);font-weight:600}
.btn.primary:hover{background:#0071e3;color:#fff}

.card-head{display:flex;align-items:center;justify-content:space-between;gap:12px;
  padding:15px 20px;border-bottom:1px solid var(--hair);flex-wrap:wrap}
.card-head h2{font-size:14.5px;font-weight:600;margin:0;display:flex;align-items:center;gap:8px;letter-spacing:-.1px}
.card-head .meta{font-size:12.5px;color:var(--muted);font-weight:400}
.queue-body{padding:4px 20px 14px}
.task{display:flex;align-items:flex-start;gap:12px;padding:13px 0;border-bottom:1px solid var(--hair)}
.task:last-child{border-bottom:none}
.task-main{flex:1;min-width:0}
.task-top{display:flex;align-items:center;gap:10px;margin-bottom:7px}
.task-name{font-size:13.5px;font-weight:500;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.task-status{font-size:11px;font-weight:600;padding:2px 9px;border-radius:999px;background:var(--fill);color:var(--muted);flex:0 0 auto}
.task-status.uploading{background:var(--accent-soft);color:var(--accent)}
.task-status.done{background:var(--ok-soft);color:#1f9d47}
.task-status.error{background:var(--danger-soft);color:var(--danger)}
.task-status.canceled{background:var(--fill);color:var(--faint)}
.bar{height:6px;border-radius:999px;background:var(--fill);overflow:hidden}
.bar i{display:block;height:100%;width:0;border-radius:999px;
  background:var(--accent);transition:width .16s linear}
.task.done .bar i{background:var(--ok)}
.task.error .bar i{background:var(--danger)}
.task.canceled .bar i{background:#c7c7cc}
.task-meta{display:flex;justify-content:space-between;gap:12px;margin-top:6px;
  font-size:12px;color:var(--muted);font-variant-numeric:tabular-nums}
.task-meta .speed{color:var(--accent);font-weight:500}
.task.error .task-meta .speed{color:var(--danger)}
.icon-btn{flex:0 0 auto;width:28px;height:28px;border-radius:50%;border:none;
  background:transparent;color:var(--faint);font-size:17px;line-height:1;cursor:pointer;transition:.18s}
.icon-btn:hover{background:var(--danger-soft);color:var(--danger)}

.table-wrap{overflow-x:auto}
table{width:100%;border-collapse:collapse}
th,td{padding:12px 20px;text-align:left;font-size:13px;white-space:nowrap}
th{font-size:11px;font-weight:600;color:var(--faint);background:transparent;
  border-bottom:1px solid var(--hair);text-transform:uppercase;letter-spacing:.6px}
tbody tr{border-bottom:1px solid var(--hair)}
tbody tr:last-child{border-bottom:none}
tbody tr:hover{background:var(--fill2)}
.cell-name{max-width:520px;width:100%;white-space:normal}
.file-cell{display:flex;align-items:center;gap:10px;min-width:0}
.file-icon{flex:0 0 auto;width:30px;height:30px;border-radius:9px;display:flex;align-items:center;
  justify-content:center;background:var(--accent-soft);color:var(--accent)}
.file-name{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;word-break:break-all;font-weight:500}
.size,.time{color:var(--muted);font-variant-numeric:tabular-nums}
.actions{display:flex;gap:6px;justify-content:flex-end}
.act{display:inline-flex;align-items:center;gap:4px;padding:5px 12px;border-radius:999px;
  border:none;background:var(--accent-soft);color:var(--accent);font-size:12.5px;font-weight:500;
  text-decoration:none;cursor:pointer;font-family:inherit;transition:background .18s}
.act:hover{background:rgba(0,122,255,.18);color:var(--accent)}
.act.danger{background:var(--danger-soft);color:var(--danger)}
.act.danger:hover{background:rgba(255,59,48,.18);color:var(--danger)}
.act:disabled{opacity:.5;cursor:default}
.empty{padding:54px 20px;text-align:center;color:var(--faint);font-size:13px}
.empty svg{opacity:.45;margin-bottom:8px}
.foot{margin-top:26px;text-align:center;font-size:12px;color:var(--faint)}
@media (max-width:640px){
  .wrap{padding:16px 14px 56px}
  .col-time{display:none}
  th,td{padding:11px 14px}
  .cell-name{max-width:200px}
  .dir code{max-width:40vw}
}

/* ---------------- 科技感增强 ---------------- */
/* 网格底纹（顶部渐隐） */
body::before{content:'';position:fixed;inset:0;z-index:-1;pointer-events:none;
  background-image:linear-gradient(rgba(10,132,255,.05) 1px,transparent 1px),
    linear-gradient(90deg,rgba(10,132,255,.05) 1px,transparent 1px);
  background-size:38px 38px;
  -webkit-mask-image:radial-gradient(ellipse 95% 75% at 50% 0%,#000 25%,transparent 78%);
  mask-image:radial-gradient(ellipse 95% 75% at 50% 0%,#000 25%,transparent 78%)}
/* 极光流彩（缓慢漂移） */
body::after{content:'';position:fixed;inset:-25%;z-index:-1;pointer-events:none;
  background:
    radial-gradient(620px 420px at 16% 8%, rgba(10,132,255,.11), transparent 62%),
    radial-gradient(720px 480px at 86% 18%, rgba(94,92,230,.11), transparent 62%),
    radial-gradient(560px 420px at 50% 105%, rgba(0,199,255,.09), transparent 62%);
  animation:aurora 16s ease-in-out infinite alternate}
@keyframes aurora{
  0%{transform:translate3d(-2%,-1.5%,0) scale(1)}
  50%{transform:translate3d(1.5%,1%,0) scale(1.05)}
  100%{transform:translate3d(2.5%,2%,0) scale(1.08)}}
/* 服务状态：雷达扫描脉冲 */
.dot{position:relative}
.dot.on::after{content:'';position:absolute;left:0;top:0;width:8px;height:8px;border-radius:50%;
  background:rgba(52,199,89,.5);animation:ping 1.9s cubic-bezier(0,0,.2,1) infinite}
@keyframes ping{0%{transform:scale(1);opacity:.85}70%,100%{transform:scale(2.8);opacity:0}}
/* 时钟：数字微光 */
.clock{color:#0a84ff;text-shadow:0 0 14px rgba(10,132,255,.30)}
/* Logo 呼吸光晕 */
.logo{animation:logoGlow 3.2s ease-in-out infinite}
@keyframes logoGlow{
  0%,100%{box-shadow:0 6px 14px rgba(0,96,223,.30)}
  50%{box-shadow:0 6px 24px rgba(10,132,255,.58)}}
/* 上传区：HUD 四角框（对角两枚）+ 云图标悬浮 */
.drop::before,.drop::after{content:'';position:absolute;width:24px;height:24px;opacity:.45;
  border:2px solid rgba(10,132,255,.55);transition:opacity .2s,transform .2s;pointer-events:none}
.drop::before{left:14px;top:14px;border-right:none;border-bottom:none;border-radius:8px 0 0 0}
.drop::after{right:14px;bottom:14px;border-left:none;border-top:none;border-radius:0 0 8px 0}
.drop:hover::before,.drop.drag::before{opacity:1;transform:translate(-3px,-3px)}
.drop:hover::after,.drop.drag::after{opacity:1;transform:translate(3px,3px)}
.cloud{animation:float 3.4s ease-in-out infinite}
@keyframes float{0%,100%{transform:translateY(0)}50%{transform:translateY(-6px)}}
.drop:hover .cloud,.drop.drag .cloud{box-shadow:0 10px 26px rgba(10,132,255,.30)}
/* 进度条：流光扫过 */
.bar i{position:relative;overflow:hidden}
.bar i::after{content:'';position:absolute;inset:0;
  background:linear-gradient(90deg,transparent,rgba(255,255,255,.5),transparent);
  transform:translateX(-100%);animation:shimmer 1.4s linear infinite}
.task.done .bar i::after,.task.error .bar i::after,.task.canceled .bar i::after{display:none}
@keyframes shimmer{to{transform:translateX(100%)}}
/* 卡片悬浮微抬 */
.card{transition:box-shadow .22s}
.card:hover{box-shadow:0 4px 16px rgba(0,0,0,.10)}
/* 尊重减弱动态偏好 */
@media (prefers-reduced-motion:reduce){
  *,*::before,*::after{animation:none!important;transition:none!important}
}
</style>
</head>
<body>
<div class="login-mask" id="loginMask" hidden>
  <form class="login-card" id="loginForm" autocomplete="off">
    <div class="login-logo">
      <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/></svg>
    </div>
    <h2>文件上传服务</h2>
    <p class="login-sub">请登录后使用</p>
    <label class="login-field">用户名
      <input id="loginUser" type="text" placeholder="请输入用户名" autocomplete="username">
    </label>
    <label class="login-field">密码
      <input id="loginPass" type="password" placeholder="请输入密码" autocomplete="current-password">
    </label>
    <div class="login-field">验证码
      <div class="cap-row">
        <input id="loginCap" type="text" maxlength="8" placeholder="不区分大小写">
        <img id="capImg" class="cap-img" alt="验证码" title="看不清？点击刷新">
      </div>
    </div>
    <div class="login-err" id="loginErr" hidden></div>
    <button class="btn primary login-btn" type="submit">登 录</button>
  </form>
</div>

<div class="login-mask" id="pwdMask" hidden>
  <form class="login-card" id="pwdForm" autocomplete="off">
    <h2>修改登录账号</h2>
    <label class="login-field">当前密码
      <input id="pwdOld" type="password" placeholder="验证身份">
    </label>
    <label class="login-field">新用户名（留空则不修改）
      <input id="pwdUser" type="text" placeholder="当前用户名保持不变">
    </label>
    <label class="login-field">新密码（至少 6 位）
      <input id="pwdNew" type="password" placeholder="请输入新密码">
    </label>
    <label class="login-field">确认新密码
      <input id="pwdNew2" type="password" placeholder="再次输入新密码">
    </label>
    <div class="login-err" id="pwdErr" hidden></div>
    <button class="btn primary login-btn" type="submit">保 存</button>
    <button class="btn login-btn" type="button" id="pwdCancel">取 消</button>
  </form>
</div>

<div class="app">
<aside class="sidebar">
  <div class="brand">
    <div class="logo">
      <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 19V6"/><path d="m6 12 6-6 6 6"/><path d="M5 21h14"/></svg>
    </div>
    <div>
      <h1>文件上传</h1>
      <p class="sub">分片传输 · 实时速度</p>
    </div>
  </div>
  <nav class="nav side-group">
    <a class="nav-item active" data-target="drop" href="#drop">
      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 13v8"/><path d="m8 17 4-4 4 4"/><path d="M20.4 14.5A4.5 4.5 0 0 0 18 6.2 6 6 0 0 0 6.3 8.1 4 4 0 0 0 4 12a4 4 0 0 0 4 4h1"/></svg>
      上传中心
    </a>
    <a class="nav-item" data-target="filesCard" href="#filesCard">
      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/></svg>
      文件列表
    </a>
  </nav>
  <div class="side-sec side-group">
    <div class="side-label">保存目录</div>
    <div class="dir" id="dirChip" title="点击修改保存目录">保存目录 <code id="dirPath">加载中…</code></div>
  </div>
  <div class="side-foot">
    <button class="btn side-btn" id="passwdBtn" type="button" hidden>修改密码</button>
    <button class="btn side-btn danger" id="logoutBtn" type="button" hidden>退出登录</button>
  </div>
</aside>
<main class="main">
  <header class="topbar">
    <div>
      <h1>上传中心</h1>
      <p class="sub">拖拽上传 · 超大文件分片传输 · 实时速度</p>
    </div>
    <div class="topbar-right">
      <span class="svc" id="svcStatus" title=""><i class="dot" id="svcDot"></i><span id="svcText">检测中…</span></span>
      <span class="clock" id="clock">--</span>
    </div>
  </header>
  <div class="wrap">
  <section class="card drop" id="drop">
    <div class="cloud">
      <svg width="30" height="30" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 13v8"/><path d="m8 17 4-4 4 4"/><path d="M20.4 14.5A4.5 4.5 0 0 0 18 6.2 6 6 0 0 0 6.3 8.1 4 4 0 0 0 4 12a4 4 0 0 0 4 4h1"/></svg>
    </div>
    <h2>拖拽文件到此处，或点击选择文件</h2>
    <p>支持多文件同时上传，文件大小不限</p>
    <div class="tip" id="chunkTip">大文件自动分片上传</div>
    <button class="btn primary" type="button" id="pickBtn">选择文件</button>
    <input type="file" id="picker" multiple hidden>
  </section>

  <section class="card" id="queueCard" hidden>
    <div class="card-head">
      <h2>上传队列 <span class="meta" id="queueSummary"></span></h2>
    </div>
    <div class="queue-body" id="queue"></div>
  </section>

  <section class="card" id="filesCard">
    <div class="card-head">
      <h2>文件列表 <span class="meta" id="fileMeta"></span></h2>
      <button class="btn" type="button" id="refreshBtn">刷新</button>
    </div>
    <div class="table-wrap">
      <table id="fileTable" hidden>
        <thead>
          <tr>
            <th>文件名</th>
            <th>大小</th>
            <th class="col-time">修改时间</th>
            <th style="text-align:right">操作</th>
          </tr>
        </thead>
        <tbody id="fileBody"></tbody>
      </table>
    </div>
    <div class="empty" id="empty">
      <div>
        <svg width="34" height="34" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/></svg>
      </div>
      暂无文件，上传后会显示在这里
    </div>
  </section>

  <div class="foot">上传成功后文件直接保存到服务器目录，无数据库</div>
  </div>
</main>
</div>

<script>
(function () {
  'use strict';

  var MAX_PARALLEL = 3;
  var TOKEN_KEY = 'upload_token';
  var state = {
    chunkSize: 8 * 1024 * 1024,
    token: '',
    cid: '',
    tasks: [],
    files: []
  };

  function authUrl(url) {
    return url + (url.indexOf('?') >= 0 ? '&' : '?') + 'token=' + encodeURIComponent(state.token || '');
  }

  function authFetch(url, opts) {
    opts = opts || {};
    opts.headers = opts.headers || {};
    opts.headers['X-Auth-Token'] = state.token || '';
    return fetch(url, opts).then(function (res) {
      if (res.status === 401) {
        showLogin();
        throw new Error('unauthorized');
      }
      return res;
    });
  }

  function $(sel) { return document.querySelector(sel); }

  function fmtBytes(n) {
    if (!n && n !== 0) return '-';
    if (n < 1024) return n + ' B';
    var units = ['KB', 'MB', 'GB', 'TB', 'PB'];
    var v = n / 1024;
    var i = 0;
    while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
    return (v >= 100 ? v.toFixed(0) : v.toFixed(v >= 10 ? 1 : 2)) + ' ' + units[i];
  }

  function fmtSpeed(bps) {
    if (!bps || bps < 1) return '0 B/s';
    return fmtBytes(bps) + '/s';
  }

  function fmtTime(sec) {
    if (!isFinite(sec) || sec < 0) return '--';
    if (sec < 1) return '<1s';
    if (sec < 60) return Math.round(sec) + 's';
    if (sec < 3600) return Math.floor(sec / 60) + 'm ' + Math.round(sec % 60) + 's';
    return Math.floor(sec / 3600) + 'h ' + Math.round((sec % 3600) / 60) + 'm';
  }

  function fmtDate(ts) {
    var d = new Date(ts * 1000);
    var p = function (v) { return v < 10 ? '0' + v : '' + v; };
    return d.getFullYear() + '-' + p(d.getMonth() + 1) + '-' + p(d.getDate()) +
      ' ' + p(d.getHours()) + ':' + p(d.getMinutes());
  }

  function makeId() {
    return Date.now().toString(36) + Math.random().toString(36).slice(2, 10);
  }

  // ---------------- 上传 ----------------

  function enqueue(fileList) {
    var added = 0;
    for (var i = 0; i < fileList.length; i++) {
      var file = fileList[i];
      if (!file || !file.name) continue;
      var task = {
        id: makeId(),
        file: file,
        loaded: 0,
        speed: 0,
        status: 'queued',
        canceled: false,
        error: '',
        samples: [],
        index: 0,
        totalChunks: 0,
        xhr: null,
        el: null
      };
      state.tasks.push(task);
      renderTaskRow(task);
      added++;
    }
    if (!added) return;
    $('#queueCard').hidden = false;
    pump();
    window.setTimeout(function () {
      $('#queueCard').scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }, 60);
  }

  function pump() {
    var active = 0;
    for (var i = 0; i < state.tasks.length; i++) {
      if (state.tasks[i].status === 'uploading') active++;
    }
    var slots = MAX_PARALLEL - active;
    for (var j = 0; j < state.tasks.length && slots > 0; j++) {
      var t = state.tasks[j];
      if (t.status === 'queued' && !t.canceled) {
        startTask(t);
        slots--;
      }
    }
  }

  function startTask(task) {
    task.status = 'uploading';
    task.samples = [];
    task.index = 0;
    task.totalChunks = Math.max(1, Math.ceil(task.file.size / state.chunkSize));
    sendChunk(task);
  }

  function sendChunk(task) {
    if (task.canceled) return;
    if (task.index >= task.totalChunks) return finishTask(task);

    var start = task.index * state.chunkSize;
    var end = Math.min(task.file.size, start + state.chunkSize);
    var blob = task.file.slice(start, end);

    var url = authUrl('/api/upload?name=' + encodeURIComponent(task.file.name) +
      '&uid=' + encodeURIComponent(task.id) +
      '&index=' + task.index +
      '&total=' + task.totalChunks +
      '&size=' + task.file.size);

    var xhr = new XMLHttpRequest();
    task.xhr = xhr;
    xhr.open('POST', url, true);
    xhr.setRequestHeader('Content-Type', 'application/octet-stream');
    xhr.setRequestHeader('X-Auth-Token', state.token || '');

    xhr.upload.onprogress = function (e) {
      if (!e.lengthComputable) return;
      task.loaded = start + e.loaded;
    };
    xhr.onload = function () {
      if (task.canceled) return;
      if (xhr.status >= 200 && xhr.status < 300) {
        task.loaded = end;
        task.index += 1;
        sendChunk(task);
      } else {
        var msg = '上传失败（HTTP ' + xhr.status + '）';
        try {
          var data = JSON.parse(xhr.responseText);
          if (data && data.error) msg = data.error;
        } catch (err) { /* ignore */ }
        failTask(task, msg);
      }
    };
    xhr.onerror = function () {
      if (task.canceled) return;
      failTask(task, '网络错误');
    };
    xhr.onabort = function () { /* 取消时由 cancelTask 处理 */ };
    xhr.send(blob);
  }

  function finishTask(task) {
    task.status = 'done';
    task.loaded = task.file.size;
    task.speed = 0;
    task.xhr = null;
    updateTaskUI(task);
    pump();
    loadFiles();
    window.setTimeout(function () { removeTask(task); }, 4500);
  }

  function failTask(task, message) {
    task.status = 'error';
    task.error = message || '上传失败';
    task.speed = 0;
    task.xhr = null;
    updateTaskUI(task);
    pump();
  }

  function cancelTask(task) {
    if (task.status === 'done' || task.status === 'error' || task.status === 'canceled') return;
    task.canceled = true;
    if (task.xhr) {
      try { task.xhr.abort(); } catch (err) { /* ignore */ }
      task.xhr = null;
    }
    task.status = 'canceled';
    task.speed = 0;
    updateTaskUI(task);
    pump();
    window.setTimeout(function () { removeTask(task); }, 1500);
  }

  function removeTask(task) {
    task.canceled = true;
    if (task.el && task.el.row && task.el.row.parentNode) {
      task.el.row.parentNode.removeChild(task.el.row);
    }
    var idx = state.tasks.indexOf(task);
    if (idx >= 0) state.tasks.splice(idx, 1);
    if (!state.tasks.length) $('#queueCard').hidden = true;
  }

  // ---------------- 上传队列渲染 ----------------

  function renderTaskRow(task) {
    var row = document.createElement('div');
    row.className = 'task';

    var main = document.createElement('div');
    main.className = 'task-main';

    var top = document.createElement('div');
    top.className = 'task-top';
    var name = document.createElement('div');
    name.className = 'task-name';
    name.textContent = task.file.name;
    name.title = task.file.name;
    var status = document.createElement('span');
    status.className = 'task-status';
    top.appendChild(name);
    top.appendChild(status);

    var bar = document.createElement('div');
    bar.className = 'bar';
    var fill = document.createElement('i');
    bar.appendChild(fill);

    var meta = document.createElement('div');
    meta.className = 'task-meta';
    var left = document.createElement('span');
    var right = document.createElement('span');
    right.className = 'speed';
    meta.appendChild(left);
    meta.appendChild(right);

    main.appendChild(top);
    main.appendChild(bar);
    main.appendChild(meta);

    var cancel = document.createElement('button');
    cancel.type = 'button';
    cancel.className = 'icon-btn';
    cancel.title = '取消上传';
    cancel.innerHTML = '&times;';
    cancel.addEventListener('click', function () { cancelTask(task); });

    row.appendChild(main);
    row.appendChild(cancel);

    task.el = { row: row, fill: fill, status: status, left: left, right: right };
    $('#queue').appendChild(row);
    updateTaskUI(task);
  }

  function statusText(task) {
    if (task.status === 'queued') return '等待中';
    if (task.status === 'uploading') return '上传中';
    if (task.status === 'done') return '已完成';
    if (task.status === 'error') return '失败';
    return '已取消';
  }

  function updateTaskUI(task) {
    if (!task.el) return;
    var size = task.file.size;
    var pct = size > 0 ? (task.loaded / size) * 100 : (task.status === 'done' ? 100 : 0);
    if (task.status === 'done') pct = 100;
    if (pct > 100) pct = 100;

    task.el.fill.style.width = pct.toFixed(1) + '%';
    task.el.status.className = 'task-status ' + task.status;
    task.el.status.textContent = statusText(task);

    if (task.status === 'uploading') {
      task.el.left.textContent = fmtBytes(task.loaded) + ' / ' + fmtBytes(size) + ' · ' + pct.toFixed(0) + '%';
      var remain = task.speed > 0 ? (size - task.loaded) / task.speed : Infinity;
      task.el.right.textContent = fmtSpeed(task.speed) + (isFinite(remain) ? ' · 剩余 ' + fmtTime(remain) : '');
    } else if (task.status === 'done') {
      task.el.left.textContent = fmtBytes(size) + ' · 100%';
      task.el.right.textContent = '已保存';
    } else if (task.status === 'error') {
      task.el.left.textContent = fmtBytes(task.loaded) + ' / ' + fmtBytes(size);
      task.el.right.textContent = task.error;
    } else if (task.status === 'canceled') {
      task.el.left.textContent = fmtBytes(task.loaded) + ' / ' + fmtBytes(size);
      task.el.right.textContent = '已取消';
    } else {
      task.el.left.textContent = fmtBytes(size) + ' · 等待上传';
      task.el.right.textContent = '排队中';
    }
    var rowClass = 'task' + (task.status === 'done' ? ' done' : '') +
      (task.status === 'error' ? ' error' : '') +
      (task.status === 'canceled' ? ' canceled' : '');
    task.el.row.className = rowClass;
  }

  function tick() {
    var now = Date.now();
    var active = 0;
    var totalSpeed = 0;

    for (var i = 0; i < state.tasks.length; i++) {
      var t = state.tasks[i];
      if (t.status === 'uploading') {
        t.samples.push({ t: now, b: t.loaded });
        while (t.samples.length > 2 && now - t.samples[0].t > 1500) t.samples.shift();
        var first = t.samples[0];
        var last = t.samples[t.samples.length - 1];
        var dt = (last.t - first.t) / 1000;
        if (dt >= 0.4) {
          t.speed = Math.max(0, (last.b - first.b) / dt);
        }
        totalSpeed += t.speed;
        active++;
      }
      updateTaskUI(t);
    }

    var summary = '';
    if (active > 0) {
      summary = '正在上传 ' + active + ' 个 · ' + fmtSpeed(totalSpeed);
    } else if (state.tasks.length) {
      summary = '队列中 ' + state.tasks.length + ' 个任务';
    }
    $('#queueSummary').textContent = summary;
  }

  // ---------------- 文件列表 ----------------

  function loadFiles() {
    var btn = $('#refreshBtn');
    btn.disabled = true;
    authFetch('/api/files', { cache: 'no-store' })
      .then(function (res) { return res.json(); })
      .then(function (data) {
        state.files = data.files || [];
        renderFiles(data);
      })
      .catch(function () {
        $('#fileMeta').textContent = '刷新失败';
      })
      .then(function () {
        btn.disabled = false;
      });
  }

  function renderFiles(data) {
    var body = $('#fileBody');
    body.innerHTML = '';
    var files = state.files;
    var total = 0;
    for (var i = 0; i < files.length; i++) total += files[i].size;

    $('#fileMeta').textContent = files.length
      ? '共 ' + files.length + ' 个文件 · ' + fmtBytes(total)
      : '';
    $('#empty').hidden = files.length > 0;
    $('#fileTable').hidden = files.length === 0;

    for (var j = 0; j < files.length; j++) {
      body.appendChild(buildRow(files[j]));
    }
  }

  function buildRow(file) {
    var tr = document.createElement('tr');

    var tdName = document.createElement('td');
    tdName.className = 'cell-name';
    var cell = document.createElement('div');
    cell.className = 'file-cell';
    var icon = document.createElement('span');
    icon.className = 'file-icon';
    icon.innerHTML = '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/></svg>';
    var nm = document.createElement('span');
    nm.className = 'file-name';
    nm.textContent = file.name;
    nm.title = file.name;
    cell.appendChild(icon);
    cell.appendChild(nm);
    tdName.appendChild(cell);

    var tdSize = document.createElement('td');
    tdSize.className = 'size';
    tdSize.textContent = fmtBytes(file.size);

    var tdTime = document.createElement('td');
    tdTime.className = 'time col-time';
    tdTime.textContent = fmtDate(file.mtime);

    var tdAct = document.createElement('td');
    var actions = document.createElement('div');
    actions.className = 'actions';

    var download = document.createElement('a');
    download.className = 'act';
    download.href = authUrl('/download?name=' + encodeURIComponent(file.name));
    download.textContent = '下载';

    var del = document.createElement('button');
    del.type = 'button';
    del.className = 'act danger';
    del.textContent = '删除';
    del.addEventListener('click', function () { deleteFile(file.name, del); });

    actions.appendChild(download);
    actions.appendChild(del);
    tdAct.appendChild(actions);

    tr.appendChild(tdName);
    tr.appendChild(tdSize);
    tr.appendChild(tdTime);
    tr.appendChild(tdAct);
    return tr;
  }

  function deleteFile(name, btn) {
    if (!window.confirm('确定删除文件 “' + name + '” 吗？')) return;
    btn.disabled = true;
    authFetch('/api/delete', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: name })
    })
      .then(function (res) {
        return res.json().then(function (data) {
          return { ok: res.ok, data: data };
        });
      })
      .then(function (result) {
        if (!result.ok) {
          window.alert((result.data && result.data.error) || '删除失败');
          btn.disabled = false;
          return;
        }
        loadFiles();
      })
      .catch(function () {
        window.alert('删除失败：网络错误');
        btn.disabled = false;
      });
  }

  // ---------------- 初始化 ----------------

  function initDrag() {
    var drop = $('#drop');
    var picker = $('#picker');
    var depth = 0;

    ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(function (type) {
      document.addEventListener(type, function (e) {
        e.preventDefault();
        e.stopPropagation();
      }, false);
    });

    drop.addEventListener('dragenter', function (e) {
      e.preventDefault();
      depth++;
      drop.classList.add('drag');
    });
    drop.addEventListener('dragleave', function (e) {
      e.preventDefault();
      depth--;
      if (depth <= 0) { depth = 0; drop.classList.remove('drag'); }
    });
    drop.addEventListener('dragover', function (e) { e.preventDefault(); });
    drop.addEventListener('drop', function (e) {
      e.preventDefault();
      depth = 0;
      drop.classList.remove('drag');
      var files = e.dataTransfer && e.dataTransfer.files;
      if (files && files.length) enqueue(files);
    });

    drop.addEventListener('click', function () { picker.click(); });
    picker.addEventListener('click', function (e) {
      e.stopPropagation();
    });
    $('#pickBtn').addEventListener('click', function (e) {
      e.stopPropagation();
      picker.click();
    });
    picker.addEventListener('change', function () {
      if (picker.files && picker.files.length) enqueue(picker.files);
      picker.value = '';
    });
  }

  // ---------------- 目录切换 ----------------

  function initDirChip() {
    var chip = $('#dirChip');
    var code = $('#dirPath');
    var current = '';

    function setDisplay(path) {
      current = path || '';
      code.textContent = current || '未知';
      code.title = current;
    }

    function restore() {
      chip.classList.remove('editing');
      setDisplay(current);
    }

    function edit() {
      chip.classList.add('editing');
      code.innerHTML = '';

      var input = document.createElement('input');
      input.type = 'text';
      input.className = 'dir-input';
      input.value = current;
      input.placeholder = '输入服务器绝对路径，如 /data/files';
      input.spellcheck = false;

      var ok = document.createElement('button');
      ok.type = 'button';
      ok.className = 'dir-btn';
      ok.textContent = '确定';

      var cancel = document.createElement('button');
      cancel.type = 'button';
      cancel.className = 'dir-btn';
      cancel.textContent = '取消';

      code.appendChild(input);
      code.appendChild(ok);
      code.appendChild(cancel);
      input.focus();
      input.select();

      function save() {
        var value = input.value.replace(/^\s+|\s+$/g, '');
        if (!value || value === current) { restore(); return; }
        ok.disabled = true;
        authFetch('/api/setdir', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ dir: value })
        })
          .then(function (res) {
            return res.json().then(function (data) { return { ok: res.ok, data: data }; });
          })
          .then(function (result) {
            if (!result.ok) {
              window.alert((result.data && result.data.error) || '修改失败');
              ok.disabled = false;
              return;
            }
            chip.classList.remove('editing');
            setDisplay(result.data.dir || value);
            loadFiles();
          })
          .catch(function () {
            window.alert('修改失败：网络错误');
            ok.disabled = false;
          });
      }

      ok.addEventListener('click', function (e) { e.stopPropagation(); save(); });
      cancel.addEventListener('click', function (e) { e.stopPropagation(); restore(); });
      input.addEventListener('click', function (e) { e.stopPropagation(); });
      input.addEventListener('keydown', function (e) {
        e.stopPropagation();
        if (e.key === 'Enter') save();
        if (e.key === 'Escape') restore();
      });
    }

    chip.addEventListener('click', function () {
      if (code.querySelector('input')) return;
      edit();
    });

    return { set: setDisplay };
  }

  // ---------------- 登录 ----------------

  function showLogin() {
    state.token = '';
    try { window.localStorage.removeItem(TOKEN_KEY); } catch (err) { /* ignore */ }
    var mask = $('#loginMask');
    mask.hidden = false;
    $('#logoutBtn').hidden = true;
    $('#passwdBtn').hidden = true;
    $('#loginPass').value = '';
    $('#loginCap').value = '';
    $('#loginErr').hidden = true;
    refreshCaptcha();
    window.setTimeout(function () { $('#loginUser').focus(); }, 50);
  }

  function hideLogin() {
    $('#loginMask').hidden = true;
    $('#logoutBtn').hidden = false;
    $('#passwdBtn').hidden = false;
  }

  function refreshCaptcha() {
    state.cid = makeId();
    $('#capImg').src = '/api/captcha?cid=' + encodeURIComponent(state.cid) + '&r=' + Date.now();
  }

  function showLoginError(message) {
    var err = $('#loginErr');
    err.textContent = message;
    err.hidden = false;
    refreshCaptcha();
  }

  function bootstrap(dirChip) {
    authFetch('/api/info', { cache: 'no-store' })
      .then(function (res) { return res.json(); })
      .then(function (info) {
        dirChip.set(info.dir);
        if (info.chunk_size) {
          state.chunkSize = info.chunk_size;
          $('#chunkTip').textContent = '大文件自动按 ' + fmtBytes(info.chunk_size) + ' 分片上传';
        }
        setSvc(true, info.uptime);
      })
      .catch(function () {
        dirChip.set('');
      })
      .then(function () {
        if (!state.token) return; // 401 已跳转登录页
        loadFiles();
        hideLogin();
      });
  }

  function initLogin(dirChip) {
    $('#capImg').addEventListener('click', refreshCaptcha);

    $('#loginForm').addEventListener('submit', function (e) {
      e.preventDefault();
      var user = $('#loginUser').value.replace(/^\s+|\s+$/g, '');
      var password = $('#loginPass').value;
      var captcha = $('#loginCap').value.replace(/^\s+|\s+$/g, '');
      if (!user || !password || !captcha) {
        showLoginError('请填写用户名、密码和验证码');
        return;
      }
      fetch('/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ user: user, password: password, cid: state.cid, captcha: captcha })
      })
        .then(function (res) {
          return res.json().then(function (data) {
            return { status: res.status, ok: res.ok, data: data };
          });
        })
        .then(function (result) {
          if (!result.ok) {
            showLoginError((result.data && result.data.error) ||
              ('登录失败（HTTP ' + result.status + '）'));
            return;
          }
          state.token = result.data.token;
          try { window.localStorage.setItem(TOKEN_KEY, state.token); } catch (err) { /* ignore */ }
          bootstrap(dirChip);
        })
        .catch(function () {
          showLoginError('登录失败：无法连接服务器，请确认服务正在运行');
        });
    });

    $('#loginCap').addEventListener('keydown', function (e) {
      if (e.key === 'Enter') {
        e.preventDefault();
        $('#loginForm').dispatchEvent(new Event('submit', { cancelable: true }));
      }
    });

    $('#logoutBtn').addEventListener('click', function () {
      authFetch('/api/logout', { method: 'POST' }).catch(function () { /* ignore */ });
      state.files = [];
      renderFiles({});
      showLogin();
    });

    // 已有会话则直接进入，否则弹出登录遮罩
    var saved = '';
    try { saved = window.localStorage.getItem(TOKEN_KEY) || ''; } catch (err) { /* ignore */ }
    if (saved) {
      state.token = saved;
      authFetch('/api/info', { cache: 'no-store' })
        .then(function () { bootstrap(dirChip); })
        .catch(function () { /* 401 时 showLogin 已被 authFetch 触发 */ });
    } else {
      showLogin();
    }
  }

  // ---------------- 修改账号密码 ----------------

  function initPasswd() {
    var mask = $('#pwdMask');
    var err = $('#pwdErr');

    function showErr(message) {
      err.textContent = message;
      err.hidden = false;
    }

    $('#passwdBtn').addEventListener('click', function () {
      err.hidden = true;
      $('#pwdOld').value = '';
      $('#pwdNew').value = '';
      $('#pwdNew2').value = '';
      $('#pwdUser').value = '';
      mask.hidden = false;
      window.setTimeout(function () { $('#pwdOld').focus(); }, 50);
    });

    $('#pwdCancel').addEventListener('click', function () {
      mask.hidden = true;
    });

    $('#pwdForm').addEventListener('submit', function (e) {
      e.preventDefault();
      var oldPwd = $('#pwdOld').value;
      var newUser = $('#pwdUser').value.replace(/^\s+|\s+$/g, '');
      var p1 = $('#pwdNew').value;
      var p2 = $('#pwdNew2').value;
      if (!oldPwd) { showErr('请输入当前密码'); return; }
      if (p1.length < 6) { showErr('新密码至少需要 6 位'); return; }
      if (p1 !== p2) { showErr('两次输入的新密码不一致'); return; }
      authFetch('/api/passwd', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ old_password: oldPwd, new_user: newUser, new_password: p1 })
      })
        .then(function (res) {
          return res.json().then(function (data) { return { ok: res.ok, data: data }; });
        })
        .then(function (result) {
          if (!result.ok) {
            showErr((result.data && result.data.error) || '修改失败');
            return;
          }
          mask.hidden = true;
          window.alert('修改成功' + (result.data.persisted === false ? '，但持久化失败' : '') +
            '。' + (result.data.user ? '当前用户名：' + result.data.user + '，' : '') +
            '下次登录请使用新账号密码。');
        })
        .catch(function () {
          showErr('修改失败：网络错误');
        });
    });
  }

  // ---------------- 时钟 / 服务状态 / 侧边导航 ----------------

  function pad2(n) { return n < 10 ? '0' + n : '' + n; }

  function initClock() {
    var el = $('#clock');
    var WEEK = ['日', '一', '二', '三', '四', '五', '六'];
    function tickClock() {
      var d = new Date();
      el.textContent = d.getFullYear() + '-' + pad2(d.getMonth() + 1) + '-' + pad2(d.getDate()) +
        ' ' + pad2(d.getHours()) + ':' + pad2(d.getMinutes()) + ':' + pad2(d.getSeconds()) +
        ' 星期' + WEEK[d.getDay()];
    }
    tickClock();
    window.setInterval(tickClock, 1000);
  }

  function fmtUptime(s) {
    s = Math.max(0, Math.floor(s));
    var d = Math.floor(s / 86400);
    var h = Math.floor((s % 86400) / 3600);
    var m = Math.floor((s % 3600) / 60);
    if (d) return d + ' 天 ' + h + ' 小时';
    if (h) return h + ' 小时 ' + m + ' 分钟';
    return Math.max(1, m) + ' 分钟';
  }

  function setSvc(ok, uptime) {
    $('#svcDot').className = 'dot ' + (ok ? 'on' : 'off');
    $('#svcText').textContent = ok ? '服务运行中' : '连接失败';
    $('#svcStatus').title = ok && uptime != null ? '已连续运行 ' + fmtUptime(uptime) : '';
  }

  function pollStatus() {
    if (!state.token) return;
    authFetch('/api/info', { cache: 'no-store' })
      .then(function (res) { return res.json(); })
      .then(function (info) { setSvc(true, info.uptime); })
      .catch(function () { setSvc(false); });
  }

  function initNav() {
    var items = document.querySelectorAll('.nav-item');
    Array.prototype.forEach.call(items, function (item) {
      item.addEventListener('click', function (e) {
        e.preventDefault();
        Array.prototype.forEach.call(items, function (i) { i.classList.remove('active'); });
        item.classList.add('active');
        var el = document.getElementById(item.getAttribute('data-target'));
        if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' });
      });
    });
  }

  function init() {
    initDrag();
    var dirChip = initDirChip();
    $('#refreshBtn').addEventListener('click', loadFiles);
    initLogin(dirChip);
    initPasswd();
    initClock();
    initNav();
    window.setInterval(pollStatus, 30000);

    window.setInterval(tick, 250);
  }

  init();
})();
</script>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# 启动
# ---------------------------------------------------------------------------

def reset_password_cli():
    """忘记密码时的交互式找回：直接更新状态文件中的账号与密码哈希"""
    import getpass

    try:
        read_input = raw_input  # noqa: F821 - Python 2
    except NameError:
        read_input = input

    print('=' * 58)
    print('重置登录账号 / 密码（忘记密码时的找回方式）')
    print('状态文件 : %s' % STATE_FILE)
    print('=' * 58)

    user = read_input('登录用户名 [admin]: ').strip() or 'admin'
    while True:
        pw1 = getpass.getpass('新密码（至少 6 位）: ')
        if len(pw1) >= 6:
            break
        print('密码太短，请至少输入 6 位')
        if not pw1:
            break
    if len(pw1) < 6:
        print('已取消：密码未修改')
        return
    pw2 = getpass.getpass('确认新密码: ')
    if pw1 != pw2:
        print('已取消：两次输入的密码不一致')
        return

    data = load_state()
    data['user'] = user
    data['pwd_hash'] = hash_password(pw1)
    try:
        body = json.dumps(data, ensure_ascii=False)
        if not isinstance(body, bytes):
            body = body.encode('utf-8')
        with open(STATE_FILE, 'wb') as fp:
            fp.write(body)
    except (IOError, OSError) as exc:
        print('写入状态文件失败：%s' % exc)
        sys.exit(1)
    print('已重置。请重启服务使其生效：./start.sh restart')


def main():
    global UPLOAD_DIR, TMP_DIR, CHUNK_SIZE, MAX_CHUNK

    parser = argparse.ArgumentParser(description='文件上传服务（Python 2.7）')
    parser.add_argument('--dir', '-d', default=os.environ.get('UPLOAD_DIR', '/file'),
                        help='上传目录，默认 /file')
    parser.add_argument('--host', default='0.0.0.0', help='监听地址，默认 0.0.0.0')
    parser.add_argument('--port', '-p', type=int, default=8000, help='监听端口，默认 8000')
    parser.add_argument('--chunk-size', type=int,
                        default=int(os.environ.get('UPLOAD_CHUNK_MB', '8')),
                        help='分片大小（MB），默认 8')
    parser.add_argument('--user', default=os.environ.get('AUTH_USER', 'admin'),
                        help='登录用户名，默认 admin')
    parser.add_argument('--password', default=os.environ.get('AUTH_PASSWORD', 'Kingsha@2026'),
                        help='登录密码，默认 Kingsha@2026')
    parser.add_argument('--reset-password', action='store_true',
                        help='忘记密码时重置账号密码（交互式，改完需重启服务）')
    args = parser.parse_args()

    global AUTH_USER, AUTH_PASSWORD
    AUTH_USER = args.user
    AUTH_PASSWORD = args.password

    if args.reset_password:
        reset_password_cli()
        return

    # 状态文件里已自定义账号/密码时优先使用（页面改密或 CLI 重置的结果）
    state = load_state()
    saved_user = state.get('user') or ''
    saved_hash = state.get('pwd_hash') or ''
    if isinstance(saved_user, bytes):
        saved_user = saved_user.decode('utf-8', 'replace')
    if isinstance(saved_hash, bytes):
        saved_hash = saved_hash.decode('utf-8', 'replace')
    if saved_user and saved_hash and saved_hash.startswith('sha256$'):
        global AUTH_HASH
        AUTH_USER = saved_user
        AUTH_HASH = saved_hash

    CHUNK_SIZE = max(1, args.chunk_size) * 1024 * 1024
    MAX_CHUNK = CHUNK_SIZE + 1024 * 1024

    default_dir = os.path.abspath(args.dir)
    if not isinstance(default_dir, bytes):
        default_dir = default_dir.encode(sys.getfilesystemencoding() or 'utf-8')

    # 目录切换持久化：优先使用上次保存的目录，无效时回退到启动参数指定的目录
    saved = load_saved_dir()
    UPLOAD_DIR = saved if saved else default_dir
    TMP_DIR = os.path.join(UPLOAD_DIR, b'.tmp')

    try:
        if not os.path.isdir(UPLOAD_DIR):
            os.makedirs(UPLOAD_DIR)
        if not os.path.isdir(TMP_DIR):
            os.makedirs(TMP_DIR)
    except OSError as exc:
        sys.stderr.write('无法创建上传目录 %s：%s\n' % (UPLOAD_DIR, exc))
        sys.exit(1)

    cleanup_tmp()

    server = ThreadedHTTPServer((args.host, args.port), UploadHandler)
    sys.stdout.write('=' * 58 + '\n')
    sys.stdout.write('文件上传服务已启动\n')
    sys.stdout.write('  访问地址 : http://%s:%d/\n' % (
        '127.0.0.1' if args.host == '0.0.0.0' else args.host, args.port))
    sys.stdout.write('  上传目录 : ' + log_text(UPLOAD_DIR) + '\n')
    if saved:
        sys.stdout.write('  （已恢复上次保存的目录，--dir %s 未生效）\n' % log_text(default_dir))
    sys.stdout.write('  分片大小 : %d MB\n' % (CHUNK_SIZE / 1024 / 1024))
    sys.stdout.write('  停止服务 : Ctrl + C\n')
    sys.stdout.write('=' * 58 + '\n')
    sys.stdout.flush()

    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        sys.stdout.write('\n正在关闭服务…\n')
    finally:
        server.server_close()


if __name__ == '__main__':
    main()

# -*- coding: utf-8 -*-
"""
校园以太网自动登录助手  CampusNetLogin
======================================
开机自动连接校园网（Portal / Web 认证），零第三方依赖，仅使用 Python 标准库。

分区索引
--------
[0] 常量与路径            [1] 密码保护 (Windows DPAPI)
[2] 配置读写              [3] 日志
[4] 联网与认证状态检测    [5] 登录页表单解析
[6] Portal 认证适配器     [7] 认证服务编排（连接/断开/重试）
[8] 开机自启动            [9] 命令行入口
[10] 图形控制面板         [11] main()

安全说明
--------
配置文件中的密码字段 `password_enc` 使用 Windows DPAPI（CryptProtectData）加密，
密钥由操作系统绑定当前用户账户派生，密文只有在本机、本用户下才能解密。
源码中不含任何明文账号密码，配置文件被拷贝到其他电脑也无法还原。
"""

from __future__ import annotations

import argparse
import base64
import ctypes
import gzip
import http.client
import http.cookiejar
import json
import logging
import logging.handlers
import os
import queue
import re
import socket
import ssl
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid
import webbrowser
import zlib
from html.parser import HTMLParser
from urllib.parse import (parse_qsl, quote, unquote, urlencode, urljoin,
                          urlparse)

# tkinter 只在图形界面时才必须存在；命令行模式（--connect/--status/--probe）不需要。
# 某些精简版 Python（如 WorkBuddy 自带的受管解释器）没有 tkinter，这里做成可选导入，
# 以免整个程序连命令行都用不了。
try:
    import tkinter as tk
    _TK_CANVAS = tk.Canvas
    HAS_TKINTER = True
except Exception:                                   # pragma: no cover
    tk = None
    _TK_CANVAS = object
    HAS_TKINTER = False

APP_NAME = "CampusNetAutoLogin"
APP_TITLE = "校园网自动登录助手"
APP_VERSION = "1.0.0"

IS_WINDOWS = os.name == "nt"
IS_FROZEN = bool(getattr(sys, "frozen", False))

# 探测点：key = 探测地址，value = 期望命中的内容（空串表示只要求 HTTP 204/200）
DEFAULT_PROBES = [
    ("http://www.msftconnecttest.com/connecttest.txt", "Microsoft Connect Test"),
    ("http://connect.rom.miui.com/generate_204", ""),
]

# Portal 页面的典型特征词，用于区分「被劫持到认证页」和「真的联网了」
PORTAL_HINTS = [
    "eportal", "srun_portal", "srun_portal_pc", "drcom", "interFace.do",
    "wlanuserip", "wlanacname", "portal", "认证", "登录", "请先登录",
    "上网登录", "上网认证", "ac_id",
]

USER_AGENT = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/120.0 Safari/537.36")


# ============================================================================
# [0] 常量与路径
# ============================================================================

def app_dir() -> str:
    """程序所在目录（打包成 exe 后即 exe 所在目录）。"""
    if IS_FROZEN:
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.abspath(__file__))


def data_dir() -> str:
    """
    数据目录：优先放在程序目录下（用户看得见、便于手动改配置）。
    若程序目录不可写（如放在只读位置），回退到 %LOCALAPPDATA%。
    """
    cand = app_dir()
    try:
        probe = os.path.join(cand, ".write_test")
        with open(probe, "w", encoding="utf-8") as f:
            f.write("ok")
        os.remove(probe)
        return cand
    except Exception:
        base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
        d = os.path.join(base, APP_NAME)
        os.makedirs(d, exist_ok=True)
        return d


def config_file() -> str:
    return os.path.join(data_dir(), "config.json")


def log_file() -> str:
    return os.path.join(data_dir(), "logs", "campus_login.log")


def log_dir() -> str:
    return os.path.join(data_dir(), "logs")


# ============================================================================
# [1] 密码保护 —— Windows DPAPI
# ============================================================================
# 使用 ctypes 直接调用 crypt32.dll，无需 pywin32。
# 非 Windows 环境自动降级为「机器无关的混淆存储」并在日志中给出警告。

class _DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", ctypes.c_uint32), ("pbData", ctypes.c_void_p)]


_ENTROPY = b"CampusNetLogin::v1::local-only"

_crypt32 = None
_kernel32 = None


def _init_dpapi() -> bool:
    """初始化 DPAPI 函数签名。返回是否可用。"""
    global _crypt32, _kernel32
    if _crypt32 is not None:
        return True
    if not IS_WINDOWS:
        return False
    try:
        from ctypes import wintypes
        _crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
        _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

        _crypt32.CryptProtectData.argtypes = [
            ctypes.POINTER(_DATA_BLOB), ctypes.c_wchar_p,
            ctypes.POINTER(_DATA_BLOB), ctypes.c_void_p, ctypes.c_void_p,
            ctypes.c_uint32, ctypes.POINTER(_DATA_BLOB)]
        _crypt32.CryptProtectData.restype = ctypes.c_int

        _crypt32.CryptUnprotectData.argtypes = [
            ctypes.POINTER(_DATA_BLOB), ctypes.POINTER(ctypes.c_wchar_p),
            ctypes.POINTER(_DATA_BLOB), ctypes.c_void_p, ctypes.c_void_p,
            ctypes.c_uint32, ctypes.POINTER(_DATA_BLOB)]
        _crypt32.CryptUnprotectData.restype = ctypes.c_int

        _kernel32.LocalFree.argtypes = [ctypes.c_void_p]
        _kernel32.LocalFree.restype = ctypes.c_void_p
        return True
    except Exception:
        _crypt32 = None
        return False


def _blob_from_bytes(data: bytes):
    """构造 DATA_BLOB，并返回缓冲区引用防止被 GC 回收。"""
    size = max(1, len(data))                # create_string_buffer 不接受 size=0
    buf = ctypes.create_string_buffer(data, size)
    blob = _DATA_BLOB(len(data), ctypes.cast(buf, ctypes.c_void_p))
    return blob, buf


def _blob_bytes(blob: _DATA_BLOB) -> bytes:
    return ctypes.string_at(blob.pbData, blob.cbData)


def _fallback_mask(data: bytes) -> bytes:
    """非 Windows 降级方案的密钥流（仅混淆，不等价于加密）。"""
    key = b"CampusNetLogin-fallback-key"
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def protect(plain: str) -> str:
    """
    把明文密码转成可落盘的密文串。
    Windows 下返回 "dpapi:<base64>"；其他平台返回 "mask:<base64>"。
    """
    if plain is None:
        plain = ""
    raw = plain.encode("utf-8")
    if _init_dpapi():
        in_blob, _keep1 = _blob_from_bytes(raw)
        ent_blob, _keep2 = _blob_from_bytes(_ENTROPY)
        out_blob = _DATA_BLOB()
        ok = _crypt32.CryptProtectData(
            ctypes.byref(in_blob), APP_NAME, ctypes.byref(ent_blob),
            None, None, 0, ctypes.byref(out_blob))
        if not ok:
            err = ctypes.get_last_error()
            raise OSError(f"CryptProtectData 失败 (WinError {err})")
        try:
            return "dpapi:" + base64.b64encode(_blob_bytes(out_blob)).decode("ascii")
        finally:
            _kernel32.LocalFree(out_blob.pbData)
    return "mask:" + base64.b64encode(_fallback_mask(raw)).decode("ascii")


def unprotect(token: str) -> str:
    """还原 protect() 生成的密文串；解析失败返回空串而不抛异常。"""
    if not token or not isinstance(token, str):
        return ""
    try:
        if token.startswith("dpapi:"):
            if not _init_dpapi():
                return ""
            raw = base64.b64decode(token[6:])
            in_blob, _keep1 = _blob_from_bytes(raw)
            ent_blob, _keep2 = _blob_from_bytes(_ENTROPY)
            out_blob = _DATA_BLOB()
            descr = ctypes.c_wchar_p()
            ok = _crypt32.CryptUnprotectData(
                ctypes.byref(in_blob), ctypes.byref(descr),
                ctypes.byref(ent_blob), None, None, 0, ctypes.byref(out_blob))
            if not ok:
                return ""
            try:
                return _blob_bytes(out_blob).decode("utf-8", "replace")
            finally:
                _kernel32.LocalFree(out_blob.pbData)
                if descr:
                    _kernel32.LocalFree(descr)
        if token.startswith("mask:"):
            raw = base64.b64decode(token[5:])
            return _fallback_mask(raw).decode("utf-8", "replace")
        # 兼容用户手填的 v1 明文前缀（不推荐，仅作过渡）
        if token.startswith("plain:"):
            return token[6:]
    except Exception:
        return ""
    return ""


def crypto_backend() -> str:
    return "Windows DPAPI (CryptProtectData)" if _init_dpapi() else "降级混淆(非 Windows)"


# ============================================================================
# [2] 配置读写
# ============================================================================

DEFAULT_CONFIG = {
    "version": 1,
    "_说明": "校园网登录配置。密码字段 password_enc 为加密后的密文，请勿手工填写明文。",

    "auth": {
        "login_url": "",
        "username": "",
        "password_enc": "",
        "adapter": "auto",
        "logout_url": "",
        "encoding": "utf-8",
        "custom": {
            "method": "POST",
            "url": "",
            "params": {"username": "{username}", "password": "{password}"},
            "headers": {},
            "success_keywords": [],
            "failure_keywords": []
        }
    },

    "network": {
        "probes": [list(p) for p in DEFAULT_PROBES],
        "timeout": 8,
        "retry": 3,
        "retry_interval": 6,
        "startup_wait": 180,
        "watch_interval": 45
    },

    "autostart": {
        "enabled": False,
        "delay": 5,               # 开机后多久开始尝试（秒）—— 抢时间，别让用户等
        "args": "--startup",
        "hard_retry_seconds": 900,  # 开机后最长坚持多久（秒）；期间反复重试直到联网
        "hard_retry_interval": 15   # 每轮失败后的间隔（秒）
    },

    "advanced": {
        "verify_by_recheck": True,
        "open_login_page_on_failure": False
    }
}


def _deep_merge(base: dict, patch: dict) -> dict:
    """把 patch 合并进 base 的副本，缺的键用 base 的默认值补齐。"""
    out = dict(base)
    for k, v in (patch or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def default_config() -> dict:
    return json.loads(json.dumps(DEFAULT_CONFIG))  # 深拷贝


def load_config(create_if_missing: bool = True) -> dict:
    path = config_file()
    if not os.path.exists(path):
        cfg = default_config()
        if create_if_missing:
            try:
                save_config(cfg)
            except Exception:
                pass
        return cfg
    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = json.load(f)
        return _deep_merge(DEFAULT_CONFIG, raw)
    except Exception:
        # 配置损坏时保留原文件，另存一份备份供排查
        try:
            os.replace(path, path + ".broken")
        except Exception:
            pass
        return default_config()


def save_config(cfg: dict) -> None:
    path = config_file()
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)


def get_password(cfg: dict) -> str:
    """读取密码：环境变量 CAMPUS_PWD 优先，其次配置文件密文。"""
    env = os.environ.get("CAMPUS_PWD")
    if env:
        return env
    return unprotect(cfg.get("auth", {}).get("password_enc", ""))


def set_password(cfg: dict, plain: str) -> None:
    cfg.setdefault("auth", {})["password_enc"] = protect(plain)


# ============================================================================
# [3] 日志
# ============================================================================

_logger: logging.Logger | None = None


def setup_logging(level: int = logging.INFO) -> logging.Logger:
    global _logger
    if _logger is not None:
        return _logger
    logger = logging.getLogger(APP_NAME)
    logger.setLevel(logging.DEBUG)
    logger.propagate = False
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s",
                            "%Y-%m-%d %H:%M:%S")
    try:
        os.makedirs(log_dir(), exist_ok=True)
        fh = logging.handlers.RotatingFileHandler(
            log_file(), maxBytes=1_000_000, backupCount=3, encoding="utf-8")
        fh.setFormatter(fmt)
        fh.setLevel(logging.DEBUG)
        logger.addHandler(fh)
    except Exception:
        pass
    if sys.stderr is not None:                 # pythonw 下 stderr 为 None
        sh = logging.StreamHandler()
        sh.setFormatter(fmt)
        sh.setLevel(level)
        logger.addHandler(sh)
    if not logger.handlers:                    # 极端兜底：至少不丢日志
        logger.addHandler(logging.NullHandler())
    _logger = logger
    return logger


def log() -> logging.Logger:
    return _logger if _logger is not None else setup_logging()


def read_log_tail(lines: int = 400) -> str:
    """读取日志尾部，供界面展示。"""
    path = log_file()
    if not os.path.exists(path):
        return "（暂无日志）"
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            data = f.readlines()
        return "".join(data[-lines:]) or "（暂无日志）"
    except Exception as e:
        return f"（读取日志失败：{e}）"


# ============================================================================
# [4] 联网与认证状态检测
# ============================================================================

ST_ONLINE = "online"      # 已联网且已通过认证
ST_PORTAL = "portal"      # 网络可通，但被重定向到认证页（未认证）
ST_OFFLINE = "offline"    # 网络不通（链路/DNS/网关异常）
ST_UNKNOWN = "unknown"

ST_TEXT = {
    ST_ONLINE: "已连接 · 已通过认证",
    ST_PORTAL: "未认证 · 需要登录",
    ST_OFFLINE: "网络不通",
    ST_UNKNOWN: "状态未知",
}


class HttpResult:
    def __init__(self, status=0, body="", headers=None, final_url="", error=""):
        self.status = status
        self.body = body
        self.headers = headers or {}
        self.final_url = final_url
        self.error = error


def _split_url(url: str):
    """
    拆出 (parse 结果, 用于请求行的 request-target)。

    注意：这里不能用 urlunparse 拼 —— urlunparse 的第 4 位是 params、
    第 5 位才是 query，参数位置一错就会把 "?method=login" 拼成
    ";method=login"，服务器解析不到 method，直接返回
    "Error code: 203 Bad request(2)"。手工拼装最稳妥。
    """
    u = urlparse(url)
    path = u.path or "/"
    if u.query:
        path = f"{path}?{u.query}"
    return u, path


def _decompress_bytes(raw: bytes, headers: dict) -> bytes:
    """
    按 Content-Encoding 解压响应体。

    实测本校门户会把 `a41.js` 以 gzip 返回（`Content-Encoding: gzip`），
    不解压拿到的就是一坨二进制乱码，抓下来的脚本根本没法看。
    """
    ce = ((headers or {}).get("content-encoding") or "").lower()
    if not ce or "identity" in ce:
        return raw
    try:
        if "gzip" in ce or "x-gzip" in ce:
            return gzip.decompress(raw)
        if "deflate" in ce:
            try:
                return zlib.decompress(raw)
            except zlib.error:
                return zlib.decompress(raw, -zlib.MAX_WBITS)
        # br 之类标准库没有，原样返回
    except Exception:                       # noqa: BLE001
        return raw
    return raw


def _decode_body(raw: bytes, content_type: str = "", default: str = "utf-8") -> str:
    """
    按响应声明的 charset 解码。

    校园门户大量使用 gb2312/gbk（Dr.COM 尤其如此）。若一律按 utf-8 解，
    中文会整片变成替换字符，页面里的提示与报错都读不出来。
    """
    m = re.search(r"charset\s*=\s*[\"']?([\w.-]+)", content_type or "", re.I)
    tries = []
    if m:
        tries.append(m.group(1))
    tries.extend([default, "utf-8", "gbk"])
    best, best_bad = None, None
    for e in tries:
        if not e:
            continue
        try:
            t = raw.decode({"gb2312": "gbk", "gb-2312": "gbk"}.get(e.lower(), e), "replace")
        except LookupError:
            continue
        bad = t.count("\ufffd")
        if best_bad is None or bad < best_bad:
            best, best_bad = t, bad
        if bad == 0:
            break
    return best if best is not None else raw.decode("utf-8", "replace")


def _b64(text: str) -> str:
    """门户脚本里的 util.base64encode（对 ASCII 等价于标准 base64）。"""
    try:
        return base64.b64encode((text or "").encode("utf-8")).decode("ascii")
    except Exception:                            # noqa: BLE001
        return ""


def _local_mac() -> str:
    """取本机 MAC（形如 AABBCCDDEEFF），取不到返回空串。"""
    try:
        n = uuid.getnode()
        return "".join(f"{(n >> (8 * i)) & 0xFF:02X}" for i in range(5, -1, -1))
    except Exception:                            # noqa: BLE001
        return ""


def http_get(url: str, timeout: float = 8.0, headers: dict | None = None,
             max_redirect: int = 0, encoding: str = "utf-8") -> HttpResult:
    """
    手动实现 HTTP(S) GET。max_redirect=0 表示不跟随重定向，
    这样可以拿到认证服务器的 302 Location（里面通常带着 wlanuserip 等参数）。
    """
    hdrs = {"User-Agent": USER_AGENT, "Accept": "*/*",
            "Connection": "close", "Cache-Control": "no-cache"}
    if headers:
        hdrs.update(headers)

    cur = url
    for _ in range(max_redirect + 1):
        u, path = _split_url(cur)
        if u.scheme not in ("http", "https") or not u.hostname:
            return HttpResult(error=f"非法地址：{cur}")
        ctx = None
        if u.scheme == "https":
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        conn_cls = http.client.HTTPSConnection if u.scheme == "https" else http.client.HTTPConnection
        conn = None
        try:
            conn = conn_cls(u.hostname, u.port, timeout=timeout, context=ctx) \
                if ctx else conn_cls(u.hostname, u.port, timeout=timeout)
            conn.request("GET", path, headers=hdrs)
            resp = conn.getresponse()
            body = resp.read()
            status = resp.status
            hdr = {k.lower(): v for k, v in resp.getheaders()}
            body = _decompress_bytes(body, hdr)
        except (socket.timeout, TimeoutError):
            return HttpResult(error="连接超时")
        except socket.gaierror as e:
            return HttpResult(error=f"DNS 解析失败：{e}")
        except (ConnectionError, OSError) as e:
            return HttpResult(error=f"网络不可达：{e}")
        except Exception as e:
            return HttpResult(error=f"请求异常：{e}")
        finally:
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass

        if status in (301, 302, 303, 307, 308) and hdr.get("location"):
            loc = urljoin(cur, hdr["location"])
            if max_redirect == 0:
                return HttpResult(status=status, body=body, headers=hdr,
                                  final_url=loc)
            cur = loc
            continue
        try:
            text = body.decode(encoding, "replace")
        except Exception:
            text = body.decode("utf-8", "replace")
        return HttpResult(status=status, body=text, headers=hdr, final_url=cur)
    return HttpResult(error="重定向次数过多")


def http_post(url: str, data: str, timeout: float = 8.0,
              headers: dict | None = None, encoding: str = "utf-8") -> HttpResult:
    hdrs = {"User-Agent": USER_AGENT, "Accept": "*/*",
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
            "Connection": "close"}
    if headers:
        hdrs.update(headers)
    u, path = _split_url(url)
    if not u.hostname:
        return HttpResult(error=f"非法地址：{url}")
    ctx = None
    if u.scheme == "https":
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    conn_cls = http.client.HTTPSConnection if u.scheme == "https" else http.client.HTTPConnection
    conn = None
    try:
        conn = conn_cls(u.hostname, u.port, timeout=timeout, context=ctx) \
            if ctx else conn_cls(u.hostname, u.port, timeout=timeout)
        body_bytes = data.encode(encoding, "replace")
        conn.request("POST", path, body=body_bytes, headers=hdrs)
        resp = conn.getresponse()
        body = resp.read()
        _hdr = {k.lower(): v for k, v in resp.getheaders()}
        body = _decompress_bytes(body, _hdr)
        return HttpResult(status=resp.status,
                          body=_decode_body(body, _hdr.get("content-type", ""), encoding),
                          headers=_hdr,
                          final_url=url)
    except (socket.timeout, TimeoutError):
        return HttpResult(error="提交超时")
    except socket.gaierror as e:
        return HttpResult(error=f"DNS 解析失败：{e}")
    except (ConnectionError, OSError) as e:
        return HttpResult(error=f"网络不可达：{e}")
    except Exception as e:
        return HttpResult(error=f"请求异常：{e}")
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass


def _looks_like_portal(body: str, location: str = "") -> bool:
    """判断响应体/重定向目标是否是认证页。"""
    blob = (body or "")[:20000].lower()
    loc = (location or "").lower()
    for hint in PORTAL_HINTS:
        if hint.lower() in loc:
            return True
    # 正文需要更强的证据，避免普通网页里的 "login" 误判
    strong = ["srun_portal", "eportal", "interface.do", "wlanuserip",
              "上网登录", "上网认证", "请先登录", "认证", "ac_id="]
    return any(k in blob for k in strong)


class NetStatus:
    def __init__(self, state: str, detail: str = "", portal_url: str = "",
                 latency_ms: int = 0, checked_at: float = 0.0):
        self.state = state
        self.detail = detail
        self.portal_url = portal_url
        self.latency_ms = latency_ms
        self.checked_at = checked_at or time.time()

    @property
    def text(self) -> str:
        return ST_TEXT.get(self.state, "状态未知")

    def as_dict(self) -> dict:
        return {"state": self.state, "text": self.text, "detail": self.detail,
                "portal_url": self.portal_url, "latency_ms": self.latency_ms,
                "checked_at": self.checked_at}


def check_network(cfg: dict, quick: bool = False) -> NetStatus:
    """
    检测当前联网/认证状态。
    依次尝试配置里的探测点，任一命中即得出结论。
    """
    net = cfg.get("network", {})
    timeout = float(net.get("timeout", 8))
    probes = net.get("probes") or [list(p) for p in DEFAULT_PROBES]
    if quick:
        timeout = min(timeout, 4.0)

    last_err = ""
    for item in probes:
        try:
            url, expect = (item[0], item[1]) if len(item) >= 2 else (item, "")
        except Exception:
            continue
        t0 = time.time()
        res = http_get(url, timeout=timeout, max_redirect=0)
        cost = int((time.time() - t0) * 1000)

        if res.error:
            last_err = res.error
            continue
        if res.status in (301, 302, 303, 307, 308):
            loc = res.final_url
            return NetStatus(ST_PORTAL, f"被重定向到认证服务器（HTTP {res.status}）",
                             portal_url=loc, latency_ms=cost)
        if expect and expect in res.body:
            return NetStatus(ST_ONLINE, f"探测点响应正常（{url.split('/')[2]}）",
                             latency_ms=cost)
        if not expect and res.status in (200, 204) and len(res.body) < 64:
            return NetStatus(ST_ONLINE, "探测点返回 204/短响应，网络畅通",
                             latency_ms=cost)
        if _looks_like_portal(res.body, res.final_url):
            return NetStatus(ST_PORTAL, "探测请求返回认证页面，尚未认证",
                             portal_url=res.final_url or url, latency_ms=cost)
        if res.status == 200:
            return NetStatus(ST_ONLINE, "探测点返回 200，网络畅通", latency_ms=cost)
        last_err = f"HTTP {res.status}"

    return NetStatus(ST_OFFLINE, last_err or "所有探测点均不可达")


def local_ip() -> str:
    """获取本机在校园网内的出口 IP（用于深澜等需要上报 ip 的接口）。"""
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.5)
        s.connect(("223.5.5.5", 80))
        return s.getsockname()[0]
    except Exception:
        return ""
    finally:
        if s:
            try:
                s.close()
            except Exception:
                pass


def _ssl_ctx():
    """校园网认证页常用自签证书，不做证书校验以免误判为网络故障。"""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


class HttpSession:
    """
    带 Cookie 的 HTTP 会话。

    为什么必须要有它：锐捷 ePortal、部分深澜版本要求**先访问门户页**，
    由服务器下发 JSESSIONID 之类的会话 Cookie，之后带着同一个 Cookie 提交登录。
    如果直接裸 POST，服务器会因为找不到登录上下文而返回
    "Error code: 203 Bad request(2)" 这类参数校验错误。
    浏览器的登录过程天然带着 Cookie，所以网页能点通、程序直连却失败。
    """

    def __init__(self, timeout: float = 8.0, encoding: str = "utf-8", logger=None):
        self.timeout = float(timeout)
        self.encoding = encoding or "utf-8"
        self.logger = logger
        self.cookiejar = http.cookiejar.CookieJar()
        handlers = [urllib.request.HTTPCookieProcessor(self.cookiejar),
                    urllib.request.HTTPSHandler(context=_ssl_ctx())]
        self.opener = urllib.request.build_opener(*handlers)
        self.opener.addheaders = [("User-Agent", USER_AGENT), ("Accept", "*/*")]
        self.history: list[str] = []

    # ---- 会话状态 ----
    @property
    def cookies(self) -> dict:
        return {c.name: c.value for c in self.cookiejar}

    def cookie_header(self) -> str:
        return "; ".join(f"{c.name}={c.value}" for c in self.cookiejar)

    def set_cookie(self, name: str, value: str) -> None:
        """手动补一个 Cookie（有些门户的 JS 会自己种 cookie）。"""
        try:
            self.cookiejar.set_cookie(http.cookiejar.Cookie(
                version=0, name=name, value=value, port=None, port_specified=False,
                domain="", domain_specified=False, domain_initial_dot=False,
                path="/", path_specified=True, secure=False, expires=None,
                discard=True, comment=None, comment_url=None, rest={}, rfc2109=False))
        except Exception:
            pass

    # ---- 请求 ----
    def open(self, url: str, data=None, headers: dict | None = None,
             method: str | None = None) -> HttpResult:
        if isinstance(data, str):
            data = data.encode("ascii", "replace")
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("Referer", url)
        for k, v in (headers or {}).items():
            req.add_header(k, v)
        self.history.append(url)
        lg = self.logger
        if lg:
            try:
                body_s = (data or b"").decode(self.encoding, "replace")[:400]
            except Exception:
                body_s = ""
            hdr_s = "; ".join(f"{k}={v}" for k, v in (headers or {}).items())
            lg.debug("[HTTP→] %s %s | %s | body=%s",
                     method or "GET", _mask_secrets(url), hdr_s or "-",
                     _mask_secrets(body_s) or "-")
        try:
            with self.opener.open(req, timeout=self.timeout) as resp:
                raw = resp.read()
                hdrs = {k.lower(): v for k, v in resp.getheaders()}
                raw = _decompress_bytes(raw, hdrs)
                text = _decode_body(raw, hdrs.get("content-type", ""), self.encoding)
                if lg:
                    lg.debug("[HTTP←] HTTP %s %s | %s", resp.status,
                             _mask_secrets(resp.geturl()),
                             "; ".join(f"{k}={v}" for k, v in resp.getheaders())[:800])
                    lg.debug("[HTTP←] body(%d 字符)：%s", len(raw), text[:400])
                return HttpResult(
                    status=resp.status,
                    body=text,
                    headers=hdrs,
                    final_url=resp.geturl() or url)
        except urllib.error.HTTPError as e:          # 4xx/5xx 也当正常响应交给调用方判断
            try:
                raw = e.read()
            except Exception:
                raw = b""
            if lg:
                lg.debug("[HTTP←] HTTP %s（错误响应）%s | %s", e.code,
                         _mask_secrets(getattr(e, "url", url)),
                         "; ".join(f"{k}={v}" for k, v in (e.headers or {}).items())[:800])
            eh = {k.lower(): v for k, v in (e.headers or {}).items()}
            raw = _decompress_bytes(raw, eh)
            return HttpResult(status=e.code,
                              body=_decode_body(raw, eh.get("content-type", ""), self.encoding),
                              headers=eh,
                              final_url=getattr(e, "url", url) or url)
        except (socket.timeout, TimeoutError):
            return HttpResult(error="连接超时")
        except socket.gaierror as e:
            return HttpResult(error=f"DNS 解析失败：{e}")
        except urllib.error.URLError as e:
            return HttpResult(error=f"网络不可达：{e.reason}")
        except Exception as e:
            return HttpResult(error=f"请求异常：{e}")

    def get(self, url, headers=None) -> HttpResult:
        return self.open(url, None, headers, method="GET")

    def post(self, url, fields: dict | list, headers=None, referer: str = "") -> HttpResult:
        body = urlencode(fields, encoding=self.encoding)
        hdrs = {"Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"}
        if referer:
            hdrs["Referer"] = referer
        hdrs.update(headers or {})
        return self.open(url, body, hdrs, method="POST")

    def post_raw(self, url, body: str, headers=None, referer: str = "") -> HttpResult:
        hdrs = {"Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"}
        if referer:
            hdrs["Referer"] = referer
        hdrs.update(headers or {})
        return self.open(url, body, hdrs, method="POST")


# ============================================================================
# [5] 登录页表单解析
# ============================================================================

FORM_USER_KEYS = ["username", "userid", "user_name", "user", "account",
                  "loginname", "login_name", "uname", "txtusername",
                  "wlanuser", "useraccount", "name"]
FORM_PWD_KEYS = ["password", "pwd", "passwd", "pass", "userpwd",
                 "txtpassword", "upass", "userpassword"]


class _FormParser(HTMLParser):
    """从 HTML 中提取 form 及其 input 字段（含页面里游离的 input）。"""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.forms: list[dict] = []
        self._cur: dict | None = None
        self._loose: list[dict] = []

    def handle_starttag(self, tag, attrs):
        d = {k.lower(): (v or "") for k, v in attrs}
        if tag == "form":
            self._cur = {"action": d.get("action", ""),
                         "method": (d.get("method") or "post").lower(),
                         "inputs": []}
        elif tag == "input":
            item = {"name": d.get("name", ""), "value": d.get("value", ""),
                    "type": (d.get("type") or "text").lower(),
                    "id": d.get("id", "")}
            (self._cur["inputs"] if self._cur is not None else self._loose).append(item)

    def handle_endtag(self, tag):
        if tag == "form" and self._cur is not None:
            self.forms.append(self._cur)
            self._cur = None

    def close(self):
        super().close()
        if self._cur is not None:
            self.forms.append(self._cur)
            self._cur = None

    def result(self) -> list[dict]:
        forms = [f for f in self.forms if f["inputs"]]
        if not forms and self._loose:
            forms = [{"action": "", "method": "post", "inputs": self._loose}]
        return forms


def parse_forms(html_text: str, base_url: str) -> list[dict]:
    p = _FormParser()
    try:
        p.feed(html_text or "")
        p.close()
    except Exception:
        pass
    forms = p.result()
    for f in forms:
        f["action"] = urljoin(base_url, f["action"]) if f["action"] else base_url
        # 为每个字段猜测用途
        for inp in f["inputs"]:
            inp["role"] = _guess_role(inp)
    return forms


def _guess_role(inp: dict) -> str:
    key = (inp.get("name") or inp.get("id") or "").strip().lower()
    if not key:
        return ""
    if inp.get("type") == "password":
        return "password"
    if inp.get("type") in ("hidden", "submit", "button", "reset", "image", "checkbox", "radio"):
        return ""
    for k in FORM_PWD_KEYS:
        if key == k:
            return "password"
    for k in FORM_USER_KEYS:
        if key == k:
            return "username"
    for k in FORM_PWD_KEYS:
        if k in key:
            return "password"
    for k in FORM_USER_KEYS:
        if k in key and k != "name":       # name 过于宽泛，不做包含匹配
            return "username"
    return ""


# ============================================================================
# [6] Portal 认证适配器
# ============================================================================

def detect_adapter(portal_url: str, page_html: str = "") -> str:
    """
    根据认证地址/页面内容猜测校园网认证系统类型。
    返回 'srun' | 'eportal' | 'drcom' | 'form'
    """
    blob = f"{portal_url}\n{(page_html or '')[:8000]}".lower()
    # Dr.COM 的判据最明确：页面里直接写着它自己的配置变量名。
    # 注意必须排在 eportal 前面 —— Dr.COM 的登录路径里也含 "eportal" 字样，
    # 早期按关键字优先匹配 eportal，导致把 Dr.COM 门户认成锐捷（实测踩过）。
    if any(k in blob for k in ("drcom", "dr.com", "authloginpath", "authuserfield",
                               "0mkkey", "城市热点")):
        return "drcom"
    if "srun_portal" in blob or "深澜" in blob or "srun" in blob:
        return "srun"
    if "interface.do" in blob or "锐捷" in blob:
        return "eportal"
    return "form"


def _url_base(url: str) -> str:
    """取出 scheme://host:port；地址非法时返回空串。"""
    u = urlparse(url)
    if not u.hostname:
        return ""
    port = f":{u.port}" if u.port else ""
    return f"{u.scheme}://{u.hostname}{port}"


def _query_of(url: str) -> str:
    """取出 URL 的查询串（不含 '?'），供锐捷 ePortal 的 queryString 参数使用。"""
    try:
        return urlparse(url).query or ""
    except Exception:
        return ""


def _extract_query_from_page(html_text: str) -> str:
    """
    兜底：从认证页里把 queryString 抠出来。

    不是所有锐捷门户都会 302 到带参数的地址 —— 有些直接把参数写在页面里：
        var queryString = "wlanuserip=10.1.2.3&wlanacname=...&ac_id=1";
    或者把带参地址整串塞进 JS / 表单隐藏域：
        <input type="hidden" name="queryString" value="wlanuserip=...">
    取不到它，登录必然被判参数非法（Error code 203），所以这里做一层兜底。
    """
    if not html_text:
        return ""
    text = html_text[:200000].replace("&amp;", "&")

    # 直接定位 wlanuserip= 再向右切片。
    # 不用 "找成对引号" 的写法：正则在长页面里会因贪心配对错位 ——
    # 前一个匹配会把 "value=" 吃掉、再拿参数自身的两个引号收尾，
    # 结果候选值变成 "  value="，真正的参数反而被跳过。
    for marker, need_unquote in (("wlanuserip=", False), ("wlanuserip%3d", True)):
        idx = text.lower().find(marker)
        if idx < 0:
            continue
        tail = unquote(text[idx:]) if need_unquote else text[idx:]
        q = re.split(r"[\s'\"<>\\]", tail)[0].rstrip("&;,")
        if q:
            return q
    return ""


class LoginOutcome:
    OK = "ok"                  # 登录成功
    FAILED = "failed"          # 明确失败（账号密码错误等）
    RETRY = "retry"            # 需要重试（网络抖动 / 未知响应）
    RELOGIN = "relogin"        # 登录后仍被要求认证（会话被顶 / 需重新登录）
    NO_CONFIG = "noconfig"     # 配置不完整
    OFFLINE = "offline"        # 网络不通

    TEXT = {
        OK: "登录成功",
        FAILED: "登录失败",
        RETRY: "需要重试",
        RELOGIN: "需要重新登录",
        NO_CONFIG: "配置不完整",
        OFFLINE: "网络不通",
    }


_KEY_OK = ["\"error\":\"ok\"", "'error':'ok'", "login_ok", "suc_msg",
           "success", "成功", "\"result\":\"success\"", "登录成功", "认证成功"]
_KEY_FAIL = ["密码错误", "用户名或密码", "账号或密码", "password error",
             "wrong password", "认证失败", "登录失败", "invalid",
             "\"result\":\"fail", "error_msg\":\"[^\"}]+", "账号不存在",
             "已欠费", "余额不足", "用户被锁定"]


def _judge_response(text: str, status: int, extra_fail: list = None,
                    extra_ok: list = None) -> str:
    """根据响应正文判定登录结果。"""
    low = (text or "").lower()
    for k in (extra_fail or []):
        if k and k.lower() in low:
            return LoginOutcome.FAILED
    for k in (extra_ok or []):
        if k and k.lower() in low:
            return LoginOutcome.OK
    for k in _KEY_FAIL:
        if k.lower() in low:
            return LoginOutcome.FAILED
    for k in _KEY_OK:
        if k.lower() in low:
            return LoginOutcome.OK
    if status in (200, 302):
        return LoginOutcome.RETRY      # 响应看不懂，交给复检决定
    return LoginOutcome.RETRY


# -------- 适配器 1：深澜 srun --------

def _login_srun(portal_url, username, password, timeout, enc, logger) -> tuple:
    base = _url_base(portal_url)
    if not base:
        return LoginOutcome.NO_CONFIG, f"认证地址非法：{portal_url}", ""
    qs = dict(parse_qsl(urlparse(portal_url).query))
    ac_id = qs.get("ac_id", "1")
    ip = qs.get("wlanuserip") or qs.get("ip") or local_ip()

    # 第一步：访问认证入口，取回 ac_id（有些学校只在这里给）
    entry = f"{base}/srun_portal_pc?ac_id={ac_id}&theme=basic"
    res = http_get(entry, timeout=timeout, encoding=enc)
    if not res.error:
        m = re.search(r"ac_id\s*[=:]\s*['\"]?(\d+)", res.body)
        if m:
            ac_id = m.group(1)

    # 第二步：提交登录
    fields = [
        ("action", "login"), ("username", username), ("password", password),
        ("ac_id", ac_id), ("ip", ip), ("chksum", ""), ("info", ""), ("n", ""),
        ("type", "1"), ("os", "Windows"), ("name", "Windows"),
        ("double_stack", "0"),
    ]
    body = urlencode(fields, encoding=enc)
    url = f"{base}/srun_portal_pc?ac_id={ac_id}&theme=basic"
    r = http_post(url, body, timeout=timeout, encoding=enc,
                  headers={"Referer": entry})
    if r.error:
        return LoginOutcome.RETRY, f"srun 提交失败：{r.error}", ""
    logger.debug("srun 响应：%s", r.body[:300])
    return _judge_response(r.body, r.status), "深澜 srun 接口已提交", r.body


def _logout_srun(portal_url, timeout, enc) -> tuple:
    base = _url_base(portal_url)
    if not base:
        return False, f"认证地址非法：{portal_url}"
    qs = dict(parse_qsl(urlparse(portal_url).query))
    ac_id = qs.get("ac_id", "1")
    ip = qs.get("wlanuserip") or local_ip()
    body = urlencode([("action", "logout"), ("ac_id", ac_id), ("ip", ip),
                      ("username", ""), ("type", "1")], encoding=enc)
    r = http_post(f"{base}/srun_portal_pc?ac_id={ac_id}&theme=basic", body,
                  timeout=timeout, encoding=enc)
    return (not r.error), (r.error or "已请求深澜断开")


# -------- 适配器 2：锐捷 ePortal --------

# 锐捷 ePortal 返回的错误码对照（各版本略有差异，仅用于给用户可读提示）
EPORTAL_ERRORS = {
    "200": "认证成功",
    "203": "参数校验失败：服务器没有找到有效的登录上下文，或 queryString 不匹配",
    "204": "认证服务器拒绝了本次请求",
    "211": "认证服务器繁忙，请稍后重试",
    "401": "账号或密码错误",
    "411": "认证服务器要求先重新登录",
}


def explain_eportal_error(body: str) -> str:
    m = re.search(r"Error\s*code\s*[:：]\s*(\d+)", body or "", re.I)
    if not m:
        return ""
    code = m.group(1)
    hint = EPORTAL_ERRORS.get(code, "未知错误")
    return f"认证服务器返回 Error code {code} —— {hint}"


def _login_eportal(portal_url, username, password, timeout, enc, logger) -> tuple:
    base = _url_base(portal_url)
    if not base:
        return LoginOutcome.NO_CONFIG, f"认证地址非法：{portal_url}", ""

    # 关键：整个流程必须走同一个会话。
    # 浏览器能点通、程序直连失败，最常见的原因就是缺少门户下发的会话 Cookie。
    sess = HttpSession(timeout=timeout, encoding=enc, logger=logger)

    page = sess.get(portal_url)
    if page.error:
        return LoginOutcome.RETRY, f"无法打开认证门户：{page.error}", ""
    final_url = page.final_url or portal_url
    logger.debug("门户入口：%s → HTTP %s，最终地址 %s",
                 portal_url, page.status, final_url)
    logger.debug("会话 Cookie：%s", sess.cookie_header() or "(空)")

    # 把门户页原文落盘，便于分析页面 JS 到底怎么调登录接口
    try:
        dump = os.path.join(data_dir(), "logs", "portal_page.html")
        os.makedirs(os.path.dirname(dump), exist_ok=True)
        with open(dump, "w", encoding="utf-8") as f:
            f.write(page.body or "")
        logger.debug("门户页原文已保存：%s（%d 字符）", dump, len(page.body or ""))
    except Exception as e:                       # noqa: BLE001
        logger.debug("门户页落盘失败：%s", e)

    query = _query_of(final_url) or _query_of(portal_url)
    if not query:
        # 兜底：参数可能写在页面 JS 里，而不是 URL 上
        query = _extract_query_from_page(page.body)
        if query:
            logger.info("从认证页 JS 中提取到 queryString（%d 字符）", len(query))
    if not query:
        logger.warning("未能从门户地址取到 queryString，服务器很可能会拒绝本次登录")

    # 部分版本要求先调用 pageInfo 建立登录上下文
    info_url = f"{base}/eportal/InterFace.do?method=pageInfo"
    pi = sess.post(info_url, {"queryString": query}, referer=final_url,
                   headers={"X-Requested-With": "XMLHttpRequest"})
    if pi.error:
        logger.debug("pageInfo 调用失败（忽略）：%s", pi.error)
    else:
        logger.debug("pageInfo：HTTP %s | %s", pi.status, (pi.body or "")[:240])
        logger.debug("pageInfo 后 Cookie：%s", sess.cookie_header() or "(空)")
        m = re.search(r'"userIndex"\s*:\s*"([^"]*)"', pi.body or "")
        if m:
            logger.debug("取得 userIndex=%s", m.group(1))

    # 提交体按浏览器的 encodeURIComponent 语义手工拼装：
    # queryString 里含 = 和 &，必须整体编码；urlencode 会把空格变成 '+'，
    # 而门户页 JS 用的是 %20，个别服务器会因此判定参数非法。
    body = "&".join([
        f"userId={quote(username, safe='')}",
        f"password={quote(password, safe='')}",
        "service=",
        f"queryString={quote(query, safe='')}",
        "operatorPwd=",
        "operatorUserId=",
        "validcode=",
        "passwordEncrypt=false",
    ])
    url = f"{base}/eportal/InterFace.do?method=login"
    logger.debug("提交登录：%s | queryString=%s", url, (query or "(空)")[:200])
    if not query:
        logger.warning("queryString 为空 —— 这通常正是服务器返回 203 Bad request 的原因，"
                       "请确认门户地址带有 wlanuserip 之类的参数")

    r = sess.post_raw(url, body, referer=final_url,
                      headers={"Origin": base, "X-Requested-With": "XMLHttpRequest"})
    if r.error:
        return LoginOutcome.RETRY, f"ePortal 提交失败：{r.error}", ""

    body = r.body or ""
    logger.debug("登录响应 HTTP %s：%s", r.status, body[:400])
    low = body.replace(" ", "").lower()

    if '"result":"success"' in low or "认证成功" in body:
        return LoginOutcome.OK, "锐捷 ePortal 认证通过", body
    if "errorcode" in low:
        return LoginOutcome.FAILED, explain_eportal_error(body) or "ePortal 返回错误", body
    if '"result":"fail' in low:
        m = re.search(r'"message"\s*:\s*"([^"]*)"', body)
        return LoginOutcome.FAILED, (m.group(1) if m else "ePortal 返回失败"), body
    if "失败" in body or "错误" in body:
        return LoginOutcome.FAILED, "ePortal 返回失败", body
    return LoginOutcome.RETRY, "ePortal 响应未知，交由复检判定", body


def _logout_eportal(portal_url, timeout, enc) -> tuple:
    base = _url_base(portal_url)
    if not base:
        return False, f"认证地址非法：{portal_url}"
    sess = HttpSession(timeout=timeout, encoding=enc)
    sess.get(portal_url)                       # 断开同样要先建立会话
    r = sess.get(f"{base}/eportal/InterFace.do?method=logout")
    return (not r.error), (r.error or "已请求 ePortal 断开")


# -------- 适配器 3：Dr.COM / 城市热点 --------

def _parse_portal_js_config(html: str) -> dict:
    """
    从门户页内嵌脚本里抠出 Dr.COM 的认证配置。

    这类门户（响应头 `Server: DrcomServer1.0`）的页面本身是**空壳**，
    登录框由外部 JS 渲染，但配置变量直接写在 <head> 的内联脚本里：

        authloginport=801;
        authloginpath='/eportal/?c=ACSetting&a=Login';
        authloginparam='url=drappal';
        authuserfield='DDDDD';          // 账号字段名
        authpassfield='upass';          // 密码字段名
        authsuccess='Dr.COMWebLoginID_3.htm';
        authfail='Dr.COMWebLoginID_2.htm';
        charset='gb2312';

    照抄这些值即可，不要去猜锐捷那套 userId/queryString —— 那套在这台服务器上
    连 pageInfo 都会被判 203。
    """
    if not html:
        return {}
    cfg: dict = {}

    def _s(name):
        m = re.search(r"\b" + name + r"\s*=\s*(['\"])(.*?)\1", html)
        return m.group(2) if m else ""

    def _i(name):
        m = re.search(r"\b" + name + r"\s*=\s*(-?\d+)", html)
        return int(m.group(1)) if m else 0

    for k in ("authloginpath", "authloginparam", "authuserfield", "authpassfield",
              "authlogoutpath", "authlogoutparam", "authsuccess", "authfail",
              "charset", "portalver", "v4serip", "v46ip", "mip", "ss5", "ss6"):
        v = _s(k)
        if v:
            cfg[k] = v
    for k in ("authloginport", "authlogoutport", "authtype"):
        v = _i(k)
        if v:
            cfg[k] = v
    m = re.search(r"\bcarrier\s*=\s*'(\{.*?\})'", html, re.S)
    if m:
        cfg["carrier"] = m.group(1)
    return cfg


def _fetch_page_scripts(sess, base: str, html: str, logger) -> dict:
    """
    把门户页引用的外部脚本拉下来存盘。

    登录参数怎么拼、要不要额外字段，全在页面引用的 JS 里（本机是 a41.js），
    存下来才有据可查，不至于靠猜。
    """
    saved: dict = {}
    for m in re.finditer(r"""<script[^>]*\bsrc\s*=\s*["']([^"']+)["']""", html or "", re.I):
        src = m.group(1).strip()
        if not src:
            continue
        url = urljoin(base.rstrip("/") + "/", src)
        try:
            r = sess.get(url)
        except Exception as e:                   # noqa: BLE001
            logger.debug("脚本拉取异常：%s（%s）", url, e)
            continue
        if r.error:
            logger.debug("脚本拉取失败：%s（%s）", url, r.error)
            continue
        name = os.path.basename(src.split("?")[0]) or "asset.js"
        try:
            path = os.path.join(data_dir(), "logs", name)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8", errors="replace") as f:
                f.write(r.body or "")
            logger.debug("已保存页面脚本：%s（%d 字符）", path, len(r.body or ""))
        except OSError as e:
            logger.debug("脚本存盘失败：%s", e)
        hint = _interface_hint(r.body or "")
        if hint:
            logger.info("脚本 %s 里的接口线索：%s", name, hint[:15])
        saved[name] = r.body or ""
    return saved


_SECRET_RE = re.compile(
    r"\b(password|passwd|pwd|upass|user_password|user_old_password"
    r"|user_new_password|operatorPwd|com_password|common_password)\b"
    r"(\s*[=:]\s*|\s*%3[dD]\s*)([^&\s\"']+)", re.I)


def _mask_secrets(text: str) -> str:
    """
    把日志里出现的口令一律打码。

    日志必须能贴给别人看（排障时全靠它），所以绝不能留下明文密码；
    但请求本身要用原值发送 —— 只对"写进日志的那份"做替换。
    """
    return _SECRET_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}***", text or "")


def _dump_text(name: str, content: str, logger=None) -> str:
    """把一段文本存到 logs/ 下，返回路径（失败返回空串）。"""
    try:
        safe = re.sub(r"[^\w.-]", "_", name)[:80]
        path = os.path.join(data_dir(), "logs", safe)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8", errors="replace") as f:
            f.write(content or "")
        if logger:
            logger.debug("已保存 %s（%d 字符）", path, len(content or ""))
        return path
    except OSError as e:
        if logger:
            logger.debug("保存 %s 失败：%s", name, e)
        return ""


def _html_text(html: str, limit: int = 800, keep_script: bool = False) -> str:
    """把 HTML 压成纯文本 —— 用来在日志里直接读出服务器给出的失败原因。

    keep_script=True 时保留 <script> 内容：不少门户把错误文案写在脚本里，
    剥掉脚本就只剩一个空壳标题（实测 Dr.COM 的"信息页"就是这样）。
    """
    t = html or ""
    if not keep_script:
        t = re.sub(r"<script.*?</script>", " ", t, flags=re.S | re.I)
        t = re.sub(r"<style.*?</style>", " ", t, flags=re.S | re.I)
    t = re.sub(r"<!--.*?-->", " ", t, flags=re.S)
    t = re.sub(r"<[^>]+>", " ", t)
    t = (t.replace("&nbsp;", " ").replace("&amp;", "&")
          .replace("&lt;", "<").replace("&gt;", ">").replace("&#39;", "'"))
    t = re.sub(r"\s+", " ", t)
    return t.strip()[:limit]


def _interface_hint(text: str) -> list:
    """从 JS/HTML 里捞可能的后端接口路径。"""
    found, out = set(), []
    for m in re.finditer(r"""['"`](/?[\w./-]*(?:InterFace\.do|eportal|login|Login|auth)[\w./?=&-]*)['"`]""",
                         text or ""):
        p = m.group(1)
        if len(p) < 4 or p in found:
            continue
        found.add(p)
        out.append(p)
    return out[:40]


def _drcom_fail_message(body: str) -> str:
    """从 Dr.COM 的失败响应里抠一句可读的提示。"""
    for pat in (r"""msg\s*[:=]\s*['"]([^'"]{2,120})""",
                r"""message\s*[:=]\s*['"]([^'"]{2,120})""",
                r"错误[：:]?\s*([^<>\"']{2,80})",
                r"失败[：:]?\s*([^<>\"']{2,80})"):
        m = re.search(pat, body or "", re.I)
        if m:
            return m.group(1).strip()
    return ""


def _port_open(host: str, port: int, timeout: float = 2.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _login_drcom(portal_url, username, password, timeout, enc, logger) -> tuple:
    """
    Dr.COM（城市热点）Web 认证。

    与锐捷 ePortal 完全不是一回事：
      · 登录路径形如 /eportal/?c=ACSetting&a=Login（不是 InterFace.do）
      · 端口常为 801（不是 80）
      · 账号字段叫 DDDDD、密码字段叫 upass（不是 userId/password）
      · 成功与否看页面名 Dr.COMWebLoginID_3 / _2

    以上取值全部从门户页的内嵌脚本里读，读不到才退回默认。
    """
    base = _url_base(portal_url)
    if not base:
        return LoginOutcome.NO_CONFIG, f"认证地址非法：{portal_url}", ""
    host = urlparse(base).hostname or ""

    sess = HttpSession(timeout=timeout, encoding=enc, logger=logger)
    page = sess.get(portal_url)
    if page.error:
        return LoginOutcome.RETRY, f"无法打开认证门户：{page.error}", ""
    final_url = page.final_url or portal_url
    logger.debug("门户入口：%s → HTTP %s，最终地址 %s", portal_url, page.status, final_url)

    try:
        dump = os.path.join(data_dir(), "logs", "portal_page.html")
        os.makedirs(os.path.dirname(dump), exist_ok=True)
        with open(dump, "w", encoding="utf-8") as f:
            f.write(page.body or "")
        logger.debug("门户页原文已保存：%s（%d 字符）", dump, len(page.body or ""))
    except OSError as e:
        logger.debug("门户页落盘失败：%s", e)
    scripts: dict = {}
    scripts.update(_fetch_page_scripts(sess, base, page.body or "", logger))

    pc = _parse_portal_js_config(page.body or "")
    logger.info("门户声明的认证配置：%s", {k: pc[k] for k in sorted(pc)} or "(未解析到)")

    login_path = pc.get("authloginpath") or "/eportal/?c=ACSetting&a=Login"
    login_port = int(pc.get("authloginport") or 801)
    user_field = pc.get("authuserfield") or "DDDDD"
    pwd_field = pc.get("authpassfield") or "upass"
    # 注意：不能用 split(".")[0] 去后缀 —— "Dr.COMWebLoginID_3.htm" 里
    # 名字本身带点，切出来只剩 "Dr"，成功与失败标志会撞在一起。
    ok_mark = re.sub(r"\.htm$", "", pc.get("authsuccess") or "Dr.COMWebLoginID_3.htm",
                     flags=re.I)
    fail_mark = re.sub(r"\.htm$", "", pc.get("authfail") or "Dr.COMWebLoginID_2.htm",
                       flags=re.I)

    # 实测：801 端口是 nginx 托管的 "EPortal" 单页应用（真正的认证前端），
    #       80 端口是 DrcomServer1.0 的老接口 —— 两个端口上不是同一套系统。
    # a41.js 里写明真实接口前缀是  http://<host>:801/eportal/portal/
    # 而登录动作在压缩功能脚本 a40.js 里（isJSMin=1 时加载的就是它）。
    for p in dict.fromkeys([login_port, 80]):
        if not _port_open(host, p):
            continue
        idx = sess.get(f"http://{host}:{p}/")
        if idx.error:
            logger.debug("端口 %s 首页抓取失败：%s", p, idx.error)
            continue
        _dump_text(f"port{p}_index.html", idx.body, logger)
        hint = _interface_hint(idx.body or "")
        if hint:
            logger.debug("端口 %s 首页里的接口线索：%s", p, hint[:12])
        if "EPortal" in (idx.body or ""):
            logger.info("端口 %s 上是 EPortal 单页应用（nginx），真实接口在它引用的 JS 里", p)
        scripts.update(_fetch_page_scripts(sess, f"http://{host}:{p}", idx.body or "", logger))

    app_root = f"http://{host}:{login_port}"
    # a41.js 是从门户页（80 端口）加载的，而它用**相对路径**加载 a40.js，
    # 所以 a40.js 很可能在 80 端口 —— 两个端口都要试。
    for root in dict.fromkeys([app_root, base]):
        for rel in ("a40.js", "eportal/a40.js",
                    "eportal/public/pageAsset/js/store.js",
                    "eportal/public/pageAsset/js/all.js"):
            u = f"{root}/{rel}"
            r = sess.get(u)
            if r.error or not r.body or r.status >= 400:
                logger.debug("脚本 %s 拉取失败（%s / HTTP %s）",
                             u, r.error or "-", r.status)
                continue
            _dump_text("app_" + re.sub(r"[^\w.-]", "_", u), r.body, logger)
            scripts[os.path.basename(rel)] = r.body
            logger.info("已抓取脚本 %s（%d 字符）", u, len(r.body))
            for h in _interface_hint(r.body)[:10]:
                logger.debug("    %s 里的接口线索：%s", rel, h)

    js_blob = "\n".join(scripts.values())

    # 按 a41.js 的流程先取一次页面配置（能拿到 login_method / page_index）
    client_ip = (pc.get("v46ip") or pc.get("v4serip") or local_ip() or "").strip()
    ac_ip = (pc.get("wlanacip") or "").strip()
    m = re.search(r"name\s*:\s*['\"]([A-Za-z0-9_]{6,})['\"]", js_blob)
    program_index = m.group(1) if m else ""
    if program_index:
        logger.info("程序标识 program_index=%s", program_index)
        q = urlencode({
            "program_index": program_index,
            "wlan_vlan_id": "1",
            "wlan_user_ip": _b64(client_ip),
            "wlan_user_ipv6": "",
            "wlan_user_ssid": "",
            "wlan_user_areaid": "",
            "wlan_ac_ip": _b64(ac_ip),
            "wlan_ap_mac": "",
            "gw_id": "",
            "jsVersion": "4.1.3",
        }, encoding=enc)
        url_cfg = f"{app_root}/eportal/portal/page/loadConfig?{q}"
        logger.debug("调用页面配置接口：%s", url_cfg)
        rc = sess.get(url_cfg)
        if rc.error:
            logger.debug("loadConfig 失败：%s", rc.error)
        else:
            logger.info("loadConfig HTTP %s：%s", rc.status, _html_text(rc.body, 400))
            _dump_text("drcom_loadConfig.txt", rc.body, logger)
            # 从返回里取 page_index，拼出页面模板地址并抓下来 ——
            # 登录表单是 JS 动态生成的，账号/密码字段名只存在于这个模板里。
            try:
                j = rc.body or ""
                m_idx = re.search(r'"page_index"\s*:\s*"([^"]+)"', j)
                m_prg = re.search(r'"program_index"\s*:\s*"([^"]+)"', j)
                m_mth = re.search(r'"login_method"\s*:\s*"?([^",}]*)"?', j)
                if m_mth:
                    logger.info("门户告知 login_method=%s", m_mth.group(1))
                if m_idx and m_prg:
                    page_url = (f"{app_root}/eportal/extern/"
                                f"{m_prg.group(1)}/{m_idx.group(1)}/")
                    for kind in ("pc", "pc_", "pc_1"):
                        u = f"{page_url}{kind}.js"
                        rp = sess.get(u)
                        if rp.error or rp.status >= 400 or not rp.body:
                            continue
                        _dump_text(f"template_{kind}.js", rp.body, logger)
                        logger.info("已抓取页面模板 %s（%d 字符）", u, len(rp.body))
                        names = sorted(set(re.findall(
                            r"""\bname\s*=\s*["'\\]*([A-Za-z_][\w.-]{0,30})["'\\]""",
                            rp.body)))
                        logger.info("模板里的表单字段名：%s", names[:40])
                        scripts[f"template_{kind}.js"] = rp.body
                        break
            except Exception as e:                # noqa: BLE001
                logger.debug("页面模板抓取异常：%s", e)

    # 从抓到的脚本里找真实的登录接口
    api_login = ""
    for src in scripts.values():
        mm = re.search(
            r"""['"]([^'"\s]{0,90}eportal/portal/[^'"\s]{0,40}[Ll]ogin[^'"\s]{0,40})['"]""",
            src)
        if mm:
            api_login = mm.group(1)
            logger.info("从脚本里找到登录接口：%s", api_login)
            break

    port_set = [p for p in dict.fromkeys([login_port, 80]) if _port_open(host, p)]
    if not port_set:
        return LoginOutcome.RETRY, f"认证端口 {login_port}/80 均不可达", ""

    query = _query_of(final_url) or _query_of(portal_url)
    drcom_fields = urlencode(
        [(user_field, username), (pwd_field, password),
         ("R1", "0"), ("R2", "0"), ("R3", "0"), ("R6", "0"),
         ("para", "00"), ("0MKKey", "123456")], encoding=enc)
    srun_body = "&".join([
        f"userId={quote(username, safe='')}",
        f"password={quote(password, safe='')}",
        "service=",
        f"queryString={quote(query, safe='')}",
        "operatorPwd=", "operatorUserId=", "validcode=", "passwordEncrypt=false",
    ])
    # Dr.COM 4.x：参数名沿用 online_list 那套 user_account / user_password
    drcom4_body = urlencode([
        ("user_account", username),
        ("user_password", password),
        ("wlan_user_ip", client_ip),
        ("wlan_user_mac", _local_mac()),
        ("wlan_ac_ip", ac_ip),
        ("user_ipv6", ""),
        ("jsVersion", "4.1.3"),
    ], encoding=enc)

    # a41.js 里所有接口都走 util._jsonp —— 也就是 GET、参数放在 URL 上。
    # 之前用 POST 提交 /eportal/portal/login，服务器取不到参数，
    # 回的正是"无法获取用户认证账号"。
    drcom4_qs = urlencode([
        ("user_account", username),
        ("user_password", password),
        ("wlan_user_ip", client_ip),
        ("wlan_user_mac", _local_mac()),
        ("wlan_ac_ip", ac_ip),
        ("jsVersion", "4.1.3"),
        ("callback", "dr1"),
        ("v", "1000"),
        ("lang", "zh"),
    ], encoding=enc)

    raw_trials = []              # (url, body, label)；body 为 None 表示走 GET
    if api_login:
        raw_trials.append((urljoin(app_root + "/", api_login.lstrip("/")),
                           drcom4_body, "脚本给出的登录接口(POST)"))
    for p in port_set:
        raw_trials.append((f"http://{host}:{p}/eportal/portal/login?{drcom4_qs}",
                           None, f"Dr.COM 4.x GET @ {p}"))
        raw_trials.append((f"http://{host}:{p}/eportal/portal/login", drcom4_body,
                           f"Dr.COM 4.x POST @ {p}"))
        raw_trials.append((f"http://{host}:{p}{login_path}", drcom_fields,
                           f"Dr.COM 老表单 @ {p}"))
        raw_trials.append((f"http://{host}:{p}/eportal/InterFace.do?method=login",
                           srun_body, f"eportal 协议 @ {p}"))

    trials, seen = [], set()                     # 同样的「地址 + 参数」只试一次
    for u, b, label in raw_trials:
        if (u, b) in seen:
            continue
        seen.add((u, b))
        trials.append((u, b, label))

    last_body, last_label = "", ""
    saw_fail_mark = False
    for u, body, label in trials:
        logger.debug("尝试（%s）：%s | %s", label, _mask_secrets(u),
                     _mask_secrets((body or "(GET)")[:200]))
        if body is None:
            r = sess.get(u)
        else:
            r = sess.post_raw(u, body, referer=final_url,
                              headers={"Origin": f"http://{host}"})
        if r.error:
            logger.debug("  → 连接失败：%s", r.error)
            last_body, last_label = r.error, label
            continue
        last_body, last_label = r.body or "", label
        hdrs = r.headers or {}
        logger.debug("  → HTTP %s | Server=%s | %d 字符",
                     r.status, hdrs.get("server", "?"), len(last_body))
        logger.debug("  → 正文摘要：%s", _html_text(last_body, 500))
        _dump_text(f"login_try_{_mask_secrets(u)}", last_body, logger)
        blob = f"{last_body} {r.final_url or ''}"
        low = blob.replace(" ", "").lower()
        if ok_mark in blob or '"result":1' in low or '"result":"success"' in low:
            return LoginOutcome.OK, f"{label} 认证通过", last_body
        msg_m = re.search(r'"msg"\s*:\s*"([^"]{2,120})"', last_body)
        if msg_m:
            logger.debug("  → 服务器说明：%s", msg_m.group(1))
        if fail_mark in blob:
            saw_fail_mark = True
            logger.debug("  → 命中失败标志 %s（继续尝试其它接口）", fail_mark)
            logger.debug("  → 该页含脚本的文本：%s",
                         _html_text(last_body, 400, keep_script=True))
    if saw_fail_mark:
        return LoginOutcome.FAILED, (
            _drcom_fail_message(last_body)
            or "Dr.COM 返回失败页（完整正文见 logs/login_try_*.html）"), last_body
    return (LoginOutcome.RETRY,
            f"各候选接口均未返回成功（最后尝试：{last_label}），交由复检判定",
            last_body)


def _logout_drcom(portal_url, timeout, enc) -> tuple:
    base = _url_base(portal_url)
    if not base:
        return False, f"认证地址非法：{portal_url}"
    host = urlparse(base).hostname or ""
    sess = HttpSession(timeout=timeout, encoding=enc)
    page = sess.get(portal_url)
    pc = _parse_portal_js_config(page.body or "") if not page.error else {}
    path = pc.get("authlogoutpath") or "/eportal/?c=ACSetting&a=Logout&ver=1.0"
    port = int(pc.get("authlogoutport") or 801)
    if not _port_open(host, port):
        port = 80
    r = sess.get(f"http://{host}:{port}{path}")
    return (not r.error), (r.error or "已请求 Dr.COM 断开")


# -------- 适配器 4：通用表单（解析页面 form 自动填表提交） --------

def _login_form(portal_url, username, password, timeout, enc, logger) -> tuple:
    # 同样走会话：不少门户的登录校验依赖浏览过程中种下的 Cookie
    sess = HttpSession(timeout=timeout, encoding=enc)
    page = sess.get(portal_url)
    if page.error:
        return LoginOutcome.RETRY, f"无法打开登录页：{page.error}", ""

    final_url = page.final_url or portal_url
    logger.debug("登录页最终地址：%s | Cookie：%s",
                 final_url, sess.cookie_header() or "(空)")
    forms = parse_forms(page.body, final_url)
    if not forms:
        return LoginOutcome.RETRY, "登录页未找到任何表单，请在配置中使用 custom 模式", page.body[:400]

    logger.debug("发现 %d 个表单：%s", len(forms),
                 [(f["action"], f["method"], len(f["inputs"])) for f in forms])

    # 优先选择含密码框的表单
    forms.sort(key=lambda f: (0 if any(i["role"] == "password" for i in f["inputs"]) else 1,
                              -len(f["inputs"])))
    form = forms[0]

    fields = []
    filled_user = filled_pwd = False
    for inp in form["inputs"]:
        name = inp.get("name") or inp.get("id")
        if not name:
            continue
        if inp["role"] == "username":
            fields.append((name, username))
            filled_user = True
        elif inp["role"] == "password":
            fields.append((name, password))
            filled_pwd = True
        elif inp["type"] not in ("submit", "button", "image", "reset"):
            fields.append((name, inp.get("value", "")))   # 保留 hidden/固定值

    if not (filled_user and filled_pwd):
        return (LoginOutcome.RETRY,
                f"表单字段无法自动识别（用户名={filled_user} 密码={filled_pwd}），"
                "请在配置中使用 custom 模式手工指定字段名", page.body[:400])

    action = form["action"] or final_url
    body = urlencode(fields, encoding=enc)
    logger.debug("提交表单 %s：%s", action, [f[0] for f in fields])

    if form["method"] == "get":
        r = sess.get(f"{action}?{body}")
    else:
        r = sess.post_raw(action, body, referer=final_url)
    if r.error:
        return LoginOutcome.RETRY, f"表单提交失败：{r.error}", ""
    logger.debug("表单响应：%s", r.body[:300])
    return _judge_response(r.body, r.status), "登录表单已自动填写并提交", r.body


# -------- 适配器 5：完全自定义 --------

def _login_custom(cfg, username, password, timeout, enc, logger) -> tuple:
    c = cfg.get("auth", {}).get("custom", {}) or {}
    url_tpl = (c.get("url") or "").strip()
    if not url_tpl:
        return LoginOutcome.NO_CONFIG, "custom 模式下未配置 auth.custom.url", ""

    def sub(text: str, need_quote: bool = True) -> str:
        v = str(text)
        u = quote(username, safe="") if need_quote else username
        p = quote(password, safe="") if need_quote else password
        return v.replace("{username}", u).replace("{password}", p) \
                .replace("{ip}", local_ip())

    params = {}
    for k, v in (c.get("params") or {}).items():
        params[k] = sub(v)
    headers = {k: sub(v, need_quote=False) for k, v in (c.get("headers") or {}).items()}

    method = (c.get("method") or "POST").upper()
    url = sub(url_tpl)
    if method == "GET":
        sep = "&" if "?" in url else "?"
        target = f"{url}{sep}{urlencode(params, encoding=enc)}" if params else url
        r = http_get(target, timeout=timeout, encoding=enc)
    else:
        r = http_post(url, urlencode(params, encoding=enc), timeout=timeout,
                      encoding=enc, headers=headers)
    if r.error:
        return LoginOutcome.RETRY, f"自定义接口提交失败：{r.error}", ""
    logger.debug("custom 响应：%s", r.body[:300])
    return (_judge_response(r.body, r.status,
                            c.get("failure_keywords"), c.get("success_keywords")),
            "自定义接口已提交", r.body)


# -------- 统一分发 --------

def perform_login(cfg: dict, logger=None, portal_url: str = "") -> tuple:
    """
    执行一次认证尝试（不含重试与复检）。
    返回 (verdict, message, raw)
    """
    logger = logger or log()
    auth = cfg.get("auth", {})
    username = (auth.get("username") or "").strip()
    password = get_password(cfg)
    enc = auth.get("encoding") or "utf-8"
    timeout = float(cfg.get("network", {}).get("timeout", 8))

    if not portal_url:
        portal_url = (auth.get("login_url") or "").strip()
    if not portal_url:
        return LoginOutcome.NO_CONFIG, "未配置校园网登录网址（auth.login_url）", ""
    if not username:
        return LoginOutcome.NO_CONFIG, "未配置账号（auth.username）", ""
    if not password:
        return LoginOutcome.NO_CONFIG, "未配置密码或密文无法解密", ""

    adapter = (auth.get("adapter") or "auto").lower()
    if adapter in ("auto", ""):
        probe = http_get(portal_url, timeout=timeout, max_redirect=2, encoding=enc)
        adapter = detect_adapter(probe.final_url or portal_url, probe.body)
        logger.info("自动识别认证系统类型：%s", adapter)

    logger.info("开始认证：类型=%s 账号=%s 地址=%s", adapter, _mask_user(username), portal_url)

    if adapter == "srun":
        return _login_srun(portal_url, username, password, timeout, enc, logger)
    if adapter == "eportal":
        return _login_eportal(portal_url, username, password, timeout, enc, logger)
    if adapter == "drcom":
        return _login_drcom(portal_url, username, password, timeout, enc, logger)
    if adapter == "custom":
        return _login_custom(cfg, username, password, timeout, enc, logger)
    return _login_form(portal_url, username, password, timeout, enc, logger)


def _mask_user(u: str) -> str:
    if not u:
        return "(空)"
    if len(u) <= 3:
        return u[0] + "*" * (len(u) - 1)
    return u[:2] + "*" * (len(u) - 3) + u[-1]


def perform_logout(cfg: dict, logger=None) -> tuple:
    logger = logger or log()
    auth = cfg.get("auth", {})
    url = (auth.get("logout_url") or auth.get("login_url") or "").strip()
    enc = auth.get("encoding") or "utf-8"
    timeout = float(cfg.get("network", {}).get("timeout", 8))
    if not url:
        return False, "未配置登录/断开地址，无法自动断开"

    if auth.get("logout_url"):
        r = http_get(url, timeout=timeout, encoding=enc)
        return (not r.error), (r.error or "已请求断开地址")

    adapter = (auth.get("adapter") or "auto").lower()
    if adapter in ("auto", ""):
        probe = http_get(url, timeout=timeout, max_redirect=2, encoding=enc)
        adapter = detect_adapter(probe.final_url or url, probe.body)
    if adapter == "srun":
        return _logout_srun(url, timeout, enc)
    if adapter == "eportal":
        return _logout_eportal(url, timeout, enc)
    if adapter == "drcom":
        return _logout_drcom(url, timeout, enc)
    return False, ("当前认证系统（%s）没有通用的断开接口，"
                   "可在配置中填写 auth.logout_url 指定断开地址" % adapter)


# ============================================================================
# [7] 认证服务编排
# ============================================================================

class ConnectResult:
    def __init__(self, ok: bool, verdict: str, message: str,
                 status: NetStatus | None = None, attempts: int = 1,
                 elapsed: float = 0.0):
        self.ok = ok
        self.verdict = verdict
        self.message = message
        self.status = status
        self.attempts = attempts
        self.elapsed = elapsed

    def as_dict(self) -> dict:
        return {"ok": self.ok, "verdict": self.verdict, "message": self.message,
                "attempts": self.attempts, "elapsed": round(self.elapsed, 1),
                "status": self.status.as_dict() if self.status else None}


def connect(cfg: dict, logger=None, force: bool = False) -> ConnectResult:
    """
    完整的「检测 → 登录 → 复检」流程。
    force=False 时，若检测到已在线则直接返回成功且不重复登录。
    """
    logger = logger or log()
    t0 = time.time()

    st = check_network(cfg, quick=False)
    logger.info("联网检测：%s（%s）", st.text, st.detail or "-")
    if st.portal_url:
        logger.info("认证服务器地址：%s", st.portal_url)

    if st.state == ST_ONLINE and not force:
        logger.info("当前已在线，跳过登录")
        return ConnectResult(True, LoginOutcome.OK, "已在线，无需重复登录", st, 0,
                             time.time() - t0)

    if st.state == ST_OFFLINE:
        logger.warning("网络不通：%s", st.detail)
        return ConnectResult(False, LoginOutcome.OFFLINE,
                             f"网络不通：{st.detail}", st, 0, time.time() - t0)

    portal_url = st.portal_url or (cfg.get("auth", {}).get("login_url") or "").strip()
    net = cfg.get("network", {})
    retry = max(1, int(net.get("retry", 3)))
    wait = float(net.get("retry_interval", 6))
    verify = bool(cfg.get("advanced", {}).get("verify_by_recheck", True))

    last_msg = ""
    for i in range(1, retry + 1):
        logger.info("第 %d/%d 次尝试登录…", i, retry)
        verdict, msg, raw = perform_login(cfg, logger, portal_url)
        last_msg = msg
        logger.info("登录响应判定：%s（%s）", LoginOutcome.TEXT.get(verdict, verdict), msg)
        if raw:
            logger.debug("原始响应片段：%s", raw[:500])

        if verdict == LoginOutcome.NO_CONFIG:
            return ConnectResult(False, verdict, msg, st, i, time.time() - t0)

        if verdict == LoginOutcome.FAILED:
            # 明确的失败（密码错误等）不重试，避免连续错误导致账号被锁
            logger.error("认证失败：%s", msg)
            return ConnectResult(False, verdict, msg, st, i, time.time() - t0)

        if verify:
            time.sleep(1.0)
            st2 = check_network(cfg, quick=True)
            logger.info("复检结果：%s", st2.text)
            if st2.state == ST_ONLINE:
                logger.info("登录成功，已联网")
                return ConnectResult(True, LoginOutcome.OK, "登录成功，已联网",
                                     st2, i, time.time() - t0)
            if st2.state == ST_PORTAL:
                last_msg = "提交后仍处于未认证状态，可能需要重新登录"
                verdict = LoginOutcome.RELOGIN
            elif st2.state == ST_OFFLINE:
                last_msg = "复检时网络不可达"
        else:
            return ConnectResult(verdict == LoginOutcome.OK, verdict, msg, st, i,
                                 time.time() - t0)

        if i < retry:
            logger.warning("本次未成功（%s），%d 秒后重试…", last_msg, int(wait))
            time.sleep(wait)

    return ConnectResult(False, LoginOutcome.RELOGIN if "重新登录" in last_msg else LoginOutcome.RETRY,
                         last_msg or "多次尝试后仍未登录成功", st, retry,
                         time.time() - t0)


def _has_local_ip() -> bool:
    """
    本机是否已拿到可用的 IPv4（不依赖 DNS / 外网）。

    开机那几十秒里 DNS 常常还没就绪，此时 check_network() 会判成"网络不通"，
    但网卡其实已经拿到 IP、只是解析不了域名。用 UDP connect 选路就能读到本机地址
    （UDP 不会真的发包，只是为了触发一次路由选择）。
    """
    for target in ("223.5.5.5", "114.114.114.114"):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(1.0)
                s.connect((target, 80))
                ip = s.getsockname()[0]
            if ip and not ip.startswith(("127.", "169.254.")):
                return True
        except OSError:
            continue
    return False


def wait_for_network(cfg: dict, logger=None, max_wait: float | None = None) -> bool:
    """
    开机场景：等待网络链路就绪（网卡/驱动/DHCP 可能需要时间）。

    判据分两层，缺一不可：
      ① 网卡已拿到 IP —— 不依赖 DNS，能过关就说明链路通了；
      ② check_network() 不再报"不通"。
    只看 ② 的话，开机时 DNS 未就绪会被误判成"网络不通"，白白空等。
    """
    logger = logger or log()
    net = cfg.get("network", {})
    limit = float(net.get("startup_wait", 180) if max_wait is None else max_wait)
    t0 = time.time()
    while time.time() - t0 < limit:
        st = check_network(cfg, quick=True)
        if st.state != ST_OFFLINE:
            logger.info("网络已就绪（%s），耗时 %d 秒", st.text, int(time.time() - t0))
            return True
        if _has_local_ip():
            logger.info("本机已获得 IP（%s），判定链路就绪（DNS 可能稍后才通），耗时 %d 秒",
                        local_ip() or "-", int(time.time() - t0))
            return True
        logger.info("网络尚未就绪，5 秒后重试…")
        time.sleep(5)
    logger.warning("等待网络就绪超时（%d 秒）", int(limit))
    return False


# ============================================================================
# [8] 开机自启动（HKCU Run 注册表键，无需管理员权限）
# ============================================================================

RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"


def _pythonw() -> str:
    """优先使用 pythonw.exe（无黑窗）。"""
    exe = sys.executable
    if not IS_FROZEN:
        cand = os.path.join(os.path.dirname(exe), "pythonw.exe")
        if os.path.exists(cand):
            return cand
    return exe


def launch_command(args: str = "--startup") -> str:
    """生成注册表里要写的完整启动命令。"""
    if IS_FROZEN:
        base = f'"{sys.executable}"'
    else:
        base = f'"{_pythonw()}" "{os.path.abspath(__file__)}"'
    return f"{base} {args}".strip()


def autostart_get() -> str | None:
    """返回当前注册表中的启动命令；未启用返回 None。"""
    if not IS_WINDOWS:
        return None
    import winreg
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY) as k:
            try:
                return winreg.QueryValueEx(k, APP_NAME)[0]
            except FileNotFoundError:
                return None
    except OSError:
        return None


def autostart_enable(args: str = "--startup") -> tuple:
    if not IS_WINDOWS:
        return False, "当前系统不是 Windows，注册表方式不可用"
    import winreg
    cmd = launch_command(args)
    try:
        with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, RUN_KEY, 0,
                                winreg.KEY_SET_VALUE) as k:
            winreg.SetValueEx(k, APP_NAME, 0, winreg.REG_SZ, cmd)
        log().info("已启用开机自启动：%s", cmd)
        return True, cmd
    except Exception as e:
        return False, f"写入注册表失败：{e}"


def autostart_disable() -> tuple:
    if not IS_WINDOWS:
        return False, "当前系统不是 Windows"
    import winreg
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0,
                            winreg.KEY_SET_VALUE) as k:
            winreg.DeleteValue(k, APP_NAME)
        log().info("已关闭开机自启动")
        return True, "已关闭"
    except FileNotFoundError:
        return True, "本来就未启用"
    except Exception as e:
        return False, f"删除注册表项失败：{e}"


def autostart_status_text() -> str:
    cmd = autostart_get()
    if cmd:
        return f"已启用\n{cmd}"
    return "未启用"


# ============================================================================
# [9] 命令行入口
# ============================================================================

def _print_status(cfg: dict) -> int:
    st = check_network(cfg)
    print(f"状态：{st.text}")
    print(f"详情：{st.detail or '-'}")
    if st.portal_url:
        print(f"认证地址：{st.portal_url}")
    print(f"本机 IP：{local_ip() or '未知'}")
    print(f"检测耗时：{st.latency_ms} ms")
    return 0


INTERFACE_HINTS = [
    r"/eportal/InterFace\.do\?method=\w+",
    r"/srun_portal[_a-zA-Z]*\?[^\s\"'<>)]*",
    r"/cgi-bin/[a-zA-Z_]+/srun_portal",
    r"/drcom[a-zA-Z_/]*",
    r"/[a-zA-Z0-9_/]*login[a-zA-Z0-9_/]*\.(?:do|jsp|php|asp)",
]


def _scan_interface_hints(body: str) -> list[str]:
    """从门户页面里搜出登录接口路径，帮助判断该用哪个适配器。"""
    found: list[str] = []
    for pat in INTERFACE_HINTS:
        for m in re.finditer(pat, body or "", re.I):
            s = m.group(0).strip()
            if s and s not in found:
                found.append(s)
    return found[:12]


def _finish_probe(lines: list) -> str:
    """汇总探测结果，同时落盘一份，方便直接把这一个文件发出去排查。"""
    path = os.path.join(log_dir(), "probe_result.txt")
    try:
        os.makedirs(log_dir(), exist_ok=True)
        lines.append("")
        lines.append(f"（本结果已保存到：{path}）")
        text = "\n".join(lines)
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
        return text
    except Exception:
        return "\n".join(lines)


def probe_portal(cfg: dict) -> str:
    """
    探测认证页：走一遍重定向、打印最终地址与页面里的表单结构。
    用户可据此判断该用哪个适配器、需要配哪些字段。
    """
    cfg_url = (cfg.get("auth", {}).get("login_url") or "").strip()
    timeout = float(cfg.get("network", {}).get("timeout", 8))
    lines: list[str] = []
    st = check_network(cfg)
    lines.append(f"[1] 联网检测    ：{st.text}（{st.detail or '-'}）")
    if st.portal_url:
        lines.append(f"    重定向到    ：{st.portal_url}")
    target = st.portal_url or cfg_url

    if st.state == ST_ONLINE and not st.portal_url and not cfg_url:
        lines.append("")
        lines.append("[!] 当前已通过认证，探测不到门户地址 —— 门户通常只在未认证网段可达。")
        lines.append("    请在掉线、需要重新登录时再跑一次；或者把浏览器里打开的")
        lines.append("    登录页地址填到 auth.login_url 后再跑一次。")
        return _finish_probe(lines)

    if not target:
        lines.append("[!] 未配置 auth.login_url，且未能从探测中获得认证地址")
        return _finish_probe(lines)

    lines.append(f"[2] 访问认证入口：{target}")
    sess = HttpSession(timeout=timeout)
    res = sess.get(target)
    if res.error:
        lines.append(f"    [!] 访问失败：{res.error}")
        if st.state == ST_ONLINE:
            lines.append("        当前已通过认证，门户地址在认证状态下通常不可达 ——")
            lines.append("        这不代表地址填错了，请等未认证时再探测一次。")
        return _finish_probe(lines)
    final_url = res.final_url or target
    lines.append(f"    HTTP {res.status}   最终地址：{final_url}")
    lines.append(f"    会话 Cookie：{sess.cookie_header() or '(无)'}")

    base = _url_base(final_url)
    adapter = detect_adapter(final_url, res.body)
    lines.append(f"[3] 识别系统类型：{adapter}（可写入 auth.adapter）")
    pc = _parse_portal_js_config(res.body or "")
    if pc:
        lines.append("    门户声明的认证配置（登录将照此构造请求）：")
        for k in sorted(pc):
            if k == "carrier":
                continue
            lines.append(f"      {k} = {pc[k]}")

    query = _query_of(final_url)
    if query:
        lines.append(f"[4] queryString ：{query[:300]}")
    else:
        # URL 上没有，试着从页面 JS 里提取 —— 这是登录能否成功的关键参数
        query = _extract_query_from_page(res.body)
        if query:
            lines.append(f"[4] queryString ：{query[:300]}")
            lines.append("    来源：认证页 JS 变量（不是 URL 参数）")
        else:
            lines.append("[4] queryString ：未取到 —— 登录很可能被判参数非法（Error code 203），"
                         "请把本文件发回以便进一步分析")

    hints = _scan_interface_hints(res.body)
    if hints:
        lines.append("[5] 页面内的接口线索：")
        for h in hints:
            lines.append(f"    {h}")
    else:
        lines.append("[5] 页面内未发现明显的登录接口路径")

    forms = parse_forms(res.body, final_url)
    if not forms:
        lines.append("[6] 未解析到表单（可能是纯 JS 提交，建议改用 custom 模式）")
    else:
        lines.append(f"[6] 解析到 {len(forms)} 个表单：")
        for idx, f in enumerate(forms, 1):
            lines.append(f"    #{idx} action={f['action']}")
            lines.append(f"        method={f['method']}")
            for inp in f["inputs"]:
                role = f"  <== 自动填充[{inp['role']}]" if inp["role"] else ""
                lines.append(f"        {inp['type']:8s} {inp['name'] or '(无 name)':22s}"
                             f" value={inp.get('value', '')[:30]}{role}")
    if adapter == "drcom":
        lines.append("[7] Dr.COM 认证端口可达性：")
        host = urlparse(base).hostname if base else ""
        for p in dict.fromkeys([int(pc.get("authloginport") or 801), 80]):
            lines.append(f"    {host}:{p} —— "
                         f"{'可连接' if _port_open(host, int(p)) else '不可达'}")
    elif adapter == "eportal" and base:
        pi = sess.post(f"{base}/eportal/InterFace.do?method=pageInfo",
                       {"queryString": query}, referer=final_url)
        lines.append("[7] pageInfo 预检：")
        if pi.error:
            lines.append(f"    调用失败：{pi.error}")
        else:
            body = (pi.body or "").strip()
            lines.append(f"    HTTP {pi.status}")
            lines.append(f"    {body[:400] or '(空响应)'}")

    lines.append("")
    lines.append("把以上内容整段发回来，就能据此确定 adapter 与所需参数。")
    return _finish_probe(lines)


CONSOLE_ARGS = {"--status", "--connect", "--probe", "--show-config",
                "--autostart", "--set-account", "--set-url", "--silent"}


def ensure_console(argv) -> None:
    """
    打包成 --windowed 的 exe 后没有控制台，print 的输出会丢失。
    当用户带命令行参数调用时，主动附着到父控制台，让 --status / --connect 等
    命令的输出能被看见。
    """
    if not IS_FROZEN or sys.stdout is not None:
        return
    args = list(argv) if argv is not None else sys.argv[1:]
    if not args or "--gui" in args or "--startup" in args:
        return
    if not any(a in CONSOLE_ARGS for a in args):
        return
    try:
        if ctypes.windll.kernel32.AttachConsole(-1):        # ATTACH_PARENT_PROCESS
            # 按控制台实际代码页输出，否则中文在 GBK 控制台下会乱码
            cp = ctypes.windll.kernel32.GetConsoleOutputCP()
            enc = "utf-8" if cp in (0, 65001) else f"cp{cp}"
            try:
                stream = open("CONOUT$", "w", encoding=enc, errors="replace",
                              buffering=1)
            except (LookupError, OSError):
                stream = open("CONOUT$", "w", encoding="utf-8",
                              errors="replace", buffering=1)
            sys.stdout = stream
            sys.stderr = stream
    except Exception:
        pass


def cli(argv=None) -> int:
    ensure_console(argv)
    parser = argparse.ArgumentParser(
        prog="campus_login",
        description="校园以太网自动登录助手（零第三方依赖）")
    parser.add_argument("--gui", action="store_true", help="打开图形控制面板（默认）")
    parser.add_argument("--startup", action="store_true",
                        help="开机自启模式：自动连接并最小化窗口，附带断线重连")
    parser.add_argument("--silent", action="store_true",
                        help="无窗口后台模式，仅写日志")
    parser.add_argument("--connect", action="store_true", help="执行一次登录并退出")
    parser.add_argument("--force", action="store_true", help="即使已在线也强制重新登录")
    parser.add_argument("--status", action="store_true", help="打印当前联网状态")
    parser.add_argument("--probe", action="store_true", help="探测认证页并打印表单结构")
    parser.add_argument("--set-account", nargs=2, metavar=("USER", "PASS"),
                        help="在命令行设置账号密码（密码会被加密保存）")
    parser.add_argument("--set-url", metavar="URL", help="设置校园网登录网址")
    parser.add_argument("--autostart", choices=["on", "off", "status"],
                        help="启用/关闭/查看开机自启动")
    parser.add_argument("--show-config", action="store_true", help="打印配置文件路径与内容")
    args = parser.parse_args(argv)

    logger = setup_logging()
    cfg = load_config()

    # ---- 纯配置类命令（不启动界面）----
    if args.set_account:
        cfg["auth"]["username"] = args.set_account[0]
        set_password(cfg, args.set_account[1])
        save_config(cfg)
        logger.info("已保存账号：%s", _mask_user(args.set_account[0]))
        print(f"已保存账号 {args.set_account[0]}，密码已用 {crypto_backend()} 加密写入：{config_file()}")
        return 0

    if args.set_url:
        cfg["auth"]["login_url"] = args.set_url
        save_config(cfg)
        print(f"已设置登录网址：{args.set_url}")
        return 0

    if args.autostart:
        if args.autostart == "on":
            ok, info = autostart_enable(cfg.get("autostart", {}).get("args", "--startup"))
            print(("已启用开机自启动：\n  " + info) if ok else f"启用失败：{info}")
            if ok:
                cfg.setdefault("autostart", {})["enabled"] = True
                save_config(cfg)
        elif args.autostart == "off":
            ok, info = autostart_disable()
            print("已关闭开机自启动" if ok else f"关闭失败：{info}")
            if ok:
                cfg.setdefault("autostart", {})["enabled"] = False
                save_config(cfg)
        else:
            print("开机自启动状态：" + autostart_status_text())
        return 0

    if args.show_config:
        print(f"配置文件：{config_file()}")
        safe = json.loads(json.dumps(cfg))
        if safe.get("auth", {}).get("password_enc"):
            safe["auth"]["password_enc"] = "<已加密，长度 %d>" % len(safe["auth"]["password_enc"])
        print(json.dumps(safe, ensure_ascii=False, indent=2))
        print(f"日志文件：{log_file()}")
        return 0

    if args.status:
        return _print_status(cfg)

    if args.probe:
        print(probe_portal(cfg))
        return 0

    if args.connect:
        # 手动执行时用户在等结果，等待网络就绪的时间不宜过长（开机模式才需要久等）
        manual_wait = min(float(cfg.get("network", {}).get("startup_wait", 180)), 30.0)
        if not wait_for_network(cfg, logger, max_wait=manual_wait):
            print("网络未就绪，登录已放弃")
            return 2
        r = connect(cfg, logger, force=args.force)
        print(f"[{LoginOutcome.TEXT.get(r.verdict, r.verdict)}] {r.message}"
              f"（尝试 {r.attempts} 次，用时 {r.elapsed:.1f}s）")
        return 0 if r.ok else 1

    if args.silent:
        return run_silent(cfg, logger)

    # ---- 默认：图形界面 ----
    return run_gui(cfg, logger, startup=args.startup)


def run_silent(cfg: dict, logger) -> int:
    """无窗口后台守护：等待网络 → 登录 → 周期性检查，掉线自动重连。"""
    logger.info("=== 后台守护模式启动 ===")
    wait_for_network(cfg, logger)
    r = connect(cfg, logger)
    logger.info("首次登录结果：%s", r.message)
    interval = int(cfg.get("network", {}).get("watch_interval", 45))
    while True:
        time.sleep(interval)
        st = check_network(cfg, quick=True)
        if st.state != ST_ONLINE:
            logger.warning("检测到状态异常（%s），尝试重新登录…", st.text)
            connect(cfg, logger)
    return 0


# ============================================================================
# [10] 图形控制面板
# ============================================================================

# ---- 配色（浅色主题）----
C_BG = "#f4f5f7"
C_CARD = "#ffffff"
C_LINE = "#e3e6ea"
C_TEXT = "#1f2430"
C_SUB = "#6b7280"
C_ACCENT = "#2563eb"
C_ACCENT_HOVER = "#1d4ed8"
C_OK = "#16a34a"
C_WARN = "#d97706"
C_ERR = "#dc2626"
C_GRAY = "#9ca3af"
C_BTN_BG = "#f1f3f5"
C_BTN_HOVER = "#e4e7eb"

FONT = "Microsoft YaHei UI"


def _mk_button(master, text, command, kind="normal", width=None):
    """统一的扁平按钮（tk 原生控件，悬停色存对象属性，避免 configure 报错）。"""
    palettes = {
        "primary": (C_ACCENT, "#ffffff", C_ACCENT_HOVER),
        "normal": (C_BTN_BG, C_TEXT, C_BTN_HOVER),
        "danger": ("#fee2e2", C_ERR, "#fecaca"),
    }
    bg, fg, hover = palettes.get(kind, palettes["normal"])
    b = tk.Button(master, text=text, command=command, bg=bg, fg=fg,
                  activebackground=hover, activeforeground=fg,
                  font=(FONT, 10), relief="flat", bd=0,
                  cursor="hand2", padx=12, pady=6,
                  highlightthickness=0)
    if width:
        b.configure(width=width)
    b._hover = hover
    b._base = bg
    b.bind("<Enter>", lambda e: b.configure(bg=b._hover) if str(b["state"]) == "normal" else None)
    b.bind("<Leave>", lambda e: b.configure(bg=b._base) if str(b["state"]) == "normal" else None)
    return b


class Switch(_TK_CANVAS):
    """自绘开关（tk.Checkbutton 在浅色卡片上观感差，且不易统一配色）。"""

    def __init__(self, master, command=None, on=False, bg=C_CARD):
        # 注意：不能用 self._w / self._h —— tkinter 用 _w 存 widget 路径名，会被覆盖
        self._sw, self._sh = 46, 24
        super().__init__(master, width=self._sw, height=self._sh, bg=bg,
                         highlightthickness=0, bd=0, cursor="hand2")
        self._on = bool(on)
        self._cmd = command
        self.bind("<Button-1>", self._click)
        self._draw()

    def _draw(self):
        self.delete("all")
        w, h = self._sw, self._sh
        r = h // 2
        track = C_ACCENT if self._on else "#cbd1d8"
        self.create_oval(0, 0, 2 * r, h, fill=track, outline=track)
        self.create_oval(w - 2 * r, 0, w, h, fill=track, outline=track)
        self.create_rectangle(r, 0, w - r, h, fill=track, outline=track)
        cx = w - r if self._on else r
        self.create_oval(cx - r + 3, 3, cx + r - 3, h - 3, fill="#ffffff", outline="")

    def _click(self, _e=None):
        self._on = not self._on
        self._draw()
        if self._cmd:
            self._cmd(self._on)

    def set(self, value, notify=False):
        self._on = bool(value)
        self._draw()
        if notify and self._cmd:
            self._cmd(self._on)

    def get(self) -> bool:
        return self._on


class StatusDot(_TK_CANVAS):
    """状态指示灯。"""
    def __init__(self, master, bg=C_CARD):
        super().__init__(master, width=14, height=14, bg=bg,
                         highlightthickness=0, bd=0)
        self._color = C_GRAY
        self._draw()

    def set(self, color):
        self._color = color
        self._draw()

    def _draw(self):
        self.delete("all")
        self.create_oval(1, 1, 13, 13, fill=self._color, outline="")


class App:
    """控制面板主窗口。"""

    def __init__(self, root, cfg, logger, startup=False):
        self.root = root
        self.cfg = cfg
        self.logger = logger
        self.startup = startup
        self.q = queue.Queue()
        self.busy = False
        self.watching = False
        self.last_status = None
        self._closing = False          # 关窗后停止一切定时回调

        self._base_scaling = 1.0
        self._build()
        self._apply_scaling()
        self._autosize()
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.root.after(200, self._poll)
        self.refresh_log()
        self.refresh_status_async()

        if startup:
            try:
                self.root.iconify()
            except Exception:
                pass
            self.root.after(800, self._auto_start)

    # ---------- 界面搭建 ----------

    def _build(self):
        r = self.root
        r.title(f"{APP_TITLE} v{APP_VERSION}")
        r.configure(bg=C_BG)
        r.resizable(False, False)
        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            pass

        outer = tk.Frame(r, bg=C_BG)
        outer.pack(fill="both", expand=True, padx=16, pady=14)

        # --- 顶部标题 ---
        head = tk.Frame(outer, bg=C_BG)
        head.pack(fill="x")
        tk.Label(head, text=APP_TITLE, bg=C_BG, fg=C_TEXT,
                 font=(FONT, 14, "bold")).pack(side="left")
        self.ver_lbl = tk.Label(head, text=f"v{APP_VERSION}  ·  {crypto_backend()}",
                                bg=C_BG, fg=C_SUB, font=(FONT, 8))
        self.ver_lbl.pack(side="right")

        # --- 状态卡片 ---
        st_card = tk.Frame(outer, bg=C_CARD, highlightbackground=C_LINE,
                           highlightthickness=1)
        st_card.pack(fill="x", pady=(10, 0))
        inner = tk.Frame(st_card, bg=C_CARD)
        inner.pack(fill="x", padx=14, pady=12)

        line1 = tk.Frame(inner, bg=C_CARD)
        line1.pack(fill="x")
        self.dot = StatusDot(line1)
        self.dot.pack(side="left", padx=(0, 8))
        self.state_lbl = tk.Label(line1, text="状态未知", bg=C_CARD, fg=C_TEXT,
                                  font=(FONT, 12, "bold"), width=20, anchor="w")
        self.state_lbl.pack(side="left")
        self.ip_lbl = tk.Label(line1, text="IP  —", bg=C_CARD, fg=C_SUB,
                               font=(FONT, 9), width=18, anchor="e")
        self.ip_lbl.pack(side="right")

        self.detail_lbl = tk.Label(inner, text="正在检测…", bg=C_CARD, fg=C_SUB,
                                   font=(FONT, 9), width=54, anchor="w")
        self.detail_lbl.pack(fill="x", pady=(6, 0))

        self.time_lbl = tk.Label(inner, text="上次检测：—", bg=C_CARD, fg=C_GRAY,
                                 font=(FONT, 8), width=54, anchor="w")
        self.time_lbl.pack(fill="x", pady=(2, 0))

        # --- 账号卡片 ---
        acc_card = tk.Frame(outer, bg=C_CARD, highlightbackground=C_LINE,
                            highlightthickness=1)
        acc_card.pack(fill="x", pady=(10, 0))
        a_in = tk.Frame(acc_card, bg=C_CARD)
        a_in.pack(fill="x", padx=14, pady=12)

        a_head = tk.Frame(a_in, bg=C_CARD)
        a_head.pack(fill="x")
        tk.Label(a_head, text="登录信息", bg=C_CARD, fg=C_TEXT,
                 font=(FONT, 10, "bold")).pack(side="left")
        self.acct_state = tk.Label(a_head, text="", bg=C_CARD, fg=C_WARN,
                                   font=(FONT, 8), width=22, anchor="e")
        self.acct_state.pack(side="right")

        self.user_lbl = self._kv(a_in, "账号", "—")
        self.pwd_lbl = self._kv(a_in, "密码", "—")
        self.url_lbl = self._kv(a_in, "登录网址", "—")

        btn_row = tk.Frame(a_in, bg=C_CARD)
        btn_row.pack(fill="x", pady=(8, 0))
        self.btn_set = _mk_button(btn_row, "设置账号密码", self.open_settings, "normal")
        self.btn_set.pack(side="left")
        self.btn_page = _mk_button(btn_row, "打开登录页", self.open_login_page, "normal")
        self.btn_page.pack(side="left", padx=8)
        self.btn_probe = _mk_button(btn_row, "探测认证页", self.do_probe, "normal")
        self.btn_probe.pack(side="left")

        # --- 操作按钮 ---
        act = tk.Frame(outer, bg=C_BG)
        act.pack(fill="x", pady=(12, 0))
        self.btn_conn = _mk_button(act, "立即连接", self.do_connect, "primary", width=12)
        self.btn_conn.pack(side="left")
        self.btn_disc = _mk_button(act, "断开连接", self.do_disconnect, "danger", width=12)
        self.btn_disc.pack(side="left", padx=8)
        self.btn_check = _mk_button(act, "检测状态", self.refresh_status_async, "normal", width=12)
        self.btn_check.pack(side="left")

        # --- 自启动卡片 ---
        auto_card = tk.Frame(outer, bg=C_CARD, highlightbackground=C_LINE,
                             highlightthickness=1)
        auto_card.pack(fill="x", pady=(12, 0))
        au_in = tk.Frame(auto_card, bg=C_CARD)
        au_in.pack(fill="x", padx=14, pady=10)

        au_top = tk.Frame(au_in, bg=C_CARD)
        au_top.pack(fill="x")
        tk.Label(au_top, text="开机自动登录", bg=C_CARD, fg=C_TEXT,
                 font=(FONT, 10, "bold")).pack(side="left")
        self.switch = Switch(au_top, command=self.on_switch_autostart,
                             on=bool(autostart_get()))
        self.switch.pack(side="right")

        self.auto_lbl = tk.Label(au_in, text="", bg=C_CARD, fg=C_SUB,
                                 font=(FONT, 8), width=56, anchor="w",
                                 justify="left")
        self.auto_lbl.pack(fill="x", pady=(4, 0))

        watch_row = tk.Frame(au_in, bg=C_CARD)
        watch_row.pack(fill="x", pady=(6, 0))
        self.watch_sw = Switch(watch_row, command=self.on_switch_watch, on=False)
        self.watch_sw.pack(side="left")
        tk.Label(watch_row, text="断线自动重连（每 45 秒检测一次）", bg=C_CARD,
                 fg=C_SUB, font=(FONT, 9)).pack(side="left", padx=8)

        # --- 日志卡片 ---
        log_card = tk.Frame(outer, bg=C_CARD, highlightbackground=C_LINE,
                            highlightthickness=1)
        log_card.pack(fill="both", expand=True, pady=(12, 0))
        lg_in = tk.Frame(log_card, bg=C_CARD)
        lg_in.pack(fill="both", expand=True, padx=14, pady=10)

        lg_head = tk.Frame(lg_in, bg=C_CARD)
        lg_head.pack(fill="x")
        tk.Label(lg_head, text="运行日志", bg=C_CARD, fg=C_TEXT,
                 font=(FONT, 10, "bold")).pack(side="left")
        _mk_button(lg_head, "刷新", self.refresh_log, "normal").pack(side="right")
        _mk_button(lg_head, "打开文件", self.open_log_file, "normal").pack(side="right", padx=6)
        _mk_button(lg_head, "清空", self.clear_log, "normal").pack(side="right")
        _mk_button(lg_head, "复制全部", self.copy_log, "normal").pack(side="right", padx=6)

        self.log_box = tk.Text(lg_in, height=11, width=68, bg="#fbfcfd",
                               fg="#333a45", font=("Consolas", 9), relief="flat",
                               bd=0, wrap="none", highlightbackground=C_LINE,
                               highlightthickness=1)
        self.log_box.pack(fill="both", expand=True, pady=(8, 0))
        sb = tk.Scrollbar(self.log_box, command=self.log_box.yview)
        self.log_box.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self.log_box.configure(state="disabled")

        # --- 底部状态条 ---
        self.hint_lbl = tk.Label(outer, text="就绪", bg=C_BG, fg=C_SUB,
                                 font=(FONT, 9), width=60, anchor="w")
        self.hint_lbl.pack(fill="x", pady=(8, 0))

        self.refresh_account_view()
        self.refresh_autostart_view()

    def _kv(self, master, key, value):
        row = tk.Frame(master, bg=C_CARD)
        row.pack(fill="x", pady=2)
        tk.Label(row, text=key, bg=C_CARD, fg=C_SUB, font=(FONT, 9),
                 width=8, anchor="w").pack(side="left")
        lbl = tk.Label(row, text=value, bg=C_CARD, fg=C_TEXT, font=(FONT, 9),
                       width=44, anchor="w")
        lbl.pack(side="left")
        return lbl

    # ---------- 尺寸自适应 ----------

    def _measure(self):
        r = self.root
        r.update_idletasks()
        r.update()
        return r.winfo_reqwidth(), r.winfo_reqheight()

    def _apply_scaling(self):
        try:
            base = self.root.winfo_fpixels("1i") / 72.0
            self._base_scaling = base
            self.root.tk.call("tk", "scaling", base)
        except Exception:
            self._base_scaling = 1.0

    def _autosize(self):
        r = self.root
        sw, sh = r.winfo_screenwidth(), r.winfo_screenheight()
        max_w, max_h = sw - 60, sh - 90
        scale = self._base_scaling
        w = h = 820
        for _ in range(12):
            w, h = self._measure()
            if (h <= max_h and w <= max_w) or scale <= 1.0:
                break
            scale = max(1.0, scale - 0.15)
            try:
                r.tk.call("tk", "scaling", scale)
            except Exception:
                break
        w = min(max(680, w), max_w)
        h = min(max(560, h), max_h)
        r.geometry(f"{w}x{h}+{(sw - w) // 2}+{max(16, (sh - h) // 2 - 40)}")

    # ---------- 视图刷新 ----------

    def refresh_account_view(self):
        auth = self.cfg.get("auth", {})
        user = (auth.get("username") or "").strip()
        url = (auth.get("login_url") or "").strip()
        pwd = get_password(self.cfg)
        self.user_lbl.configure(text=user or "（未设置）")
        self.pwd_lbl.configure(text=("●" * min(len(pwd), 12)) if pwd else "（未设置）")
        self.url_lbl.configure(text=(url[:44] + "…") if len(url) > 44 else (url or "（未设置）"))
        if user and pwd and url:
            self.acct_state.configure(text="配置完整", fg=C_OK)
        else:
            missing = [n for n, v in (("账号", user), ("密码", pwd), ("网址", url)) if not v]
            self.acct_state.configure(text="缺少：" + "/".join(missing), fg=C_WARN)

    def refresh_autostart_view(self):
        cmd = autostart_get()
        if cmd:
            self.auto_lbl.configure(text="当前状态：已启用 · " + cmd[:80], fg=C_OK)
        else:
            self.auto_lbl.configure(text="当前状态：未启用（开启后开机将自动运行并登录）",
                                    fg=C_SUB)

    def refresh_log(self):
        self.log_box.configure(state="normal")
        self.log_box.delete("1.0", "end")
        self.log_box.insert("1.0", read_log_tail(400))
        self.log_box.see("end")
        self.log_box.configure(state="disabled")

    def copy_log(self):
        try:
            self.root.clipboard_clear()
            self.root.clipboard_append(read_log_tail(400))
            self.hint("日志已复制到剪贴板")
        except Exception as e:
            self.hint(f"复制失败：{e}")

    def clear_log(self):
        path = log_file()
        try:
            if os.path.exists(path):
                open(path, "w", encoding="utf-8").close()
            self.refresh_log()
            self.hint("日志已清空")
        except Exception as e:
            self.hint(f"清空失败：{e}")

    def open_log_file(self):
        path = log_file()
        try:
            if not os.path.exists(path):
                os.makedirs(os.path.dirname(path), exist_ok=True)
                open(path, "a", encoding="utf-8").close()
            if IS_WINDOWS:
                os.startfile(path)          # noqa: S606
            else:
                webbrowser.open("file://" + path)
        except Exception as e:
            self.hint(f"打开失败：{e}")

    def hint(self, text, color=C_SUB):
        self.hint_lbl.configure(text=text, fg=color)

    def _set_busy(self, busy):
        """忙时禁用全部操作按钮，避免重复触发。"""
        self.busy = bool(busy)
        state = "disabled" if self.busy else "normal"
        for b in (self.btn_conn, self.btn_disc, self.btn_check,
                  self.btn_set, self.btn_page, self.btn_probe):
            b.configure(state=state,
                        bg=(b._base if state == "normal" else "#dfe3e8"))

    # ---------- 异步执行 ----------

    def _run_async(self, fn, *a, **kw):
        if self.busy:
            self.hint("正在执行中，请稍候…", C_WARN)
            return
        self._set_busy(True)

        def worker():
            try:
                result = fn(*a, **kw)
                self.q.put(("done", result))
            except Exception as e:
                import traceback
                traceback.print_exc()
                self.q.put(("error", str(e)))
        threading.Thread(target=worker, daemon=True).start()

    def _poll(self):
        if self._closing:
            return
        try:
            while True:
                try:
                    kind, payload = self.q.get_nowait()
                except queue.Empty:
                    break
                try:
                    if kind == "done":
                        self._on_task_done(payload)
                    elif kind == "status":
                        st, from_watch = payload
                        self._on_status(st)
                        if (from_watch and self.watching and not self.busy
                                and st.state != ST_ONLINE):
                            self.do_connect()
                    elif kind == "error":
                        self._set_busy(False)
                        self.hint(f"执行出错：{payload}", C_ERR)
                        self.refresh_log()
                except Exception:
                    import traceback
                    traceback.print_exc()
        finally:
            try:
                if not self._closing:
                    self.root.after(120, self._poll)
            except Exception:
                pass

    def _on_task_done(self, result):
        self._set_busy(False)
        self.refresh_log()
        self.refresh_account_view()
        if isinstance(result, ConnectResult):
            if result.ok:
                self.hint(f"✓ {result.message}（尝试 {result.attempts} 次，"
                          f"耗时 {result.elapsed:.1f}s）", C_OK)
            else:
                self.hint(f"✗ {result.message}", C_ERR)
            if result.status:
                self._on_status(result.status)
        elif isinstance(result, NetStatus):
            self._on_status(result)
        elif isinstance(result, dict):
            if result.get("kind") == "logout":
                self.hint(result.get("message", ""),
                          C_OK if result.get("ok") else C_WARN)
            elif result.get("kind") == "probe":
                self._show_text_window("认证页探测结果", result.get("text", ""))
        self.refresh_autostart_view()

    def _on_status(self, st: NetStatus):
        self.last_status = st
        colors = {ST_ONLINE: C_OK, ST_PORTAL: C_WARN, ST_OFFLINE: C_ERR,
                  ST_UNKNOWN: C_GRAY}
        self.dot.set(colors.get(st.state, C_GRAY))
        self.state_lbl.configure(text=st.text,
                                 fg=colors.get(st.state, C_TEXT))
        self.detail_lbl.configure(text=(st.detail or "-")[:70])
        ip = local_ip()
        self.ip_lbl.configure(text=f"IP  {ip or '—'}")
        self.time_lbl.configure(
            text="上次检测：" + time.strftime("%Y-%m-%d %H:%M:%S",
                                              time.localtime(st.checked_at))
            + (f"    耗时 {st.latency_ms} ms" if st.latency_ms else ""))

    # ---------- 各操作 ----------

    def _auto_start(self):
        """
        开机自启模式：一开机就抢着登录，失败就反复重试，直到联网成功。

        校园网的认证页跳转时快时慢，开机阶段 DNS / 网卡也常常还没就绪，
        所以这里不做"一次性尝试"，而是**持续缠斗**：
        每轮「等链路 → 登录」，失败就隔一会儿再来，直到成功或超出时限。
        """
        self.watch_sw.set(True)
        self.watching = True
        au = self.cfg.get("autostart", {})
        delay = int(au.get("delay", 5))
        hard = float(au.get("hard_retry_seconds", 900))
        gap = float(au.get("hard_retry_interval", 15))
        boot_wait = float(self.cfg.get("network", {}).get("startup_wait", 180))
        self.hint(f"开机自启：{delay} 秒后开始自动登录（失败会自动重试）…")
        self.logger.info("开机自启流程启动：延迟 %d 秒，最长坚持 %d 秒", delay, int(hard))

        def wait_and_go():
            time.sleep(delay)
            deadline = time.time() + hard
            attempt = 0
            while not self._closing and time.time() < deadline:
                attempt += 1
                # 首轮给足等待时间；后续轮网络已大致就绪，只需短等
                wait_cap = boot_wait if attempt == 1 else 20.0
                if not wait_for_network(self.cfg, self.logger, max_wait=wait_cap):
                    self.logger.warning("链路等待超时（第 %d 轮），仍然尝试登录一次", attempt)
                res = connect(self.cfg, self.logger)
                self.q.put(("done", res))
                if res.ok:
                    self.logger.info("开机自动登录完成（第 %d 轮，耗时 %.1f 秒）",
                                     attempt, res.elapsed)
                    return
                if res.verdict == LoginOutcome.FAILED:
                    # 明确失败（如密码错误）不硬刚，避免连续错误把账号锁掉
                    self.logger.error("开机自动登录明确失败，停止重试：%s", res.message)
                    return
                remain = int(deadline - time.time())
                if remain <= 0:
                    break
                wait = min(gap, remain)
                self.logger.warning("第 %d 轮未成功（%s），%d 秒后重试（剩余 %d 秒）",
                                    attempt, res.message, int(wait), remain)
                time.sleep(wait)
            self.logger.error("开机自动登录在 %d 秒内未成功，已停止重试", int(hard))

        threading.Thread(target=wait_and_go, daemon=True).start()

    def do_connect(self):
        self.hint("正在连接…")
        self._run_async(self._task_connect)

    def _task_connect(self):
        return connect(self.cfg, self.logger, force=False)

    def do_disconnect(self):
        self.hint("正在断开…")
        self._run_async(self._task_disconnect)

    def _task_disconnect(self):
        ok, msg = perform_logout(self.cfg, self.logger)
        self.logger.info("断开请求：%s", msg)
        st = check_network(self.cfg, quick=True)
        if st.state == ST_ONLINE:
            msg = msg + "（检测仍在网，可能认证服务器不支持远程断开，请手动退出）"
        return {"kind": "logout", "ok": ok, "message": msg}

    def refresh_status_async(self):
        self.hint("正在检测网络状态…")
        self._run_async(self._task_status)

    def _task_status(self):
        st = check_network(self.cfg, quick=False)
        self.logger.info("手动检测：%s（%s）", st.text, st.detail or "-")
        return st

    def do_probe(self):
        self.hint("正在探测认证页…")
        self._run_async(self._task_probe)

    def _task_probe(self):
        text = probe_portal(self.cfg)
        self.logger.info("已执行认证页探测")
        return {"kind": "probe", "text": text}

    def open_login_page(self):
        url = (self.cfg.get("auth", {}).get("login_url") or "").strip()
        if not url:
            st = self.last_status
            url = (st.portal_url if st else "") or ""
        if not url:
            self.hint("未配置登录网址，且未探测到认证地址", C_WARN)
            return
        try:
            webbrowser.open(url)
            self.hint(f"已打开：{url}")
        except Exception as e:
            self.hint(f"打开失败：{e}", C_ERR)

    def open_settings(self):
        SettingsDialog(self.root, self.cfg, on_saved=self._on_settings_saved)

    def _on_settings_saved(self):
        self.refresh_account_view()
        self.hint("配置已保存（密码已加密写入配置文件）", C_OK)
        self.refresh_log()

    def on_switch_autostart(self, on):
        if on:
            ok, info = autostart_enable(self.cfg.get("autostart", {}).get("args", "--startup"))
            if ok:
                self.cfg.setdefault("autostart", {})["enabled"] = True
                save_config(self.cfg)
                self.hint("已启用开机自启动", C_OK)
            else:
                self.switch.set(False)
                self.hint(f"启用失败：{info}", C_ERR)
        else:
            ok, info = autostart_disable()
            if ok:
                self.cfg.setdefault("autostart", {})["enabled"] = False
                save_config(self.cfg)
                self.hint("已关闭开机自启动", C_SUB)
            else:
                self.switch.set(True)
                self.hint(f"关闭失败：{info}", C_ERR)
        self.refresh_autostart_view()
        self.refresh_log()

    def on_switch_watch(self, on):
        self.watching = bool(on)
        self.hint("已开启断线自动重连" if on else "已关闭断线自动重连",
                  C_OK if on else C_SUB)
        if on:
            self._watch_tick()

    def _watch_tick(self):
        """断线重连：周期性后台检测，状态异常时自动发起登录。"""
        if not self.watching:
            return

        def worker():
            try:
                st = check_network(self.cfg, quick=True)
                self.q.put(("status", (st, True)))
            except Exception:
                import traceback
                traceback.print_exc()
        threading.Thread(target=worker, daemon=True).start()
        try:
            if not self._closing:
                self.root.after(
                    int(self.cfg.get("network", {}).get("watch_interval", 45)) * 1000,
                    self._watch_tick)
        except Exception:
            pass

    def on_close(self):
        self._closing = True
        self.watching = False
        try:
            save_config(self.cfg)
        except Exception:
            pass
        try:
            self.root.destroy()
        except Exception:
            pass

    def _show_text_window(self, title, text):
        win = tk.Toplevel(self.root)
        win.title(title)
        win.configure(bg=C_BG)
        win.geometry("760x520")
        frame = tk.Frame(win, bg=C_BG)
        frame.pack(fill="both", expand=True, padx=12, pady=12)
        box = tk.Text(frame, bg="#ffffff", fg=C_TEXT, font=("Consolas", 9),
                      wrap="none", relief="flat", bd=0, highlightbackground=C_LINE,
                      highlightthickness=1)
        box.pack(fill="both", expand=True)
        sb = tk.Scrollbar(box, command=box.yview)
        box.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        box.insert("1.0", text)
        box.configure(state="disabled")
        row = tk.Frame(frame, bg=C_BG)
        row.pack(fill="x", pady=(8, 0))

        def copy():
            win.clipboard_clear()
            win.clipboard_append(text)
            self.hint("探测结果已复制")

        _mk_button(row, "复制", copy, "primary").pack(side="right")
        _mk_button(row, "关闭", win.destroy, "normal").pack(side="right", padx=8)


class SettingsDialog:
    """账号 / 密码 / 登录网址 设置对话框。"""

    def __init__(self, parent, cfg, on_saved=None):
        self.cfg = cfg
        self.on_saved = on_saved
        self.top = tk.Toplevel(parent)
        self.top.title("设置账号密码")
        self.top.configure(bg=C_BG)
        self.top.transient(parent)
        self.top.grab_set()
        self.top.resizable(False, False)

        wrap = tk.Frame(self.top, bg=C_CARD, highlightbackground=C_LINE,
                        highlightthickness=1)
        wrap.pack(padx=16, pady=16, fill="both", expand=True)
        inner = tk.Frame(wrap, bg=C_CARD)
        inner.pack(padx=16, pady=14, fill="both", expand=True)

        tk.Label(inner, text="登录信息设置", bg=C_CARD, fg=C_TEXT,
                 font=(FONT, 11, "bold")).pack(anchor="w", pady=(0, 10))

        auth = cfg.get("auth", {})
        self.e_url = self._field(inner, "校园网登录网址", auth.get("login_url", ""),
                                 "例如 http://10.10.10.10/ 或认证服务器地址")
        self.e_user = self._field(inner, "账号", auth.get("username", ""), "学号 / 上网账号")
        self.e_pwd = self._field(inner, "密码", get_password(cfg), "密码将以 "
                                 + crypto_backend() + " 加密后保存", show="*")

        self.show_var = tk.BooleanVar(value=False)
        chk = tk.Checkbutton(inner, text="显示密码", variable=self.show_var,
                             command=self._toggle_pwd, bg=C_CARD, fg=C_SUB,
                             activebackground=C_CARD, font=(FONT, 9),
                             selectcolor=C_CARD, bd=0, highlightthickness=0)
        chk.pack(anchor="w", pady=(4, 0))

        note = ("说明：密码不会以明文写入源码或配置文件，"
                "加密与当前 Windows 用户绑定，配置拷贝到其他电脑将无法解密。")
        tk.Label(inner, text=note, bg=C_CARD, fg=C_SUB, font=(FONT, 8),
                 wraplength=420, justify="left").pack(anchor="w", pady=(10, 0))

        row = tk.Frame(inner, bg=C_CARD)
        row.pack(fill="x", pady=(14, 0))
        _mk_button(row, "保存", self.save, "primary").pack(side="right")
        _mk_button(row, "取消", self.top.destroy, "normal").pack(side="right", padx=8)

        self.msg = tk.Label(inner, text="", bg=C_CARD, fg=C_ERR, font=(FONT, 9),
                            width=52, anchor="w")
        self.msg.pack(fill="x", pady=(8, 0))

        self.top.update_idletasks()
        self.top.geometry("+%d+%d" % (parent.winfo_rootx() + 60,
                                      parent.winfo_rooty() + 60))

    def _field(self, master, label, value, hint="", show=None):
        tk.Label(master, text=label, bg=C_CARD, fg=C_SUB, font=(FONT, 9),
                 anchor="w").pack(fill="x", pady=(6, 2))
        e = tk.Entry(master, font=(FONT, 10), width=46, relief="flat", bd=0,
                     bg="#f7f8fa", fg=C_TEXT, insertbackground=C_TEXT,
                     highlightbackground=C_LINE, highlightcolor=C_ACCENT,
                     highlightthickness=1)
        if show:
            e.configure(show=show)
        e.insert(0, value or "")
        e.pack(fill="x", ipady=5)
        if hint:
            tk.Label(master, text=hint, bg=C_CARD, fg=C_GRAY,
                     font=(FONT, 8), anchor="w").pack(fill="x", pady=(2, 0))
        return e

    def _toggle_pwd(self):
        self.e_pwd.configure(show="" if self.show_var.get() else "*")

    def save(self):
        url = self.e_url.get().strip()
        user = self.e_user.get().strip()
        pwd = self.e_pwd.get()
        if not user:
            self.msg.configure(text="请填写账号")
            return
        if not url:
            self.msg.configure(text="请填写校园网登录网址")
            return
        self.cfg.setdefault("auth", {})["login_url"] = url
        self.cfg["auth"]["username"] = user
        set_password(self.cfg, pwd)
        try:
            save_config(self.cfg)
        except Exception as e:
            self.msg.configure(text=f"保存失败：{e}")
            return
        log().info("账号配置已更新：%s", _mask_user(user))
        if self.on_saved:
            self.on_saved()
        self.top.destroy()


def run_gui(cfg: dict, logger, startup: bool = False) -> int:
    if not HAS_TKINTER:
        msg = ("当前 Python 解释器没有 tkinter，无法启动图形界面。\n"
               "解决办法：改用带 tkinter 的官方 Python，或使用命令行模式，例如\n"
               "    python campus_login.py --connect   立即登录一次\n"
               "    python campus_login.py --status    查看联网状态\n"
               "    python campus_login.py --probe     探测认证页\n")
        try:
            sys.stderr.write(msg)
        except Exception:
            try:
                print(msg)
            except Exception:
                pass
        return 3
    root = tk.Tk()
    App(root, cfg, logger, startup=startup)
    root.mainloop()
    return 0


# ============================================================================
# [11] 入口
# ============================================================================

def main(argv=None) -> int:
    try:
        return cli(argv)
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())

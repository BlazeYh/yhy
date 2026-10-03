#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
仿真锐捷 ePortal 认证服务器 —— 离线端到端验证用。

为什么要造它
------------
真实校园门户只在「未认证网段」可达：一旦认证成功，或者换了别的网络
（比如手机热点），门户地址就完全连不上，没法随时验证登录流程。

这个仿真服务器严格复刻锐捷 ePortal 的关键行为，尤其是最容易被忽略、
也最容易导致「网页能点通、程序直连失败」的那一条：

    必须先访问门户页，拿到服务器下发的 JSESSIONID 会话 Cookie，
    之后带着**同一个 Cookie** 提交登录；否则返回
        Error code: 203 Bad request(2)

行为对照（与真机一致）
----------------------
GET  /                      -> 302 跳转到 /a70.htm?wlanuserip=...&ac_id=1&...
GET  /a70.htm?...           -> 200 返回认证页，并下发 JSESSIONID
POST /eportal/InterFace.do?method=pageInfo  -> 需要 Cookie，返回 userIndex
POST /eportal/InterFace.do?method=login     -> 校验会话 + queryString + 账密
POST /eportal/InterFace.do?method=logout    -> 注销

单独运行：
    python tests/mock_eportal.py                # 监听 127.0.0.1:8888
    python tests/mock_eportal.py --port 9000
"""

import argparse
import http.server
import json
import threading
from urllib.parse import parse_qs, urlparse

# 认证页跳转时携带的参数（真机上是 AC 设备根据客户端信息拼的）
PORTAL_QUERY = ("wlanuserip=10.132.7.66&wlanacname=AC_NAM_01"
                "&nasip=10.132.0.1&mac=3c-52-82-1f-9a-0b"
                "&t=1727942400123&ac_id=1"
                "&url=http%3A%2F%2Fwww.baidu.com%2F")

# 认证页：故意带上 "eportal" / "InterFace.do" 字样，
# 这样主程序的 detect_adapter() 能正确识别为锐捷 ePortal。
LOGIN_PAGE = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<title>校园网认证</title>
</head>
<body>
<div class="wrap">
  <h2>校园网认证</h2>
  <form id="loginForm" action="/eportal/InterFace.do?method=login" method="post">
    <input type="text"     name="userId"       placeholder="学号">
    <input type="password" name="password"     placeholder="密码">
    <input type="hidden"   name="queryString"  value="%s">
    <input type="hidden"   name="service"      value="">
    <input type="hidden"   name="passwordEncrypt" value="false">
    <button type="button">登 录</button>
  </form>
</div>
<script>
// 真机的登录按钮由这段 JS 提交（所以纯表单引擎抓不到，必须走 eportal 适配器）
function doLogin() {
    var f = document.getElementById('loginForm');
    f.submit();
}
</script>
</body>
</html>
"""


class _Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "RG-ePortal/1.0"

    # 默认实现会往 stderr 写日志，这里静音（我们自己记录结构化请求）
    def log_message(self, fmt, *args):
        pass

    # ---------------- 基础工具 ----------------

    def _send(self, status, body="", headers=None,
              ctype="text/html; charset=utf-8"):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if body:
            try:
                self.wfile.write(body)
            except Exception:
                pass

    def _read_body(self):
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            n = 0
        if n <= 0:
            return ""
        try:
            return self.rfile.read(n).decode("utf-8", "replace")
        except Exception:
            return ""

    def _cookies(self):
        raw = self.headers.get("Cookie") or ""
        out = {}
        for part in raw.split(";"):
            if "=" in part:
                k, v = part.split("=", 1)
                out[k.strip()] = v.strip()
        return out

    def _record(self, method, body=""):
        self.server.requests.append({
            "method": method,
            "path": self.path,
            "cookie": self.headers.get("Cookie") or "",
            "content_type": self.headers.get("Content-Type") or "",
            "body": body,
        })

    def _json(self, obj):
        self._send(200, json.dumps(obj, ensure_ascii=False),
                   ctype="application/json; charset=utf-8")

    # ---------------- 路由 ----------------

    def do_GET(self):
        u = urlparse(self.path)
        self._record("GET")
        path = u.path

        if path in ("/", "/index.html", "/portal"):
            if self.server.js_only:
                # 变体：门户根地址直接返回页面，参数只写在页面里（不 302）
                hdrs = {"Set-Cookie": "JSESSIONID=%s; Path=/" % self.server.new_sid()}
                self._send(200, LOGIN_PAGE % PORTAL_QUERY, hdrs)
                return
            # 真机行为：访问门户根地址 -> 302 到带参数的认证页
            self._send(302, "", {
                "Location": "/a70.htm?" + PORTAL_QUERY,
                "Set-Cookie": "JSESSIONID=%s; Path=/" % self.server.new_sid(),
            })
            return

        if path in ("/a70.htm", "/portal.htm"):
            # 未带会话时下发 JSESSIONID —— 这是后续能登录成功的前提
            hdrs = {}
            if not self._cookies().get("JSESSIONID"):
                hdrs["Set-Cookie"] = "JSESSIONID=%s; Path=/" % self.server.new_sid()
            self._send(200, LOGIN_PAGE % (u.query or PORTAL_QUERY), hdrs)
            return

        if path == "/blank.htm":
            # 变体：页面里**完全没有** wlanuserip，用于验证"取不到参数"的告警分支
            self._send(200, LOGIN_PAGE % "")
            return

        if path == "/eportal/InterFace.do":
            self._interface(u)
            return

        self._send(404, "not found")

    def do_POST(self):
        body = self._read_body()
        u = urlparse(self.path)
        self._record("POST", body)
        if u.path == "/eportal/InterFace.do":
            self._interface(u, body)
            return
        self._send(404, "not found")

    # ---------------- ePortal 接口 ----------------

    def _interface(self, u, body=""):
        method = (parse_qs(u.query).get("method") or [""])[0]
        form = {k: v[0] for k, v in
                parse_qs(body, keep_blank_values=True).items()}
        sid = self._cookies().get("JSESSIONID")

        if method == "logout":
            self.server.logged_in = False
            self._json({"result": "success", "message": "注销成功"})
            return

        if method == "pageInfo":
            # 真机同样要求先有会话
            if not sid:
                self._send(200, "Error code: 203 Bad request(2)")
                return
            qs_in = form.get("queryString", "")
            self._json({
                "result": "success",
                "userIndex": "7",
                "pageInfo": self._page_info(qs_in),
            })
            return

        if method == "login":
            # ① 没有会话 Cookie -> 参数校验失败（就是用户日志里那条错误）
            if not sid:
                self._send(200, "Error code: 203 Bad request(2)")
                return
            # ② queryString 必须能还原出 wlanuserip（真机据此定位接入设备）
            #    parse_qs 已经解码过一层，这里直接用原值，不再二次解码
            if "wlanuserip" not in (form.get("queryString") or ""):
                self._send(200, "Error code: 203 Bad request(2)")
                return
            # ③ 校验账号密码
            if (form.get("userId"), form.get("password")) == \
                    (self.server.username, self.server.password):
                self.server.logged_in = True
                self._json({"result": "success", "message": "认证成功",
                            "userIndex": "7", "forwordurl": ""})
            else:
                self.server.logged_in = False
                self._json({"result": "fail", "message": "用户名或密码错误",
                            "userIndex": ""})
            return

        self._send(404, "unknown method")

    @staticmethod
    def _page_info(qs_in):
        d = {k: v[0] for k, v in
             parse_qs(qs_in, keep_blank_values=True).items()}
        return {"ssid": "",
                "t": d.get("t", ""),
                "wlanacname": d.get("wlanacname", ""),
                "wlanuserip": d.get("wlanuserip", ""),
                "nasip": d.get("nasip", "")}


class MockEportal(http.server.ThreadingHTTPServer):
    """仿真锐捷 ePortal 服务器；作为上下文管理器使用最方便。"""

    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, addr=("127.0.0.1", 0),
                 username="student001", password="Passw0rd", js_only=False):
        super().__init__(addr, _Handler)
        self.username = username
        self.password = password
        self.js_only = js_only       # True = 门户根页不 302，参数只写在页面里
        self.requests = []
        self.logged_in = False
        self._sid = 0
        self._lock = threading.Lock()

    # ---- 生命周期 ----
    def start(self):
        threading.Thread(target=self.serve_forever, daemon=True).start()
        return self

    def stop(self):
        try:
            self.shutdown()
        except Exception:
            pass
        try:
            self.server_close()
        except Exception:
            pass

    def __enter__(self):
        return self.start()

    def __exit__(self, *exc):
        self.stop()

    # ---- 辅助 ----
    def new_sid(self):
        with self._lock:
            self._sid += 1
            return "MOCKSID%06d" % self._sid

    @property
    def base(self):
        return "http://%s:%d" % (self.server_address[0], self.server_address[1])

    @property
    def login_url(self):
        return self.base + "/"

    def reset(self):
        self.requests.clear()
        self.logged_in = False


def main():
    ap = argparse.ArgumentParser(description="仿真锐捷 ePortal 认证服务器")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8888)
    ap.add_argument("--username", default="student001")
    ap.add_argument("--password", default="Passw0rd")
    a = ap.parse_args()

    srv = MockEportal((a.host, a.port), a.username, a.password)
    print("仿真 ePortal 已启动：%s" % srv.login_url)
    print("可用账号：%s / %s" % (a.username, a.password))
    print("把配置里的 auth.login_url 指向这个地址，即可离线验证登录流程。")
    print("按 Ctrl+C 停止。")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n已停止")
    finally:
        srv.stop()


if __name__ == "__main__":
    main()

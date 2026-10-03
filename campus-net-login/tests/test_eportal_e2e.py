#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
锐捷 ePortal 登录流程 —— 离线端到端验证。

背景
----
用户实测日志：
    Error code: 203 Bad request(2)
程序直接裸 POST 登录接口，被服务器判为参数非法。本脚本用仿真服务器
（tests/mock_eportal.py）把这条错误**先复现出来**，再验证修复后的
「会话 + queryString」流程确实能通过，从而在不依赖校园网的情况下
证明改动有效。

运行：
    python tests/test_eportal_e2e.py -v
"""

import logging
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
for p in (ROOT, HERE):
    if p not in sys.path:
        sys.path.insert(0, p)

import campus_login as C                      # noqa: E402
from mock_eportal import MockEportal          # noqa: E402

LOG = logging.getLogger("e2e")
LOG.addHandler(logging.NullHandler())
LOG.propagate = False

USER = "2024001"
PWD = "Campus@2026"

SERVER = None
ARCHIVE = []          # 跨测试累积的请求记录，最后统一打印
_SUITE_TMP = None
_ORIG = {}


def setUpModule():
    global SERVER, _SUITE_TMP
    # 数据目录隔离：别把打桩数据写进用户真实的 logs/campus_login.log
    _SUITE_TMP = tempfile.mkdtemp(prefix="cnl_e2e_")
    _ORIG["data_dir"] = C.data_dir
    _ORIG["logger"] = C._logger
    C.data_dir = lambda: _SUITE_TMP
    C._logger = None
    SERVER = MockEportal(("127.0.0.1", 0), USER, PWD).start()


def tearDownModule():
    if SERVER:
        ARCHIVE.extend(SERVER.requests)
        SERVER.stop()
    C.data_dir = _ORIG["data_dir"]
    C._logger = _ORIG["logger"]


def make_cfg(login_url, adapter="eportal", user=USER, pwd=PWD, retry=1):
    cfg = C.default_config()
    cfg["auth"]["login_url"] = login_url
    cfg["auth"]["adapter"] = adapter
    cfg["auth"]["username"] = user
    C.set_password(cfg, pwd)
    cfg["network"]["retry"] = retry
    cfg["network"]["retry_interval"] = 0
    cfg["network"]["timeout"] = 4
    return cfg


def fake_check_network(cfg, quick=False):
    """打桩联网检测：登录前=需认证，登录后=已在线。"""
    if SERVER.logged_in:
        return C.NetStatus(C.ST_ONLINE, "仿真探测点响应正常", latency_ms=1)
    return C.NetStatus(C.ST_PORTAL, "被重定向到认证服务器（HTTP 302）",
                       portal_url=SERVER.login_url, latency_ms=1)


class TestEportalFlow(unittest.TestCase):

    def setUp(self):
        ARCHIVE.extend(SERVER.requests)
        SERVER.reset()

    # ------------------------------------------------------------------
    def test_01_reproduce_203_bad_request(self):
        """复现用户遇到的错误：不带会话 Cookie 直接裸 POST -> 203。"""
        import json
        from urllib.parse import urlencode
        url = SERVER.base + "/eportal/InterFace.do?method=login"
        body = urlencode([("userId", USER), ("password", PWD),
                          ("service", ""), ("queryString", "wlanuserip=1.2.3.4"),
                          ("operatorPwd", ""), ("operatorUserId", ""),
                          ("validcode", ""), ("passwordEncrypt", "false")])
        r = C.http_post(url, body, timeout=4)
        self.assertFalse(r.error, r.error)
        # 顺便守住一个真 bug：请求行里的 "?method=login" 不能被拼成 ";method=login"
        self.assertEqual(SERVER.requests[-1]["path"],
                         "/eportal/InterFace.do?method=login",
                         "查询串必须用 ? 拼接，否则服务器解析不到 method")
        self.assertIn("203", r.body, "仿真服务器应像真机一样拒绝无会话请求")
        # 顺便验证程序能给这句错误配上人话解释
        hint = C.explain_eportal_error(r.body)
        self.assertIn("203", hint)

    # ------------------------------------------------------------------
    def test_02_session_flow_succeeds(self):
        """修复后的流程：先取会话 -> 带 Cookie 提交 -> 成功。"""
        cfg = make_cfg(SERVER.login_url)
        verdict, msg, raw = C.perform_login(cfg, LOG)
        self.assertEqual(verdict, C.LoginOutcome.OK, f"{verdict} / {msg}")
        self.assertTrue(SERVER.logged_in, "仿真服务器应记录为已登录")

        # 关键校验：登录请求确实带上了 JSESSIONID，且 queryString 带 wlanuserip
        login_reqs = [q for q in SERVER.requests
                      if q["method"] == "POST" and "method=login" in q["path"]]
        self.assertEqual(len(login_reqs), 1)
        req = login_reqs[0]
        self.assertIn("JSESSIONID=", req["cookie"],
                      "必须携带会话 Cookie，这正是原实现的缺陷")
        import urllib.parse as up
        form = {k: v[0] for k, v in
                up.parse_qs(req["body"], keep_blank_values=True).items()}
        self.assertIn("wlanuserip", form.get("queryString", ""))
        self.assertIn("ac_id=1", form.get("queryString", ""))

    # ------------------------------------------------------------------
    def test_03_auto_detect_picks_eportal(self):
        """adapter=auto 时应能从仿真页面识别出 eportal。"""
        cfg = make_cfg(SERVER.login_url, adapter="auto")
        verdict, msg, _ = C.perform_login(cfg, LOG)
        self.assertEqual(verdict, C.LoginOutcome.OK, f"{verdict} / {msg}")

    # ------------------------------------------------------------------
    def test_04_wrong_password_is_failed_not_retried(self):
        """密码错误 -> 明确判定 FAILED，且 connect() 立即返回不重试。"""
        cfg = make_cfg(SERVER.login_url, pwd="WrongPassword")
        verdict, msg, _ = C.perform_login(cfg, LOG)
        self.assertEqual(verdict, C.LoginOutcome.FAILED, f"{verdict} / {msg}")
        self.assertIn("密码", msg + "用户名")

        cfg["network"]["retry"] = 3          # 即便配置允许重试 3 次
        with _patch_check_network(fake_check_network):
            res = C.connect(cfg, LOG)
        self.assertFalse(res.ok)
        self.assertEqual(res.verdict, C.LoginOutcome.FAILED)
        self.assertEqual(res.attempts, 1, "密码错误必须立刻停止，避免连续错误锁号")

    # ------------------------------------------------------------------
    def test_05_connect_orchestration_success(self):
        """完整编排：检测(需认证) -> 登录 -> 复检(已在线) -> 成功。"""
        cfg = make_cfg(SERVER.login_url)
        with _patch_check_network(fake_check_network):
            res = C.connect(cfg, LOG)
        self.assertTrue(res.ok, f"{res.verdict} / {res.message}")
        self.assertEqual(res.attempts, 1)
        self.assertTrue(SERVER.logged_in)

    # ------------------------------------------------------------------
    def test_06_already_online_skips_login(self):
        """已在线时 connect() 不得发起任何登录请求。"""
        SERVER.logged_in = True
        cfg = make_cfg(SERVER.login_url)
        with _patch_check_network(fake_check_network):
            res = C.connect(cfg, LOG)
        self.assertTrue(res.ok)
        self.assertEqual(res.attempts, 0, "已在线应跳过登录")
        self.assertEqual(SERVER.requests, [], "不应产生任何请求")

    # ------------------------------------------------------------------
    def test_07_missing_querystring_gets_diagnosed(self):
        """queryString 为空时同样会 203，程序应给出可操作提示。"""
        import logging as _l
        sess = C.HttpSession(timeout=4, encoding="utf-8")
        sess.get(SERVER.base + "/a70.htm?" + "wlanuserip=1.1.1.1")   # 建立会话
        r = sess.post_raw(SERVER.base + "/eportal/InterFace.do?method=login",
                          "userId=%s&password=%s&queryString=&service=" % (USER, PWD))
        self.assertIn("203", r.body)
        # 直连服务端记录，确认请求体原样送达（不依赖终端输出）
        raw_body = SERVER.requests[-1]["body"]
        self.assertIn(f"userId={USER}", raw_body)
        self.assertIn(f"password={PWD}", raw_body)
        self.assertIn("queryString=&service=", raw_body)
        # 程序侧：整页都找不到参数时，必须在提交前明确预警
        cfg = make_cfg(SERVER.base + "/blank.htm")
        cfg["auth"]["adapter"] = "eportal"
        recs = []

        class _Cap(_l.Handler):
            def emit(self, record):
                recs.append(record.getMessage())

        cap = _l.getLogger("e2e-cap")
        cap.addHandler(_Cap())
        C.perform_login(cfg, cap)
        self.assertTrue(any("queryString" in m for m in recs),
                        "应在日志中明确提示 queryString 为空")

    # ------------------------------------------------------------------
    def test_08_logout(self):
        """注销接口走同一会话。"""
        cfg = make_cfg(SERVER.login_url)
        C.perform_login(cfg, LOG)
        self.assertTrue(SERVER.logged_in)
        ok, msg = C.perform_logout(cfg, LOG)
        self.assertTrue(ok, msg)
        self.assertFalse(SERVER.logged_in)

    # ------------------------------------------------------------------
    def test_09_query_extracted_from_page_when_no_redirect(self):
        """
        变体门户：根地址不 302 出带参地址，queryString 只写在页面里。
        必须靠页面兜底提取才能登录成功。
        """
        with MockEportal(("127.0.0.1", 0), USER, PWD, js_only=True) as alt:
            cfg = make_cfg(alt.login_url)
            verdict, msg, _ = C.perform_login(cfg, LOG)
            self.assertEqual(verdict, C.LoginOutcome.OK, f"{verdict} / {msg}")
            login_reqs = [q for q in alt.requests
                          if q["method"] == "POST" and "method=login" in q["path"]]
            self.assertEqual(len(login_reqs), 1)
            import urllib.parse as up
            form = {k: v[0] for k, v in
                    up.parse_qs(login_reqs[0]["body"], keep_blank_values=True).items()}
            self.assertIn("wlanuserip", form.get("queryString", ""),
                          "必须从页面里兜底提取出 queryString")


class _patch_check_network:
    """临时替换模块级 check_network（避免动真网）。"""

    def __init__(self, fn):
        self.fn = fn

    def __enter__(self):
        self._old = C.check_network
        C.check_network = self.fn
        return self

    def __exit__(self, *exc):
        C.check_network = self._old


def _report():
    print("\n" + "=" * 72)
    print("仿真服务器收到的请求（按顺序）")
    print("=" * 72)
    if not ARCHIVE:
        print("（无）")
        return
    for i, q in enumerate(ARCHIVE, 1):
        ck = q["cookie"][:46] or "(无 Cookie)"
        print(f"{i:2d}. {q['method']:4s} {q['path'][:62]}")
        print(f"    Cookie: {ck}")
        if q["body"]:
            print(f"    Body  : {q['body'][:96]}")


if __name__ == "__main__":
    try:
        unittest.main(verbosity=2, exit=False)
    finally:
        _report()

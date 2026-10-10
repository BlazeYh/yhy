# -*- coding: utf-8 -*-
"""
校园网自动登录助手 —— 自测脚本
================================================================
分四层验证，全部可无人值守运行：
  第一层 逻辑层 ：密码加解密、配置读写、表单解析、适配器识别
  第二层 引擎层 ：打桩网络调用，验证「已在线跳过 / 成功 / 失败 / 重试」四种编排分支
  第三层 界面层 ：构建窗口、灌入最长文本，断言布局不被撑破
  第四层 只读层 ：自启动读取（不写注册表，避免污染本机环境）

运行：  python tests/test_core.py -v
"""
import json
import logging
import os
import sys
import tempfile
import unittest
from unittest import mock
from urllib.parse import parse_qsl

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import campus_login as C  # noqa: E402


# ---------------------------------------------------------------------------
# 全局隔离：整个测试套件的数据目录都指向临时目录
#
# 只让个别测试类各自打补丁是不够的 —— 模块级的日志对象 _logger 是**缓存**的，
# 一旦在某个用例里被创建，就会一直指向当时的目录，后面不重置 _logger 的用例
# 会把打桩数据写进真实的 logs/campus_login.log，污染用户日志。
# ---------------------------------------------------------------------------
_SUITE_TMP = None
_ORIG = {}


def setUpModule():
    global _SUITE_TMP
    _SUITE_TMP = tempfile.mkdtemp(prefix="cnl_suite_")
    _ORIG["data_dir"] = C.data_dir
    _ORIG["logger"] = C._logger
    C.data_dir = lambda: _SUITE_TMP
    C._logger = None


def tearDownModule():
    C.data_dir = _ORIG["data_dir"]
    C._logger = _ORIG["logger"]


def mkcfg(**over):
    """构造一份自包含的测试配置（临时目录 + 假账号）。"""
    cfg = C.default_config()
    cfg["auth"]["login_url"] = "http://10.0.0.1/"
    cfg["auth"]["username"] = "2023001"
    C.set_password(cfg, "p@ss w0rd#$")
    cfg["network"]["retry"] = 3
    cfg["network"]["retry_interval"] = 0
    cfg["network"]["timeout"] = 1
    cfg.update(over)
    return cfg


# ============================================================================
# 第一层：逻辑
# ============================================================================

class TestLogic(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="cnl_test_")
        self._orig_data_dir = C.data_dir
        self._orig_logger = C._logger
        C.data_dir = lambda: self.tmp          # 所有配置/日志落到临时目录
        C._logger = None                       # 日志处理器也要跟着落临时目录

    def tearDown(self):
        C.data_dir = self._orig_data_dir
        C._logger = self._orig_logger

    # ---- 密码保护 ----
    def test_dpapi_roundtrip(self):
        for plain in ["p@ss w0rd#$", "中文密码123", "", "a" * 200,
                      "特殊字符 !@#$%^&*()_+-=[]{}|;':\",./<>?"]:
            token = C.protect(plain)
            self.assertTrue(token.startswith(("dpapi:", "mask:")),
                            f"密文前缀异常：{token[:24]}")
            self.assertNotIn(plain, token) if plain else None
            self.assertEqual(C.unprotect(token), plain,
                             f"加解密往返失败，明文={plain!r}")

    def test_unprotect_rejects_garbage(self):
        for bad in ["", None, "garbage", "dpapi:@@@not-base64@@@", "mask:zzz"]:
            self.assertEqual(C.unprotect(bad), "")

    def test_password_never_plain_in_config_file(self):
        cfg = mkcfg()
        C.save_config(cfg)
        with open(C.config_file(), encoding="utf-8") as f:
            raw = f.read()
        self.assertNotIn("p@ss w0rd#$", raw, "配置文件里出现了明文密码！")
        self.assertIn("password_enc", raw)
        # 重新加载后仍能取回
        cfg2 = C.load_config()
        self.assertEqual(C.get_password(cfg2), "p@ss w0rd#$")

    # ---- 配置 ----
    def test_config_defaults_merge(self):
        C.save_config({"auth": {"username": "u1"}})       # 只写一部分
        cfg = C.load_config()
        self.assertEqual(cfg["auth"]["username"], "u1")
        self.assertEqual(cfg["auth"]["adapter"], "auto")  # 默认值补齐
        self.assertEqual(cfg["network"]["retry"], 3)

    def test_config_broken_file_is_backed_up(self):
        with open(C.config_file(), "w", encoding="utf-8") as f:
            f.write("{ 这不是合法 json")
        cfg = C.load_config()
        self.assertEqual(cfg["auth"]["adapter"], "auto")
        self.assertTrue(os.path.exists(C.config_file() + ".broken"))

    def test_missing_config_is_created(self):
        self.assertFalse(os.path.exists(C.config_file()))
        C.load_config()
        self.assertTrue(os.path.exists(C.config_file()))

    # ---- 表单解析 ----
    HTML = """<html><body>
      <form action="/login" method="post">
        <input type="hidden" name="action" value="login">
        <input type="text"   name="username" value="">
        <input type="password" name="pwd" value="">
        <input type="hidden" name="ac_id" value="1">
        <input type="submit" value="登录">
      </form></body></html>"""

    def test_parse_forms(self):
        forms = C.parse_forms(self.HTML, "http://10.0.0.1/portal")
        self.assertEqual(len(forms), 1)
        f = forms[0]
        self.assertEqual(f["action"], "http://10.0.0.1/login")   # 相对路径补全
        self.assertEqual(f["method"], "post")
        self.assertEqual(len(f["inputs"]), 5)
        roles = {i["name"]: i["role"] for i in f["inputs"]}
        self.assertEqual(roles["username"], "username")
        self.assertEqual(roles["pwd"], "password")
        self.assertEqual(roles["ac_id"], "")                     # hidden 保留原值但不填充
        # submit 按钮无 name，不应被当作登录字段
        submits = [i for i in f["inputs"] if i["type"] == "submit"]
        self.assertEqual(len(submits), 1)
        self.assertEqual(submits[0]["role"], "")

    def test_parse_forms_without_form_tag(self):
        html = ('<div><input name="userName"><input name="userPwd" type="password">'
                '<button onclick="doLogin()">登录</button></div>')
        forms = C.parse_forms(html, "http://10.0.0.1/")
        self.assertEqual(len(forms), 1)
        roles = {i["name"]: i["role"] for i in forms[0]["inputs"]}
        self.assertEqual(roles["userName"], "username")
        self.assertEqual(roles["userPwd"], "password")

    def test_guess_role_priority(self):
        self.assertEqual(C._guess_role({"type": "password", "name": "x"}), "password")
        self.assertEqual(C._guess_role({"type": "hidden", "name": "password"}), "")
        self.assertEqual(C._guess_role({"type": "text", "name": "txtUserName"}), "username")
        self.assertEqual(C._guess_role({"type": "text", "name": "name"}), "username")
        self.assertEqual(C._guess_role({"type": "text", "name": "somethingElse"}), "")

    # ---- 适配器识别 ----
    def test_detect_adapter(self):
        self.assertEqual(C.detect_adapter("http://a/srun_portal_pc?ac_id=1"), "srun")
        self.assertEqual(C.detect_adapter("http://a/eportal/InterFace.do"), "eportal")
        self.assertEqual(C.detect_adapter("http://a/", "<title>Dr.COM 登录</title>"), "drcom")
        self.assertEqual(C.detect_adapter("http://a/portal", "<form>登录</form>"), "form")

    def test_url_helpers(self):
        self.assertEqual(C._url_base("http://10.0.0.1:8080/a/b?x=1"), "http://10.0.0.1:8080")
        self.assertEqual(C._url_base("not a url"), "")
        self.assertEqual(C._query_of("http://a/eportal/InterFace.do?method=login&u=1"),
                         "method=login&u=1")

    def test_split_url_keeps_query_with_question_mark(self):
        """
        回归：请求行必须用 '?' 拼接查询串。
        曾经用 urlunparse 拼，而它第 4 位是 params，结果拼成
        '/eportal/InterFace.do;method=login'，服务器解析不到 method，
        直接回 'Error code: 203 Bad request(2)' —— 这正是真实故障的元凶。
        """
        u, path = C._split_url("http://10.0.0.1/eportal/InterFace.do?method=login&ac_id=1")
        self.assertEqual(path, "/eportal/InterFace.do?method=login&ac_id=1")
        self.assertNotIn(";", path, "查询串不能被拼成 params 分隔符 ;")
        self.assertEqual(u.hostname, "10.0.0.1")
        # 无查询串时保持干净路径
        self.assertEqual(C._split_url("http://a/b")[1], "/b")
        self.assertEqual(C._split_url("http://a")[1], "/")

    def test_extract_query_from_page(self):
        """门户根页不带参数时，queryString 可能写在 JS 里，必须能兜底抠出来。"""
        js = '<script>var queryString = "wlanuserip=10.1.2.3&wlanacname=AC_1&ac_id=1";</script>'
        self.assertEqual(C._extract_query_from_page(js),
                         "wlanuserip=10.1.2.3&wlanacname=AC_1&ac_id=1")
        # 带引号包裹的完整地址
        html = '<a href="http://1.1.1.1/a70.htm?wlanuserip=10.1.2.3&ac_id=2&t=9">go</a>'
        self.assertEqual(C._extract_query_from_page(html),
                         "wlanuserip=10.1.2.3&ac_id=2&t=9")
        # HTML 实体要还原
        self.assertEqual(
            C._extract_query_from_page('x="?wlanuserip=1.1.1.1&amp;ac_id=1"'),
            "wlanuserip=1.1.1.1&ac_id=1")
        # 整串被编码过时先解开一层，避免后续二次编码
        self.assertEqual(
            C._extract_query_from_page('q="wlanuserip%3D1.1.1.1%26ac_id%3D1"'),
            "wlanuserip=1.1.1.1&ac_id=1")
        # 什么也没有时返回空串，不能瞎猜
        self.assertEqual(C._extract_query_from_page("<html>登录</html>"), "")
        self.assertEqual(C._extract_query_from_page(""), "")

    def test_mask_user(self):
        self.assertEqual(C._mask_user("2023001"), "20****1")
        self.assertEqual(C._mask_user("ab"), "a*")
        self.assertEqual(C._mask_user(""), "(空)")

    def test_launch_command(self):
        cmd = C.launch_command("--startup")
        self.assertIn("--startup", cmd)
        self.assertTrue(cmd.startswith('"'), "路径必须加引号，否则带空格的路径会失效")

    # ---- ePortal 相关 ----
    def test_explain_eportal_error(self):
        msg = C.explain_eportal_error(
            "<html><body>\nError code: 203 Bad request(2)\n</body></html>")
        self.assertIn("203", msg)
        self.assertIn("参数校验失败", msg)
        self.assertEqual(C.explain_eportal_error("普通内容"), "")

    def test_scan_interface_hints(self):
        html = '<script>var u="/eportal/InterFace.do?method=login";</script>'
        hints = C._scan_interface_hints(html)
        self.assertTrue(any("method=login" in h for h in hints), hints)
        self.assertEqual(C._scan_interface_hints(""), [])

    def test_http_session_cookies(self):
        s = C.HttpSession(timeout=1)
        self.assertEqual(s.cookie_header(), "")
        s.set_cookie("JSESSIONID", "abc123")
        self.assertIn("JSESSIONID=abc123", s.cookie_header())
        self.assertEqual(s.cookies.get("JSESSIONID"), "abc123")


# ============================================================================
# 第二层：引擎（打桩网络）
# ============================================================================

class TestEngine(unittest.TestCase):

    def setUp(self):
        self.logger = C.setup_logging()
        self.cfg = mkcfg()
        self._patches = [
            mock.patch.object(C.time, "sleep", lambda s: None),
        ]
        for p in self._patches:
            p.start()

    def tearDown(self):
        for p in self._patches:
            p.stop()

    def test_already_online_skips_login(self):
        """需求 2：已在线时必须直接结束，不能重复登录。"""
        with mock.patch.object(C, "check_network",
                               return_value=C.NetStatus(C.ST_ONLINE, "ok")), \
             mock.patch.object(C, "perform_login") as m:
            r = C.connect(self.cfg, self.logger)
        self.assertTrue(r.ok)
        self.assertEqual(r.attempts, 0)
        m.assert_not_called()

    def test_offline_short_circuits_without_ip(self):
        """连本机 IP 都没有 → 确实是网络不通，直接短路，不发起登录。"""
        self.cfg["auth"]["login_url"] = "http://10.0.0.1/"
        with mock.patch.object(C, "check_network",
                               return_value=C.NetStatus(C.ST_OFFLINE, "连接超时")), \
                mock.patch.object(C, "_has_local_ip", lambda: False), \
                mock.patch.object(C, "perform_login") as m:
            r = C.connect(self.cfg, self.logger)
        self.assertFalse(r.ok)
        self.assertEqual(r.verdict, C.LoginOutcome.OFFLINE)
        m.assert_not_called()

    def test_offline_but_has_ip_still_tries_login(self):
        """
        回归（2026-10-10 用户反馈"有时要干等"）：
        开机时 DNS 滞后于 DHCP，探测点按域名访问会报"不通"，
        但网卡已有 IP、门户（内网 IP）可达 —— 登录根本不需要 DNS，
        不能就此放弃白等一整轮（实测这么白等过 38 秒）。
        """
        self.cfg["auth"]["login_url"] = "http://10.0.0.1/"
        self.cfg["network"]["retry"] = 1          # 只试一轮，避免测试等 6 秒间隔
        seen = []
        with mock.patch.object(C, "check_network",
                               return_value=C.NetStatus(C.ST_OFFLINE, "DNS 解析失败")), \
                mock.patch.object(C, "_has_local_ip", lambda: True), \
                mock.patch.object(C, "perform_login",
                                  side_effect=lambda *a, **k: (
                                      seen.append(1),
                                      (C.LoginOutcome.RETRY, "仍不通", ""))[1]):
            r = C.connect(self.cfg, self.logger)
        self.assertTrue(seen, "本机有 IP 时，即使探测点不通也必须尝试登录")
        self.assertFalse(r.ok)

    def test_login_success(self):
        seq = [C.NetStatus(C.ST_PORTAL, "需要认证"), C.NetStatus(C.ST_ONLINE, "ok")]
        with mock.patch.object(C, "check_network", side_effect=seq), \
             mock.patch.object(C, "perform_login",
                               return_value=(C.LoginOutcome.OK, "提交成功", "ok")):
            r = C.connect(self.cfg, self.logger)
        self.assertTrue(r.ok)
        self.assertEqual(r.attempts, 1)

    def test_wrong_password_does_not_retry(self):
        """密码错误属于确定性失败，重试只会导致账号被锁。"""
        with mock.patch.object(C, "check_network",
                               return_value=C.NetStatus(C.ST_PORTAL, "需要认证")), \
             mock.patch.object(C, "perform_login") as m:
            m.return_value = (C.LoginOutcome.FAILED, "账号或密码错误", "")
            r = C.connect(self.cfg, self.logger)
        self.assertFalse(r.ok)
        self.assertEqual(r.verdict, C.LoginOutcome.FAILED)
        self.assertEqual(m.call_count, 1)

    def test_retry_then_give_up_as_relogin(self):
        """反复提交后仍处于未认证 → 判定为「需要重新登录」。"""
        with mock.patch.object(C, "check_network",
                               return_value=C.NetStatus(C.ST_PORTAL, "需要认证")), \
             mock.patch.object(C, "perform_login",
                               return_value=(C.LoginOutcome.OK, "提交成功", "ok")) as m:
            r = C.connect(self.cfg, self.logger)
        self.assertFalse(r.ok)
        self.assertEqual(r.verdict, C.LoginOutcome.RELOGIN)
        self.assertEqual(m.call_count, 3)          # = network.retry

    def test_missing_config(self):
        """需求 5：配置不完整时要给出明确提示，而不是抛异常或静默失败。"""
        cfg = C.default_config()
        with mock.patch.object(C, "check_network",
                               return_value=C.NetStatus(C.ST_PORTAL, "未认证")):
            r = C.connect(cfg, self.logger)
        self.assertFalse(r.ok)
        self.assertEqual(r.verdict, C.LoginOutcome.NO_CONFIG)

    def test_perform_login_validates_config(self):
        cfg = C.default_config()
        v, msg, _ = C.perform_login(cfg, self.logger)
        self.assertEqual(v, C.LoginOutcome.NO_CONFIG)
        self.assertIn("登录网址", msg)

        cfg["auth"]["login_url"] = "http://10.0.0.1/"
        v, msg, _ = C.perform_login(cfg, self.logger)
        self.assertEqual(v, C.LoginOutcome.NO_CONFIG)
        self.assertIn("账号", msg)

    def test_judge_response(self):
        self.assertEqual(C._judge_response('{"error":"ok","suc_msg":"登录成功"}', 200),
                         C.LoginOutcome.OK)
        self.assertEqual(C._judge_response("密码错误，请重试", 200),
                         C.LoginOutcome.FAILED)
        self.assertEqual(C._judge_response('{"result":"success"}', 200),
                         C.LoginOutcome.OK)
        # 看不懂的响应 → 交给复检，判为需重试
        self.assertEqual(C._judge_response("<html>hello</html>", 200),
                         C.LoginOutcome.RETRY)


# ============================================================================
# 第二层续：ePortal 适配器流程（本次修复的重点）
# ============================================================================

class _FakeSession:
    """
    假的 HttpSession：记录调用顺序，并可按需返回指定响应。
    用来验证「先 GET 门户建会话 → POST pageInfo → POST login」这条链路，
    以及 queryString 是否取自跳转后的真实地址。
    """

    calls: list = []
    login_body = '{"result":"success"}'

    def __init__(self, timeout=8.0, encoding="utf-8", logger=None):
        self.timeout = timeout
        self.encoding = encoding
        self.logger = logger

    def cookie_header(self):
        return "JSESSIONID=fake"

    def get(self, url, headers=None):
        type(self).calls.append(("GET", url))
        return C.HttpResult(status=200, body="<html>portal</html>",
                            final_url="http://10.0.0.1/a70.htm"
                                      "?wlanuserip=10.0.0.100&wlanacname=nas01&ac_id=1")

    def post(self, url, fields, headers=None, referer=""):
        type(self).calls.append(("POST", url, fields))
        if "pageInfo" in url:
            return C.HttpResult(status=200, body='{"userIndex":"7"}')
        return C.HttpResult(status=200, body=type(self).login_body)

    def post_raw(self, url, body, headers=None, referer=""):
        type(self).calls.append(("POST_RAW", url, body))
        return C.HttpResult(status=200, body=type(self).login_body)


class TestEportalAdapter(unittest.TestCase):

    def setUp(self):
        _FakeSession.calls = []
        _FakeSession.login_body = '{"result":"success"}'
        self.tmp = tempfile.mkdtemp(prefix="cnl_ep_")
        self._orig_data_dir = C.data_dir
        self._orig_logger = C._logger
        C.data_dir = lambda: self.tmp          # 门户页落盘等写入也隔离
        C._logger = None
        self.logger = C.setup_logging()

    def tearDown(self):
        C.data_dir = self._orig_data_dir
        C._logger = self._orig_logger

    def _run(self):
        with mock.patch.object(C, "HttpSession", _FakeSession):
            return C._login_eportal("http://10.0.0.1/", "2024001",
                                    "secret", 3, "utf-8", self.logger)

    def test_session_is_established_before_login(self):
        """必须先用同一个会话访问门户，否则服务器返回 203。"""
        self._run()
        methods = [c[0] for c in _FakeSession.calls]
        self.assertEqual(methods[0], "GET", "第一步必须是访问门户页建立会话")
        self.assertIn("POST", methods[1:], "随后必须提交登录")

    def test_query_string_comes_from_redirected_url(self):
        self._run()
        login = [c for c in _FakeSession.calls
                 if c[0] == "POST_RAW" and "method=login" in c[1]]
        self.assertEqual(len(login), 1)
        fields = dict(parse_qsl(login[0][2]))
        self.assertIn("wlanuserip=10.0.0.100", fields["queryString"])
        self.assertIn("ac_id=1", fields["queryString"])
        self.assertEqual(fields["userId"], "2024001")

    def test_login_success_detected(self):
        v, _, _ = self._run()
        self.assertEqual(v, C.LoginOutcome.OK)

    def test_error_203_reported_as_failure_with_hint(self):
        """203 是确定性参数错误，应判失败并给出可读原因，而不是无脑重试。"""
        _FakeSession.login_body = ("<html><body>\nError code: 203 Bad request(2)\n"
                                   "</body></html>")
        v, msg, _ = self._run()
        self.assertEqual(v, C.LoginOutcome.FAILED)
        self.assertIn("203", msg)

    def test_failure_message_is_surfaced(self):
        _FakeSession.login_body = '{"result":"fail","message":"账号或密码错误"}'
        v, msg, _ = self._run()
        self.assertEqual(v, C.LoginOutcome.FAILED)
        self.assertIn("账号或密码错误", msg)


# ============================================================================
# 第三层：界面（构建 + 布局稳定性）
# ============================================================================
@unittest.skipUnless(C.HAS_TKINTER, "当前解释器没有 tkinter")
class TestGUI(unittest.TestCase):

    def setUp(self):
        self.logger = C.setup_logging()
        self.cfg = mkcfg()
        self._orig_data_dir = C.data_dir
        self.tmp = tempfile.mkdtemp(prefix="cnl_gui_")
        C.data_dir = lambda: self.tmp
        self.stub = mock.patch.object(
            C, "check_network",
            return_value=C.NetStatus(C.ST_ONLINE, "探测点响应正常", latency_ms=12))
        self.stub.start()

    def tearDown(self):
        self.stub.stop()
        C.data_dir = self._orig_data_dir

    def test_window_builds_and_layout_is_stable(self):
        root = C.tk.Tk()
        try:
            app = C.App(root, self.cfg, self.logger)
            root.update()
            self.assertGreater(root.winfo_width(), 300)
            self.assertGreater(root.winfo_height(), 300)

            # 把所有会变化的文本灌成「最长形态」，看会不会把窗口撑破
            app.state_lbl.configure(text="未认证 · 需要登录")
            app.detail_lbl.configure(text="被重定向到认证服务器（HTTP 302），"
                                          "认证地址 http://10.10.10.10:8080/eportal/x")
            app.time_lbl.configure(text="上次检测：2026-10-03 14:33:07    耗时 12345 ms")
            app.ip_lbl.configure(text="IP  255.255.255.255")
            app.user_lbl.configure(text="2023001123456789")
            app.pwd_lbl.configure(text="●" * 12)
            app.url_lbl.configure(text="http://10.10.10.10:8080/eportal/InterFace.do")
            app.auto_lbl.configure(text="当前状态：已启用 · \"C:\\Python\\pythonw.exe\" "
                                         + "\"D:\\长路径测试\\campus_login.py\" --startup")
            for state in (C.ST_ONLINE, C.ST_PORTAL, C.ST_OFFLINE):
                app._on_status(C.NetStatus(state, "测试"))
                app._set_busy(True)
                root.update()
                app._set_busy(False)
                root.update()
                self.assertLessEqual(
                    root.winfo_reqwidth(), root.winfo_width() + 2,
                    "窗口需求宽度被撑破，底部按钮可能被裁掉")
                self.assertLessEqual(
                    root.winfo_reqheight(), root.winfo_height() + 2,
                    "窗口需求高度被撑破")
        finally:
            root.destroy()

    def test_settings_dialog_builds(self):
        root = C.tk.Tk()
        try:
            C.App(root, self.cfg, self.logger)
            root.update()
            dlg = C.SettingsDialog(root, self.cfg)
            root.update()
            self.assertEqual(dlg.e_user.get(), "2023001")
            self.assertEqual(dlg.e_pwd.get(), "p@ss w0rd#$")   # 打开时应回显真实密码
            dlg.save()                                          # 保存一次应正常写盘
            self.assertTrue(os.path.exists(C.config_file()))
            root.update()
        finally:
            root.destroy()

    def test_switch_and_dot(self):
        root = C.tk.Tk()
        try:
            fire = []
            sw = C.Switch(root, command=lambda v: fire.append(v), on=False)
            self.assertFalse(sw.get())
            sw._click()
            self.assertTrue(sw.get())
            self.assertEqual(fire, [True])
            dot = C.StatusDot(root)
            dot.set(C.C_OK)
            self.assertEqual(dot._color, C.C_OK)
        finally:
            root.destroy()


# ============================================================================
# 第四层：自启动（只读，不修改注册表）
# ============================================================================

class TestAutostartReadOnly(unittest.TestCase):

    def test_read_does_not_raise(self):
        cmd = C.autostart_get()
        self.assertTrue(cmd is None or isinstance(cmd, str))
        text = C.autostart_status_text()
        self.assertIn("启用", text)

    def test_launch_command_round_trip(self):
        """注册表里写入的命令必须能被解析回本程序路径。"""
        cmd = C.launch_command("--startup")
        self.assertIn(os.path.basename(os.path.abspath(C.__file__)), cmd)


# ============================================================================
# 第五层：命令行入口（参数真的传下去了吗）
# ============================================================================

class TestCli(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="cnl_cli_")
        self._orig_data_dir = C.data_dir
        self._orig_logger = C._logger
        C.data_dir = lambda: self.tmp
        C._logger = None                 # 让日志处理器也落到临时目录

    def tearDown(self):
        C.data_dir = self._orig_data_dir
        C._logger = self._orig_logger

    @staticmethod
    def _cli(argv):
        """跑一次 CLI，屏蔽它打印的内容，只关心返回值与副作用。"""
        import contextlib
        import io
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            rc = C.cli(argv)
        return rc, buf.getvalue()

    def test_force_flag_reaches_connect(self):
        """
        回归：--force 曾经只声明不传递，导致「强制重新登录」静默失效，
        已在线时永远跳过登录。
        """
        seen = {}

        def fake_connect(cfg, logger=None, force=False):
            seen["force"] = force
            return C.ConnectResult(True, C.LoginOutcome.OK, "ok")

        with mock.patch.object(C, "connect", fake_connect), \
                mock.patch.object(C, "wait_for_network", lambda *a, **k: True):
            rc, _ = self._cli(["--connect", "--force"])
        self.assertEqual(rc, 0)
        self.assertTrue(seen.get("force"), "--force 必须被传进 connect()")

    def test_connect_without_force_keeps_default(self):
        seen = {}

        def fake_connect(cfg, logger=None, force=False):
            seen["force"] = force
            return C.ConnectResult(True, C.LoginOutcome.OK, "ok")

        with mock.patch.object(C, "connect", fake_connect), \
                mock.patch.object(C, "wait_for_network", lambda *a, **k: True):
            self._cli(["--connect"])
        self.assertFalse(seen.get("force"), "不带 --force 时不应强制登录")

    def test_set_url_and_account_are_persisted(self):
        self.assertEqual(self._cli(["--set-url", "http://10.9.9.9/"])[0], 0)
        self.assertEqual(self._cli(["--set-account", "2024001", "Secret@1"])[0], 0)
        cfg = C.load_config()
        self.assertEqual(cfg["auth"]["login_url"], "http://10.9.9.9/")
        self.assertEqual(cfg["auth"]["username"], "2024001")
        self.assertEqual(C.get_password(cfg), "Secret@1")
        with open(C.config_file(), encoding="utf-8") as f:
            self.assertNotIn("Secret@1", f.read(), "密码不得以明文落盘")

    def test_manual_connect_does_not_wait_too_long(self):
        """手动 --connect 的等待上限应远小于开机模式，避免用户干等 3 分钟。"""
        recorded = {}

        def fake_wait(cfg, logger=None, max_wait=None):
            recorded["max_wait"] = max_wait
            return True

        with mock.patch.object(C, "wait_for_network", fake_wait), \
                mock.patch.object(C, "connect",
                                  lambda *a, **k: C.ConnectResult(
                                      True, C.LoginOutcome.OK, "ok")):
            self._cli(["--connect"])
        self.assertLessEqual(recorded["max_wait"], 30.0)


# ============================================================================
# 第五层：Dr.COM（城市热点）认证 —— 取自真机门户页的真实结构
# ============================================================================

DRCOM_PORTAL_HTML = """<!DOCTYPE html>
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=gb2312">
<title>上网登录页</title>
<script type="text/javascript">
v4serip='10.0.0.1';v46ip='10.0.0.100';
portalver='4.0';
authtype=1;
authloginIP='';
authloginport=801;
authloginpath='/eportal/?c=ACSetting&a=Login';
authloginparam='url=drappal';
authuserfield='DDDDD';
authpassfield='upass';
authlogoutpath='/eportal/?c=ACSetting&a=Logout&ver=1.0';
authlogoutport=801;
authsuccess='Dr.COMWebLoginID_3.htm';
authfail='Dr.COMWebLoginID_2.htm';
charset='gb2312';
</script>
<script src="a41.js?version=1753289342530"></script>
</head>
<body></body>
</html>
"""


DRCOM_APP_JS = """
var page = { name:'FFI0NB1658374298' };
var LOGIN_API = 'http://10.0.0.1:801/eportal/portal/login';
function doLogin(){ util._jsonp({url: LOGIN_API, data:{user_account:1,user_password:2}}); }
"""


class _FakeDrcomSession:
    calls: list = []
    login_body = "<!--Dr.COMWebLoginID_3.htm-->"

    def __init__(self, timeout=8.0, encoding="utf-8", logger=None):
        self.timeout, self.encoding, self.logger = timeout, encoding, logger

    def cookie_header(self):
        return ""

    def get(self, url, headers=None):
        type(self).calls.append(("GET", url))
        if "/a41.js" in url:
            # 真实门户的 a41.js 里就带着 program_index（即 page.name）与登录接口
            return C.HttpResult(status=200, body=DRCOM_APP_JS, final_url=url)
        if "a40.js" in url:
            return C.HttpResult(status=200, body=DRCOM_APP_JS, final_url=url)
        if "portal/login" in url:                  # 登录接口 GET：不返回成功标志
            return C.HttpResult(status=200,
                                body='jsonpReturn({"result":0,"msg":"no"});',
                                final_url=url)
        return C.HttpResult(status=200, body=DRCOM_PORTAL_HTML, final_url=url)

    def post(self, url, fields, headers=None, referer=""):
        type(self).calls.append(("POST", url, ""))
        return C.HttpResult(status=200, body="", final_url=url)

    def post_raw(self, url, body, headers=None, referer=""):
        type(self).calls.append(("POST", url, body))
        if "ACSetting" in url:                     # 仅老表单接口被"接受"
            return C.HttpResult(status=200, body=type(self).login_body, final_url=url)
        return C.HttpResult(status=200, body="<html>EPortal</html>", final_url=url)


class TestDrcomAdapter(unittest.TestCase):

    def setUp(self):
        _FakeDrcomSession.calls = []
        _FakeDrcomSession.login_body = "<!--Dr.COMWebLoginID_3.htm-->"
        self.tmp = tempfile.mkdtemp(prefix="cnl_dr_")
        self._o_dd, self._o_lg = C.data_dir, C._logger
        C.data_dir = lambda: self.tmp
        C._logger = None
        self.logger = C.setup_logging()

    def tearDown(self):
        C.data_dir, C._logger = self._o_dd, self._o_lg

    def test_parse_config_from_portal_page(self):
        pc = C._parse_portal_js_config(DRCOM_PORTAL_HTML)
        self.assertEqual(pc["authloginpath"], "/eportal/?c=ACSetting&a=Login")
        self.assertEqual(pc["authloginport"], 801)
        self.assertEqual(pc["authuserfield"], "DDDDD")
        self.assertEqual(pc["authpassfield"], "upass")
        self.assertEqual(pc["authsuccess"], "Dr.COMWebLoginID_3.htm")
        self.assertEqual(pc["charset"], "gb2312")

    def test_detect_drcom_beats_eportal(self):
        """回归：Dr.COM 的登录路径里也含 eportal，早期按关键字优先匹配 eportal，
        把本校门户误判成锐捷，导致一律 203。必须优先判 drcom。"""
        self.assertEqual(C.detect_adapter("http://10.0.0.1/", DRCOM_PORTAL_HTML),
                         "drcom")

    def test_login_prefers_drcom4_api_on_declared_port(self):
        """a41.js 写明真实接口前缀是 <host>:801/eportal/portal/，
        因此必须优先打 801 上的 4.x 接口，同时保留老 Dr.COM 表单作为兜底。"""
        with mock.patch.object(C, "HttpSession", _FakeDrcomSession), \
                mock.patch.object(C, "_port_open", lambda h, p, timeout=2.0: True):
            verdict, msg, _ = C._login_drcom("http://10.0.0.1/", "2024001",
                                             "secret", 3, "utf-8", self.logger)
        self.assertEqual(verdict, C.LoginOutcome.OK, msg)
        posts = [c for c in _FakeDrcomSession.calls if c[0] == "POST"]
        self.assertTrue(posts, "必须提交登录请求")
        self.assertIn(":801", posts[0][1], "第一个候选必须走门户声明的 801 端口")
        self.assertIn("/eportal/portal/login", posts[0][1])
        self.assertIn("user_account=2024001", posts[0][2])
        self.assertIn("user_password=secret", posts[0][2])
        self.assertTrue(any("DDDDD=2024001" in p[2] for p in posts),
                        "老的 Dr.COM 表单也要作为兜底尝试")

    def test_reads_program_index_and_login_api_from_scripts(self):
        """应从抓到的脚本里解析出 program_index，并按 a41.js 的流程调用 loadConfig。"""
        with mock.patch.object(C, "HttpSession", _FakeDrcomSession), \
                mock.patch.object(C, "_port_open", lambda h, p, timeout=2.0: True):
            C._login_drcom("http://10.0.0.1/", "u", "p", 3, "utf-8", self.logger)
        gets = [c[1] for c in _FakeDrcomSession.calls if c[0] == "GET"]
        self.assertTrue(any("page/loadConfig" in u for u in gets),
                        "必须按 a41.js 的流程调用 page/loadConfig")
        self.assertTrue(any("program_index=FFI0NB1658374298" in u for u in gets),
                        "program_index 应从脚本里解析得到")

    def test_slim_path_sends_far_fewer_requests(self):
        """
        回归（2026-10-06 用户反馈"校园网连接响应变慢"）：
        日常登录必须走精简路径。此前把当初逆向接口用的侦察动作（探端口、抓 a40.js、
        抓页面模板）也留在了主流程里 —— 实测一次登录要发 16 个请求，其中 10 个是 404。
        """
        _FakeDrcomSession.calls = []
        with mock.patch.object(C, "HttpSession", _FakeDrcomSession), \
                mock.patch.object(C, "_port_open", lambda h, p, timeout=2.0: True):
            C._login_drcom("http://10.0.0.1/", "2024001", "pw", 3, "utf-8",
                           self.logger)                 # diagnose 默认 False
        urls = [c[1] for c in _FakeDrcomSession.calls if c[0] == "GET"]
        self.assertLessEqual(len(urls), 5,
                             f"精简路径应只发 4~5 个请求，实际 {len(urls)} 个：{urls}")
        self.assertFalse(any("a40.js" in u for u in urls), "不该再抓 a40.js")
        self.assertFalse(any("pageAsset" in u for u in urls), "不该再抓前端资源")
        self.assertFalse(any("extern/" in u for u in urls), "不该再抓页面模板")

    def test_diagnose_mode_still_collects_evidence(self):
        """diagnose=True 时必须保留完整侦察，否则以后排障拿不到材料。"""
        _FakeDrcomSession.calls = []
        with mock.patch.object(C, "HttpSession", _FakeDrcomSession), \
                mock.patch.object(C, "_port_open", lambda h, p, timeout=2.0: True):
            C._login_drcom("http://10.0.0.1/", "2024001", "pw", 3, "utf-8",
                           self.logger, diagnose=True)
        urls = [c[1] for c in _FakeDrcomSession.calls if c[0] == "GET"]
        self.assertGreater(len(urls), 5, "诊断模式应抓取更多材料以便排障")

    def test_fail_marker_detected(self):
        _FakeDrcomSession.login_body = "<!--Dr.COMWebLoginID_2.htm-->"
        with mock.patch.object(C, "HttpSession", _FakeDrcomSession), \
                mock.patch.object(C, "_port_open", lambda h, p, timeout=2.0: True):
            verdict, _, _ = C._login_drcom("http://10.0.0.1/", "u", "p", 3,
                                           "utf-8", self.logger)
        self.assertEqual(verdict, C.LoginOutcome.FAILED)

    def test_decode_body_honours_declared_charset(self):
        """门户页是 gb2312，必须按响应声明的编码解，否则中文全成乱码。"""
        raw = "上网登录页".encode("gbk")
        self.assertEqual(C._decode_body(raw, "text/html; charset=gb2312"), "上网登录页")
        self.assertEqual(C._decode_body(raw, "text/html; charset=GB2312"), "上网登录页")

    def test_secrets_are_masked_in_logs(self):
        """日志要能贴出来排障，所以绝不能留下明文口令。"""
        s = "user_account=2024001&user_password=Passw0rd123&jsVersion=4.1.3"
        out = C._mask_secrets(s)
        self.assertNotIn("Passw0rd123", out)
        self.assertIn("user_password=***", out)
        self.assertIn("user_account=2024001", out, "账号不属于机密，无需打码")
        # URL 编码过的（%3D 形式）也要盖住
        self.assertNotIn("secret", C._mask_secrets("http://x/login?upass%3Dsecret&a=1"))

    def test_gzip_response_is_decompressed(self):
        """实测门户把 a41.js 以 gzip 返回（Content-Encoding: gzip），
        不解压抓到的是二进制乱码，脚本等于白抓。"""
        import gzip as _gz
        raw = _gz.compress("function page(){}".encode())
        self.assertEqual(
            C._decompress_bytes(raw, {"content-encoding": "gzip"}).decode(),
            "function page(){}")
        self.assertEqual(C._decompress_bytes(b"abc", {}), b"abc")   # 未压缩原样返回


class TestStartupFlow(unittest.TestCase):
    """开机自动登录：必须"缠斗到成功"，不能试一次就放弃。"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="cnl_boot_")
        self._o_dd, self._o_lg = C.data_dir, C._logger
        C.data_dir = lambda: self.tmp
        C._logger = None
        self.logger = logging.getLogger("cnl_boot_silent")

    def tearDown(self):
        C.data_dir, C._logger = self._o_dd, self._o_lg

    def test_wait_for_network_accepts_link_without_dns(self):
        """开机时 DNS 还没就绪，check_network 会判成"不通"；
        但只要网卡已拿到 IP，就该判定链路就绪，不该空等到超时。"""
        cfg = C.default_config()
        with mock.patch.object(
                C, "check_network",
                lambda *a, **k: C.NetStatus(C.ST_OFFLINE, "DNS 解析失败")), \
                mock.patch.object(C, "_has_local_ip", lambda: True):
            self.assertTrue(C.wait_for_network(cfg, self.logger, max_wait=5))

    def test_wait_for_network_still_fails_without_ip(self):
        """连 IP 都没有时，才应该老老实实等到超时并报失败。"""
        cfg = C.default_config()
        with mock.patch.object(
                C, "check_network",
                lambda *a, **k: C.NetStatus(C.ST_OFFLINE, "无链路")), \
                mock.patch.object(C, "_has_local_ip", lambda: False), \
                mock.patch.object(C.time, "sleep", lambda s: None):
            self.assertFalse(C.wait_for_network(cfg, self.logger, max_wait=0.01))

    def test_startup_defaults_are_aggressive(self):
        """开机参数要"抢时间 + 长耐心"：延迟要短，重试窗口要够长。"""
        au = C.default_config()["autostart"]
        self.assertLessEqual(au["delay"], 10, "开机后应尽快开始尝试")
        self.assertGreaterEqual(au["hard_retry_seconds"], 300, "要坚持足够久才放弃")


class TestBootModes(unittest.TestCase):
    """开机静默模式：无窗口、登录完就退出、失败持续重试。"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="cnl_boot_")
        self._orig_data_dir = C.data_dir
        self._orig_logger = C._logger
        C.data_dir = lambda: self.tmp
        C._logger = None
        self.logger = C.setup_logging()

    def tearDown(self):
        C.data_dir = self._orig_data_dir
        C._logger = self._orig_logger

    def _cfg(self):
        cfg = C.default_config()
        cfg["autostart"]["delay"] = 0
        cfg["autostart"]["hard_retry_seconds"] = 20
        cfg["autostart"]["hard_retry_interval"] = 1
        cfg["network"]["startup_wait"] = 1
        return cfg

    def test_default_autostart_is_windowless(self):
        """开机自启默认必须走无窗口的 --silent，而不是会弹窗口的 --startup。"""
        self.assertEqual(C.default_config()["autostart"]["args"], "--silent")
        self.assertIn("--silent", C.launch_command())
        self.assertNotIn("--startup", C.launch_command())

    def test_boot_login_returns_immediately_on_success(self):
        cfg = self._cfg()
        calls = []
        ok = C.ConnectResult(True, C.LoginOutcome.OK, "ok")
        with mock.patch.object(C, "wait_for_network", lambda *a, **k: True), \
                mock.patch.object(C, "connect",
                                  lambda c, l, force=False: (calls.append(1), ok)[1]):
            r = C.boot_login(cfg, self.logger)
        self.assertTrue(r.ok)
        self.assertEqual(len(calls), 1, "成功即返回，不该再尝试第二轮")

    def test_boot_login_gives_up_on_wrong_password(self):
        """明确失败（密码错误）必须立即停手，避免把账号试锁。"""
        cfg = self._cfg()
        calls = []
        bad = C.ConnectResult(False, C.LoginOutcome.FAILED, "密码错误")
        with mock.patch.object(C, "wait_for_network", lambda *a, **k: True), \
                mock.patch.object(C, "connect",
                                  lambda c, l, force=False: (calls.append(1), bad)[1]):
            r = C.boot_login(cfg, self.logger)
        self.assertFalse(r.ok)
        self.assertEqual(len(calls), 1, "密码错误不应重试")

    def test_boot_login_keeps_retrying_until_deadline(self):
        """可重试的失败（如未认证）应反复重试，而不是试一次就放弃。"""
        cfg = self._cfg()
        cfg["autostart"]["hard_retry_seconds"] = 2
        cfg["autostart"]["hard_retry_interval"] = 0.2
        calls = []
        retry = C.ConnectResult(False, C.LoginOutcome.RETRY, "未认证")
        with mock.patch.object(C, "wait_for_network", lambda *a, **k: True), \
                mock.patch.object(C, "connect",
                                  lambda c, l, force=False: (calls.append(1), retry)[1]):
            C.boot_login(cfg, self.logger)
        self.assertGreaterEqual(len(calls), 2, "应至少重试一次")

    def test_run_silent_exits_without_daemon(self):
        """watch=False：登录完必须直接返回，不留后台进程。"""
        cfg = self._cfg()
        ok = C.ConnectResult(True, C.LoginOutcome.OK, "ok")
        with mock.patch.object(C, "wait_for_network", lambda *a, **k: True), \
                mock.patch.object(C, "connect", lambda c, l, force=False: ok), \
                mock.patch.object(C, "check_network",
                                  side_effect=AssertionError("不该进入守护循环")):
            rc = C.run_silent(cfg, self.logger, watch=False)
        self.assertEqual(rc, 0)

    def test_run_silent_never_daemonizes_after_failure(self):
        """登录失败时也不能进入守护循环（否则进程会一直赖着不走）。"""
        cfg = self._cfg()
        bad = C.ConnectResult(False, C.LoginOutcome.FAILED, "密码错误")
        with mock.patch.object(C, "wait_for_network", lambda *a, **k: True), \
                mock.patch.object(C, "connect", lambda c, l, force=False: bad), \
                mock.patch.object(C, "check_network",
                                  side_effect=AssertionError("不该进入守护循环")):
            rc = C.run_silent(cfg, self.logger, watch=True)
        self.assertEqual(rc, 1)

    def test_run_silent_watch_enters_daemon(self):
        """watch=True（手动指定）才进入常驻守护。"""
        cfg = self._cfg()
        ok = C.ConnectResult(True, C.LoginOutcome.OK, "ok")
        seen = []

        def fake_check(c, quick=False):
            seen.append(1)
            raise KeyboardInterrupt       # 打断 while True，避免测试卡住

        with mock.patch.object(C, "wait_for_network", lambda *a, **k: True), \
                mock.patch.object(C, "connect", lambda c, l, force=False: ok), \
                mock.patch.object(C, "check_network", fake_check), \
                mock.patch.object(C.time, "sleep", lambda *a, **k: None):
            with self.assertRaises(KeyboardInterrupt):
                C.run_silent(cfg, self.logger, watch=True)
        self.assertTrue(seen, "watch=True 应进入守护循环")


if __name__ == "__main__":
    unittest.main(verbosity=2)

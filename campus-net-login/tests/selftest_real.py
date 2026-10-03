# -*- coding: utf-8 -*-
"""
真实校园网登录自测

用途：在真实网络环境下走一遍「环境快照 → 状态判定 → 门户探测 → 尝试登录」，
      把每一步的结果同时打到屏幕 + 落盘成 测试结果.txt，方便直接发回分析。

用法：
    双击上级目录的「测试校园网.bat」
    或：  python tests/selftest_real.py [--force]

说明：
    --force  即使程序判定「已在线」也强制走一次登录（用于多网卡场景下验证登录链路）
"""
from __future__ import annotations

import datetime
import logging
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import campus_login as C  # noqa: E402

REPORT = os.path.join(ROOT, "测试结果.txt")
LOG_FILE = os.path.join(ROOT, "logs", "campus_login.log")
LINES: list[str] = []


# ---------------------------------------------------------------- 输出工具
def say(text: str = "") -> None:
    print(text)
    LINES.append(text)


def head(title: str) -> None:
    say()
    say("=" * 68)
    say(title)
    say("=" * 68)


def sh(args) -> str:
    """执行系统命令并按中文编码解出文本。"""
    try:
        p = subprocess.run(args, capture_output=True, timeout=25)
    except Exception as e:                       # noqa: BLE001
        return f"(执行失败: {e})"
    for enc in ("gbk", "utf-8"):
        try:
            return p.stdout.decode(enc)
        except UnicodeDecodeError:
            continue
    return p.stdout.decode("utf-8", "replace")


# ---------------------------------------------------------------- 各步骤
def step_config(cfg: dict) -> bool:
    head("① 配置检查")
    auth = cfg.get("auth", {})
    login_url = (auth.get("login_url") or "").strip()
    username = auth.get("username") or ""
    has_pwd = bool(auth.get("password_enc"))
    say(f"  登录地址 : {login_url or '(未配置)'}")
    say(f"  账号     : {C._mask_user(username)}")
    say(f"  密码     : {'已保存（DPAPI 加密）' if has_pwd else '(未设置)'}")
    say(f"  认证类型 : {auth.get('adapter')}")
    if not login_url or not username or not has_pwd:
        say("  [X] 配置不完整 —— 请先打开界面点「设置账号密码」填好再测。")
        return False
    return True


def step_interfaces() -> list:
    head("② 网络接口快照")
    for block in sh(["ipconfig"]).split("\n\n"):
        keep = []
        for line in block.split("\n"):
            s = line.strip()
            if any(k in s for k in ("适配器", "IPv4", "默认网关", "媒体状态")):
                keep.append(s)
        if keep:
            say("  " + " | ".join(keep))
    return step_routes()


def step_routes() -> list:
    head("③ 默认路由（决定流量实际走哪张网卡）")
    defaults = []
    for line in sh(["route", "print", "-4"]).split("\n"):
        p = line.split()
        if len(p) >= 5 and p[0] == "0.0.0.0" and p[1] == "0.0.0.0":
            defaults.append(p)
    if not defaults:
        say("  (无默认路由 —— 可能完全没联网)")
        return defaults
    for p in sorted(defaults, key=lambda x: int(x[4])):
        say(f"  网关 {p[2]:<16} 本机 {p[3]:<16} metric={p[4]}")
    if len(defaults) > 1:
        say("")
        say("  [!] 检测到多条默认路由：有多张网卡同时在线。")
        say("      系统只会用 metric 最小的那条发外网流量。")
        say("      如果那条不是校园网接口，访问门户就会走错网卡。")
    return defaults


def step_status(cfg: dict):
    head("④ 程序联网状态判定")
    st = C.check_network(cfg, quick=False)
    say(f"  状态     : {st.text}")
    say(f"  详情     : {st.detail or '-'}")
    say(f"  本机 IP  : {C.local_ip()}")
    if st.portal_url:
        say(f"  门户跳转 : {st.portal_url}")
    return st


def step_portal(cfg: dict, login_url: str):
    head("⑤ 认证门户可达性")
    last = None
    for i in (1, 2):
        last = C.http_get(login_url, timeout=6, max_redirect=3)
        if not last.error:
            say(f"  HTTP {last.status}   最终地址：{last.final_url}")
            say("  [OK] 门户可达 —— 当前确实处于未认证状态，具备测试条件。")
            return True, last
        say(f"  第 {i} 次尝试失败：{last.error}")
    say("  [X] 门户不可达。常见原因：")
    say("      ① 外网由别的网卡提供（如手机热点），校园网这张卡没生效；")
    say("      ② 网线没插 / 没连校园网 WiFi。")
    return False, last


def step_probe(cfg: dict) -> None:
    head("⑥ 认证页探测")
    try:
        say(C.probe_portal(cfg))
    except Exception as e:                       # noqa: BLE001
        say(f"  [X] 探测异常：{e}")


def step_login(cfg: dict, logger, reachable: bool, st, force: bool):
    head("⑦ 尝试登录")
    if not reachable:
        say("  [跳过] 门户不可达，登录必然失败，不发起请求以免无意义等待。")
        return None
    use_force = force
    if st.state == C.ST_ONLINE and not force:
        use_force = True
        say("  [注意] 程序判定「已在线」，但门户同时可达 —— 很可能有多张网卡。")
        say("         本次改为强制登录，以便真实验证登录链路。")
    res = C.connect(cfg, logger=logger, force=use_force)
    say(f"  结果     : {'成功' if res.ok else '失败'}")
    say(f"  判定     : {res.verdict}")
    say(f"  说明     : {res.message}")
    say(f"  尝试次数 : {res.attempts}    耗时：{res.elapsed:.1f}s")
    if res.status:
        say(f"  复检     : {res.status.text}（{res.status.detail or '-'}）")
    return res


# ---------------------------------------------------------------- 收尾
def _tail_log(max_lines: int = 180) -> list[str]:
    if not os.path.isfile(LOG_FILE):
        return []
    try:
        with open(LOG_FILE, encoding="utf-8", errors="replace") as f:
            lines = f.read().splitlines()
    except OSError:
        return []
    return lines[-max_lines:]


def step_portal_dump() -> None:
    """把门户页原文里跟接口调用有关的关键片段摘出来，供直接分析。"""
    path = os.path.join(ROOT, "logs", "portal_page.html")
    if not os.path.isfile(path):
        return
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            html = f.read()
    except OSError:
        return
    say()
    say("-" * 68)
    say("门户页原文关键片段（用于判断接口到底怎么调）")
    say("-" * 68)
    say(f"  原文文件：{path}（共 {len(html)} 字符）")
    keys = ("InterFace.do", "queryString", "userIndex", ".ajax(", ".post(")
    seen, shown = set(), 0
    for line in html.splitlines():
        s = line.strip()
        if not s:
            continue
        hit = [k for k in keys if k in s]
        if not hit:
            continue
        if len(s) > 240:                      # 单行压缩的 JS：围绕关键字取窗口
            idx = min(s.find(k) for k in hit if s.find(k) >= 0)
            s = s[max(0, idx - 80): idx + 160]
        if s in seen:
            continue
        seen.add(s)
        say("  " + s)
        shown += 1
        if shown >= 30:
            say("  …（更多内容见原文文件）")
            break
    if not shown:
        say("  （未找到关键字，页面可能是纯静态或被压缩）")


def step_hints() -> None:
    """把已抓到的页面/脚本里出现的后端接口路径集中列出来。"""
    logs = os.path.join(ROOT, "logs")
    if not os.path.isdir(logs):
        return
    found = set()
    for fn in sorted(os.listdir(logs)):
        if not fn.endswith((".js", ".html")):
            continue
        try:
            with open(os.path.join(logs, fn), encoding="utf-8", errors="replace") as f:
                text = f.read()
        except OSError:
            continue
        for h in C._interface_hint(text):
            found.add((fn, h))
    if not found:
        return
    say()
    say("-" * 68)
    say("页面/脚本里出现的接口路径（定位真实登录接口的线索）")
    say("-" * 68)
    for fn, h in sorted(found)[:40]:
        say(f"  [{fn}] {h}")


def step_js_extract() -> None:
    """从抓到的 JS 里摘出登录相关代码 —— 参数怎么拼、接口怎么调全在这里面。"""
    logs = os.path.join(ROOT, "logs")
    if not os.path.isdir(logs):
        return
    blob, names = "", []
    for fn in sorted(os.listdir(logs)):
        if not fn.endswith(".js"):
            continue
        try:
            with open(os.path.join(logs, fn), encoding="utf-8", errors="replace") as f:
                blob += "\n" + f.read()
            names.append(fn)
        except OSError:
            continue
    if not blob.strip():
        return
    say()
    say("-" * 68)
    say(f"抓到的 JS（{'、'.join(names)}）里的登录相关片段")
    say("-" * 68)
    say(f"  （总长度 {len(blob)} 字符；完整文件就在 logs 目录，可直接发回）")
    pat = re.compile(
        r".{0,160}(?:authloginpath|authuserfield|authpassfield|ACSetting|0MKKey"
        r"|DDDDD|upass|loginMethod|login_method|loginPath).{0,260}", re.S)
    seen, shown = set(), 0
    for m in pat.finditer(blob):
        frag = re.sub(r"\s+", " ", m.group(0)).strip()
        if frag in seen:
            continue
        seen.add(frag)
        say("  " + frag[:360])
        shown += 1
        if shown >= 30:
            say("  …（更多内容见 logs 下的 JS 文件）")
            break
    if not shown:
        say("  （未提取到关键词）")


def finish(reachable: bool, res, st) -> None:
    head("⑧ 结论与下一步")
    if reachable:
        if res is not None and res.ok:
            say("  ✅ 登录成功 —— 程序链路完全正常。")
            say("     下一步：打开界面，把「开机自动登录」开关打开即可。")
        else:
            say("  ❌ 登录未成功 —— 已记录完整现场。")
            say("     请把本文件「测试结果.txt」发回，日志里有服务器原始响应。")
    elif st.state == C.ST_ONLINE:
        say(f"  ⚠ 门户不可达，但外网是通的（当前出口 IP：{C.local_ip()}）。")
        say("     两种可能：")
        say("       A. 外网仍由另一张网卡提供（热点没断干净）——")
        say("          请确认热点已断开，然后重测；")
        say("       B. 这张校园网卡本身不需要认证、已经能上网 ——")
        say("          那就无需自动登录，直接使用即可。")
    else:
        say("  既连不上外网，也连不上认证门户。")
        say("  请确认网线插好 / 已连接校园网 WiFi，然后重测。")

    _write_report()


def _write_report() -> None:
    tail = _tail_log()
    if tail:
        head("附：运行日志（末尾 %d 行）" % len(tail))
        for l in tail:
            say("  " + l)
    try:
        with open(REPORT, "w", encoding="utf-8") as f:
            f.write("\n".join(LINES) + "\n")
        say("")
        say(f"报告已保存：{REPORT}")
    except OSError as e:
        print(f"报告写入失败：{e}")


def main() -> int:
    force = "--force" in sys.argv
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    logger = C.setup_logging(logging.DEBUG)

    head("校园网登录 · 真实环境自测")
    say(f"时间：{datetime.datetime.now():%Y-%m-%d %H:%M:%S}")
    say(f"模式：{'强制登录' if force else '常规（已在线则跳过）'}")

    cfg = C.load_config()
    if not step_config(cfg):
        head("⑧ 结论")
        say("  配置不完整，未开始网络测试。")
        say("  请先打开界面点「设置账号密码」填好三项（地址/账号/密码）后重试。")
        _write_report()
        return 2

    step_interfaces()
    st = step_status(cfg)
    reachable, _ = step_portal(cfg, (cfg.get("auth", {}).get("login_url") or "").strip())
    step_probe(cfg)
    res = step_login(cfg, logger, reachable, st, force)
    step_portal_dump()
    step_hints()
    step_js_extract()
    finish(reachable, res, st)
    return 0


if __name__ == "__main__":
    sys.exit(main())

# 校园网自动登录助手

开机自动连接并登录校园网（Portal / Web 认证）。
**纯 Python 标准库实现，零第三方依赖**，Windows 下开箱即用。

---

## 一、特性

| 能力 | 说明 |
| --- | --- |
| 三项可配置 | 登录网址 / 账号 / 密码，界面与命令行均可修改 |
| 密码不落明文 | 用 Windows **DPAPI** 加密后写入配置，源码与配置文件里都搜不到明文 |
| 启动先检测 | 已在线直接退出，**不重复登录** |
| 自动适配 | 自动识别认证系统类型，填入账号密码提交，并复检确认 |
| 结果三态 | 区分「登录成功 / 登录失败（密码错误等）/ 需要重新登录（被顶下线）」 |
| 开机自启 | 一键启用/禁用，写当前用户注册表，**免管理员权限** |
| 无人值守 | 开机后自动等网络、自动重试，失败会持续重连而不是放弃 |
| 控制面板 | 连接 / 断开 / 设置账号 / 自启开关 / 查看日志 / 探测认证页 |
| 异常可见 | 网络不通、字段变化、超时、认证失败都有明确原因，全部写入日志 |
| 日志脱敏 | 写盘前自动把口令字段替换成 `***` |

---

## 二、快速开始

**第 0 步 · 确认 Python**（用打包好的 exe 可跳过）

需要 Python 3.8+ 且**带 tkinter**：

```bash
python -c "import tkinter; print(tkinter.TkVersion)"
```

打印出 `8.6` 之类的版本号即可。报 `ModuleNotFoundError` 说明是精简版 Python，换个官方安装包（安装时保留 tcl/tk 组件）。

**第 1 步 · 填写登录信息**

* 方式 A（推荐）：双击 `启动.bat` → 点「设置账号密码」→ 填三项 → 保存
* 方式 B（命令行）：

```bash
python campus_login.py --set-url "http://10.10.10.10/"      # 校园网登录网址
python campus_login.py --set-account 学号 密码               # 密码自动加密
```

**第 2 步 · 试一次**

```bash
python campus_login.py --connect     # 立即登录
python campus_login.py --status      # 查看联网状态
```

成功后，在控制面板把「开机自动登录」开关打开即可。

> 不知道登录网址填什么？见[第五章](#五认证系统适配)，用 `--probe` 一探便知。

---

## 三、文件说明

```
campus-net-login/
├── campus_login.py            主程序（单文件，[0]~[11] 分区，中文注释）
├── 启动.bat                   启动图形界面
├── 测试校园网.bat              真实环境一键自测（八步自动，结果落盘）
├── 启用开机自启.bat / 关闭开机自启.bat
├── config.example.json        配置模板（含全部字段说明）
└── tests/
    ├── test_core.py           主自测，51 项
    ├── test_eportal_e2e.py    端到端验证，9 项（自动起仿真服务器）
    ├── mock_eportal.py        仿真 ePortal 服务器，可单独启动
    └── selftest_real.py       「测试校园网.bat」调用的自测脚本
```

以下文件**首次运行后自动生成**，已在 `.gitignore` 中排除，不会进仓库：

| 文件 | 内容 |
| --- | --- |
| `config.json` | 实际配置（密码是 DPAPI 密文） |
| `logs/campus_login.log` | 运行日志（超 1MB 滚动，保留 3 份） |
| `测试结果.txt` | 自测脚本的报告 |

> 别手动往 `config.json` 写密码——用界面或 `--set-account`，程序才会加密。

---

## 四、配置说明

### auth — 登录信息

| 字段 | 说明 |
| --- | --- |
| `login_url` | **校园网登录网址**。可填完整认证地址，也可只填网关地址（程序会跟随跳转） |
| `username` | 账号（学号 / 上网账号） |
| `password_enc` | 密码密文，**由程序生成，不要手写**（Windows 下形如 `dpapi:AQAAANCMnd8...`） |
| `adapter` | 认证系统类型，默认 `auto` 自动识别 |
| `logout_url` | 断开接口地址（可选），留空则按识别出的类型自动尝试 |
| `encoding` | 编码，默认 `utf-8`，老系统可能是 `gbk` |
| `custom` | 自定义接口，仅当 `adapter` 为 `custom` 时使用 |

### auth.custom — 万能兜底

自动识别失败时使用。支持 `{username}` `{password}` `{ip}` 三个占位符：

```json
"custom": {
  "method": "POST",
  "url": "http://10.10.10.10:8080/eportal/InterFace.do?method=login",
  "params": {
    "userId": "{username}",
    "password": "{password}",
    "queryString": "wlanuserip=xxx&wlanacname=yyy"
  },
  "headers": { "Referer": "http://10.10.10.10/a70.htm" },
  "success_keywords": ["success", "登录成功"],
  "failure_keywords": ["密码错误", "账号不存在"]
}
```

`params` 的键名照你抓到的实际请求填。填了 `success_keywords` / `failure_keywords` 就**优先**按它们判定。

### network — 检测与重试

| 字段 | 默认 | 说明 |
| --- | --- | --- |
| `probes` | 见下 | 探测点列表，每项 `[地址, 期望内容]`，期望内容为空表示只要求 200/204 |
| `timeout` | 8 | 单次请求超时（秒） |
| `retry` | 3 | 登录重试次数 |
| `retry_interval` | 6 | 重试间隔（秒） |
| `startup_wait` | 180 | 开机后最长等待网络就绪的时间（秒） |
| `watch_interval` | 45 | 断线重连检测间隔（秒） |

默认探测点为 `http://www.msftconnecttest.com/connecttest.txt` 与
`http://connect.rom.miui.com/generate_204`，它们能区分
「已认证」「被劫持到认证页」「完全不通」三种状态。

> ⚠️ 探测点**不要填校园网内部地址**，否则未认证时也能通，就检测不出真实状态了。

### autostart — 开机自启

| 字段 | 默认 | 说明 |
| --- | --- | --- |
| `enabled` | false | 开关状态（程序维护） |
| `delay` | 5 | 开机后延迟几秒开始登录 |
| `hard_retry_seconds` | 900 | 开机后最长坚持重试多久（秒） |
| `hard_retry_interval` | 15 | 每轮重试间隔（秒） |
| `args` | `--startup` | 自启参数，可改 `--silent` 走无窗口后台 |

### advanced — 其他

| 字段 | 默认 | 说明 |
| --- | --- | --- |
| `verify_by_recheck` | true | 提交后重新探测外网确认（**建议保持开启**，很多系统失败也返回 200） |
| `open_login_page_on_failure` | false | 自动登录失败时是否打开登录页，方便手动处理 |

---

## 五、认证系统适配

### adapter 取值

| 值 | 适用系统 | 说明 |
| --- | --- | --- |
| `auto` | — | **默认**，访问一次认证页，按页面特征自动判断 |
| `srun` | 深澜 | 走 `/srun_portal_pc?ac_id=`，自动从跳转地址取 `ac_id` |
| `eportal` | 锐捷 ePortal | 走 `/eportal/InterFace.do?method=login`，自动拼 `queryString` |
| `drcom` | Dr.COM / 城市热点 | 走 `:801/eportal/portal/login`，按页面声明构造请求 |
| `form` | 通用网页表单 | **通用兜底**：抓登录页 HTML，自动识别账号/密码框（含 JS 生成的游离 `input`），保留 hidden 字段后提交 |
| `custom` | 任意 | 按 `auth.custom` 提交，最灵活 |

自动识别不准时，直接把 `adapter` 写死成对应值；都不行就用 `custom`。

### 怎么知道自己学校用哪个

```bash
python campus_login.py --probe
```

跟随一次跳转、打印最终认证地址、识别系统类型，并**列出页面里所有表单与字段名**。

探测也搞不定时改手动抓包：浏览器打开登录页 → `F12` → `Network` → 勾选
`Preserve log` → 正常登录一次 → 找到那条 `login` 请求，把**地址**和**参数名**
抄进 `auth.custom`。

### Dr.COM（城市热点）4.x 实测流程

> 下面是从真实站点抓包还原的完整链路。Dr.COM 与锐捷 ePortal 完全是两套东西。

**登录接口**

```
GET http://<门户IP>:801/eportal/portal/login
    ?user_account=<账号>&user_password=<密码>
    &wlan_user_ip=<本机IP>&wlan_user_mac=<本机MAC>
    &wlan_ac_ip=&jsVersion=4.1.3&callback=dr1
```

* 是 **GET（JSONP）**，参数走 URL。用 POST 提交只会得到
  `{"result":0,"msg":"无法获取用户认证账号！"}`
* 成功响应：`dr1({"result":1,"msg":"Portal协议认证成功！"})`

**前置步骤**：先调 `GET :801/eportal/portal/page/loadConfig`
（含 `program_index`、base64 的 `wlan_user_ip`），拿到 `login_method` 等配置。

**登录逻辑不在 HTML 里**：门户页（80 端口，如 `a79.htm`）只是空壳，它加载
`a41.js`（流程编排）和 **`a40.js`（登录逻辑本体）**，登录表单由 `pc.js` 模板
动态生成——所以直接抓 HTML 永远看不到表单，必须抓 JS。

程序会自动把这些脚本存进 `logs/`。若学校升级了系统，照着 `logs/a40.js`
里的实际调法改 `_login_drcom()` 即可。

**踩过的坑**

| 坑 | 教训 |
| --- | --- |
| 靠 URL 关键字猜系统 | Dr.COM 的登录路径里也含 `eportal` 字样，按关键字优先匹配会误判成锐捷 |
| 不看页面声明 | 门户页内联脚本里就有 `authloginpath` / `authuserfield` / `authpassfield`，**照抄最可靠** |
| 忽略 gzip | 响应头带 `Content-Encoding: gzip`，不解压拿到的是一坨二进制乱码 |
| 一律当 utf-8 | 门户页是 `gb2312`，中文全乱；要按响应声明的 charset 解码 |

### 锐捷 ePortal 的两个坑

| 坑 | 现象 | 原因 |
| --- | --- | --- |
| 缺会话 Cookie | `Error code: 203 Bad request(2)` | 必须先访问门户页拿到 `JSESSIONID`，再带**同一** Cookie 提交 |
| 请求行查询串被拼错 | 同样 203 | `urlunparse` 第 4 位是 `params`、第 5 位才是 `query`，位置写错会把 `?method=login` 拼成 `;method=login` |

`queryString` 参数的两种来源程序都支持：302 跳转后的最终 URL，
或页面内联的 JS 变量 / 隐藏域。两处都取不到时会在日志里明确预警。

---

## 六、开机自启

**启用 / 关闭**

* 控制面板 →「开机自动登录」开关
* 命令：`python campus_login.py --autostart on` / `off`

写入位置（当前用户，**免管理员权限**，不影响其他用户）：

```
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run   项名：CampusNetAutoLogin
```

开机后的行为：先等链路就绪（最长 `startup_wait` 秒，判据是**网卡拿到 IP**
而非 DNS 能解析——开机时 DNS 往往还没起来），再延迟 `delay` 秒登录；
失败不会放弃，而是每 `hard_retry_interval` 秒重试一次，直到成功或超过
`hard_retry_seconds`。唯一例外是明确报错（如密码错误）会立即停手，避免把账号试锁。

**查看当前状态（三种方式）**

1. 控制面板上开关的位置，下方还会显示注册表里的具体启动命令
2. `python campus_login.py --autostart status`
3. `Win + R` → `regedit` → 定位到上面的路径找 `CampusNetAutoLogin`；
   或**任务管理器 → 启动**选项卡

---

## 七、命令行

```bash
python campus_login.py                     # 图形控制面板（默认）
python campus_login.py --startup           # 开机自启模式：自动登录 + 最小化 + 断线重连
python campus_login.py --silent            # 无窗口后台守护，只写日志
python campus_login.py --connect           # 登录一次后退出
python campus_login.py --connect --force   # 即使已在线也强制重登
python campus_login.py --status            # 打印当前联网状态
python campus_login.py --probe             # 探测认证页并打印表单结构
python campus_login.py --set-url URL
python campus_login.py --set-account 账号 密码
python campus_login.py --autostart on|off|status
python campus_login.py --show-config       # 查看配置（密码自动打码）
```

退出码：登录成功 `0`，失败 `1`，网络未就绪 `2`。方便被其他脚本调用。

---

## 八、异常处理

| 情况 | 程序行为 |
| --- | --- |
| 网络不通 | **不发起登录**，提示具体原因（超时 / DNS 失败 / 网络不可达）；开机模式下继续等 |
| 未认证被劫持 | 从 302 跳转取出真实认证地址，接着登录 |
| 表单字段识别不出 | 提示「字段无法自动识别」并列出已解析到的字段名，引导改用 `custom`，不静默失败 |
| 请求超时 | 按 `retry` 次数重试，间隔 `retry_interval`，逐次记日志 |
| 密码错误 / 账号被锁 | **立即停止，不重试**，避免连续错误提交把账号试锁 |
| 提交成功但仍未认证 | 复检发现状态没变，判为「需要重新登录」，重试若干次后如实报告 |
| 配置缺失 | 指出缺哪一项（网址 / 账号 / 密码），不抛异常 |
| 配置文件损坏 | 备份为 `config.json.broken` 后重建默认配置 |
| 界面操作中 | 按钮自动禁用，后台线程执行，不卡界面；异常在状态栏和日志里显示 |

日志在程序目录下 `logs/campus_login.log`，控制面板可一键查看、复制、打开。

---

## 九、系统适配

| 环境 | 支持情况 |
| --- | --- |
| **Windows 10 / 11** | 完整支持（DPAPI 加密、注册表自启、`pythonw.exe` 无黑窗启动） |
| **Windows 7 / 8.1** | 可用，需 Python 3.8（3.9+ 官方已不支持 Win7）。程序纯标准库，无兼容性障碍 |
| **无 tkinter 的精简版 Python** | 图形界面不可用，但**命令行功能全部正常**，程序会提示替代命令 |
| **macOS / Linux** | 可运行（需另装 `python3-tk`）。无 DPAPI，密码自动降级为混淆存储并给出提示；自启需自行配 `launchd` / `systemd` |
| **高 DPI 屏幕** | 窗口尺寸与字体自动适配，按钮不会被裁掉 |
| **自签证书的认证页** | 不会因证书校验失败而中断 |

> **换电脑 / 换用户**：DPAPI 密文与「当前 Windows 用户」绑定，把 `config.json`
> 拷到别的电脑无法解密，需重设一次密码——这是设计如此。

---

## 十、安全

* 源码中**没有任何明文账号密码**，密码只以密文形式存在于 `config.json`。
* 加密用 Windows 自带的 `CryptProtectData`（DPAPI），密钥由系统按当前用户账户派生，
  并叠加了应用专属熵。除本机本用户外无法解密。
* 想临时跑一次不落盘，可用环境变量（优先级高于配置文件）：

  ```bash
  set CAMPUS_PWD=你的密码
  python campus_login.py --connect
  ```

* **日志里的口令一律打码**（`user_password=***`）。日志经常要被贴出来排障，
  所以写盘前会替换 `password` / `pwd` / `upass` / `user_password` 等字段的值，
  但请求本身仍用原值发送。
* 程序不采集、不上传任何数据，除认证请求外不访问其他网络地址。

---

## 十一、自测与排错

```bash
python tests/test_core.py           # 主自测，51 项
python tests/test_eportal_e2e.py    # 端到端，9 项
```

* **`test_core.py`** 覆盖四层：逻辑层（加解密往返、配置读写、表单解析、适配器识别、
  URL 拼接与 queryString 兜底提取）、引擎层（打桩网络，验证「已在线跳过 / 成功 /
  失败不重试 / 重试后判定需重新登录」）、界面层（建窗口 + 灌最长文本断言布局不被撑破）、
  命令行层（`--force` 传递、`--set-url` 落盘、等待上限）。
* **`test_eportal_e2e.py`** 起一个**仿真 ePortal 服务器**跑真实 HTTP，覆盖复现 203、
  会话流程登录成功、自动识别类型、密码错误不重试、已在线跳过、缺失 queryString 告警、
  注销、参数只在页面里的兜底提取。仿真服务器行为对齐真机（含「无会话 Cookie 就回 203」）。

想单独跑仿真服务器：

```bash
python tests/mock_eportal.py --port 8888
python campus_login.py --set-url "http://127.0.0.1:8888/"
python campus_login.py --set-account student001 Passw0rd
python campus_login.py --connect          # 完全离线就能验证整条链路
```

### 在真实校园网上验证

门户**只在未认证状态下可达**，所以要在「连着校园网但尚未认证」时测。

双击 **`测试校园网.bat`**，它自动完成八步：

> ① 检查配置 → ② 打印网络接口 → ③ 打印默认路由（判断流量走哪张网卡）
> → ④ 状态判定 → ⑤ 门户可达性 → ⑥ 认证页探测 → ⑦ 尝试登录 → ⑧ 给出结论

结果上屏并保存为 `测试结果.txt`（UTF-8，含日志末尾，可直接发给别人分析）。
需要强制重登时加参数：`测试校园网.bat --force`。

**前提是让校园网那张网卡成为出口。** 门户通常只在校园网段内可达；若机器同时连着
手机热点，系统会用 metric 更小的默认路由发外网流量，门户就连不上（第 ③ 步能直接看出来）。

* **方案 A（最简单）**：断开热点 → 双击 `测试校园网.bat` → 测完重连热点。
  若登录成功，外网会自动恢复。
* **方案 B（全程不断网，需管理员）**：保留热点，把门户单独路由到校园网网卡：

  ```bat
  route add <门户IP> mask 255.255.255.255 <有线口网关> metric 1
  :: 测完删除
  route delete <门户IP>
  ```

  `<有线口网关>` 从 `ipconfig /all` 里看。这条路由只影响一个地址，外网不受影响。

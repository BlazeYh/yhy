# 校园网自动登录助手 CampusNetLogin

开机自动连接并登录校园以太网（Portal / Web 认证）。
**纯 Python 标准库实现，零第三方依赖**，Windows 下开箱即用。

---

## 一、它能做什么

| 需求 | 实现方式 |
| --- | --- |
| 登录信息可配置 | 登录网址 / 账号 / 密码三项独立配置，支持界面与命令行两种修改方式 |
| 密码安全保存 | 密码用 **Windows DPAPI** 加密后写入配置文件，源码与配置里都没有明文 |
| 启动即检测 | 先探测是否已联网：已在线直接结束，**不会重复登录** |
| 自动登录 | 自动识别认证系统类型，填好账号密码后提交，并复检确认结果 |
| 结果三态判定 | 区分「登录成功 / 登录失败（如密码错误）/ 需要重新登录（被顶下线等）」 |
| 开机自启动 | 一键启用/禁用，写入当前用户注册表，**不需要管理员权限** |
| 控制面板 | 立即连接、断开连接、设置账号密码、自启开关、查看日志、探测认证页 |
| 异常处理 | 网络不通、页面元素变化、超时、认证失败均有明确提示，可自动重试 |
| 运行日志 | 全部结果写入日志文件，界面内可直接查看、复制、打开 |

---

## 二、文件说明

```
campus-net-login/
├── campus_login.py             主程序（单文件，按 [0]~[11] 分区块，中文注释）
├── CampusNetLogin.exe          （可选）打包后的免安装版本，双击即用
├── 启动.bat                    双击启动图形界面（自动寻找可用的 Python）
├── 测试校园网.bat               双击做一次真实环境自测（八步全自动，结果落盘）
├── 启用开机自启.bat             一键开启开机自动登录
├── 关闭开机自启.bat             一键关闭开机自动登录
├── config.example.json         配置模板（含全部字段说明）
├── config.json                 实际配置（首次运行自动生成，含加密后的密码）
├── 测试结果.txt                 自测脚本的输出报告（运行后生成）
├── logs/campus_login.log       运行日志（自动滚动，超过 1MB 换一份，保留 3 份）
└── tests/
    ├── test_core.py            主自测脚本，48 项，可无人值守运行
    ├── mock_eportal.py         仿真锐捷 ePortal 服务器（离线验证用，可单独启动）
    ├── test_eportal_e2e.py     登录流程端到端验证，9 项
    └── selftest_real.py        「测试校园网.bat」调用的真实环境自测脚本
```

`config.json` 和 `logs/` 在程序首次运行时自动创建，**不要手动把密码写进 config.json**，
用界面上的「设置账号密码」或命令 `--set-account` 来设，程序会自动加密。

---

## 三、快速开始（三步）

### 第 1 步：确认 Python

程序需要 **Python 3.8+**，且该 Python **必须带有 tkinter**（图形界面依赖）。

```bash
python -c "import tkinter; print(tkinter.TkVersion)"
```

能打印出版本号（如 `8.6`）即可。若报 `ModuleNotFoundError`，说明这个 Python 是精简版，
换一个官方安装包安装的 Python 即可（安装时保持默认勾选 tcl/tk 组件）。

> 已经用了打包好的 `CampusNetLogin.exe` 的话，可以完全跳过这一步 —— exe 自带运行环境。

### 第 2 步：填写登录信息

**方式 A（推荐）**：双击 `启动.bat` 打开控制面板 → 点「设置账号密码」→ 填三项 → 保存。

**方式 B（命令行）**：

```bash
python campus_login.py --set-url "http://10.10.10.10/"     # 校园网登录网址
python campus_login.py --set-account 20230012345 你的密码    # 账号 + 密码（自动加密）
```

### 第 3 步：试一次

```bash
python campus_login.py --connect      # 立即登录一次
python campus_login.py --status       # 看看当前联网状态
```

成功后，在控制面板里把「开机自动登录」开关打开即可。

---

## 四、配置文件说明

`config.json` 全部字段：

### auth —— 登录信息

| 字段 | 说明 |
| --- | --- |
| `login_url` | **校园网登录网址**。可以填认证服务器的完整地址，也可以只填网关地址，程序会自动跟随跳转 |
| `username` | **账号**（学号 / 上网账号） |
| `password_enc` | **密码密文**。由程序生成，不要手写。Windows 下形如 `dpapi:AQAAANCMnd8...` |
| `adapter` | 认证系统类型，见下方「认证方式适配」。默认 `auto` 自动识别 |
| `logout_url` | 断开接口地址（可选）。留空时程序会按识别出的类型尝试默认断开接口 |
| `encoding` | 页面与提交内容的编码，默认 `utf-8`。老系统可能是 `gbk` |
| `custom` | 自定义接口配置，仅当 `adapter` 为 `custom` 时使用，见下 |

### auth.custom —— 自定义接口（万能兜底）

当自动识别失败时使用。支持 `{username}` `{password}` `{ip}` 三个占位符：

```json
"custom": {
  "method": "POST",
  "url": "http://10.10.10.10:8080/eportal/InterFace.do?method=login",
  "params": {
    "userId": "{username}",
    "password": "{password}",
    "service": "",
    "queryString": "wlanuserip=xxx&wlanacname=yyy"
  },
  "headers": { "Referer": "http://10.10.10.10/a70.htm" },
  "success_keywords": ["success", "登录成功"],
  "failure_keywords": ["密码错误", "账号不存在"]
}
```

`params` 里的键名按你抓到的实际请求填即可。`success_keywords` / `failure_keywords`
用于判断结果，填了就会**优先**按它们判定。

### network —— 网络检测与重试

| 字段 | 默认 | 说明 |
| --- | --- | --- |
| `probes` | 见下 | 探测点列表，每项是 `[地址, 期望内容]`。期望内容为空表示只要求 HTTP 200/204 |
| `timeout` | 8 | 单次请求超时（秒） |
| `retry` | 3 | 登录重试次数 |
| `retry_interval` | 6 | 两次重试之间的间隔（秒） |
| `startup_wait` | 180 | 开机后最长等待网络就绪的时间（秒）—— 网卡和 DHCP 需要时间 |
| `watch_interval` | 45 | 断线自动重连的检测间隔（秒） |

默认探测点：`http://www.msftconnecttest.com/connecttest.txt`（期望 `Microsoft Connect Test`）
和 `http://connect.rom.miui.com/generate_204`。这两个在校园网里通常能正确区分
「已认证」「被劫持到认证页」「完全不通」三种状态。

> ⚠️ 探测点不要填校园网内部的地址，否则「未认证」时也能通，就检测不出真实状态了。

### autostart —— 开机自启

| 字段 | 默认 | 说明 |
| --- | --- | --- |
| `enabled` | false | 记录开关状态（由程序维护） |
| `delay` | 25 | 开机后延迟多少秒才开始登录，避开开机时的网络初始化高峰 |
| `args` | `--startup` | 自启动时使用的参数，可改成 `--silent` 走无窗口后台模式 |

### advanced —— 其他

| 字段 | 默认 | 说明 |
| --- | --- | --- |
| `verify_by_recheck` | true | 提交后重新探测一次外网来确认是否真的登录成功（**建议保持开启**，很多认证系统即使失败也返回 HTTP 200） |
| `open_login_page_on_failure` | false | 自动登录失败时是否自动打开登录页面，方便手动处理 |

---

## 五、怎么知道自己学校的登录网址

**用程序自带的探测功能**（推荐）：

```bash
python campus_login.py --probe
```

或在控制面板点「探测认证页」。它会：跟随一次跳转、打印最终认证地址、
识别认证系统类型、并**把页面里所有表单和字段名列出来**，直接告诉你该用什么适配器、该填哪些字段。

**手动抓包**（探测也搞不定时）：在浏览器里打开一次校园网登录页 → 按 `F12` →
切到 `Network` → 勾选 `Preserve log` → 正常登录一次 → 找到那条 `login` 请求，
把它的**请求地址**和**表单参数名**抄到 `auth.custom` 里即可。

---

## 六、认证方式适配

`auth.adapter` 可选值：

| 值 | 适用系统 | 说明 |
| --- | --- | --- |
| `auto` | — | **默认**。访问一次认证页，按页面特征自动判断用下面哪种 |
| `srun` | 深澜（常见于多数高校） | 走 `/srun_portal_pc?ac_id=` 接口，自动从跳转地址取 `ac_id`、上报本机 IP |
| `eportal` | 锐捷 ePortal | 走 `/eportal/InterFace.do?method=login`，自动拼 `queryString` |
| `drcom` | Dr.COM / 城市热点 | **本校就是这个**（认证服务器响应头 `Server: DrcomServer1.0`）。实现见下节 |
| `form` | 通用网页表单 | **通用兜底**：抓取登录页 HTML，自动识别账号/密码输入框（含页面上游离的 `input`，兼容 JS 提交的页面），保留 hidden 字段，然后提交 |
| `custom` | 任意 | 按 `auth.custom` 里的配置提交，最灵活 |

自动识别不准时，直接在配置里把 `adapter` 写死成对应值即可。都失败就用 `custom`。

### 本校实测（某高校 · Dr.COM 4.x）

认证服务器是 **Dr.COM（城市热点）**，与锐捷 ePortal 完全不是一回事。真机抓包后确认的完整流程：

* **登录接口**：`GET http://10.0.0.1:801/eportal/portal/login`
  * 参数：`user_account` / `user_password` / `wlan_user_ip` / `wlan_user_mac` /
    `wlan_ac_ip` / `jsVersion` / `callback`
  * 是 **GET（JSONP）**，参数走 URL —— 用 POST 提交会得到"无法获取用户认证账号"
  * 成功响应：`dr1({"result":1,"msg":"Portal协议认证成功！"})`
* **前置步骤**：先 `GET :801/eportal/portal/page/loadConfig`
  （参数含 `program_index`、`wlan_user_ip` 的 base64），拿到 `login_method` 等配置
* **登录逻辑不在页面里**：门户页 `a79.htm`（80 端口）是空壳，
  它加载 `a41.js`（流程编排）与 **`a40.js`（登录逻辑本体）**，
  登录表单则由 `pc.js` 模板动态生成 —— 所以直接抓 HTML 永远看不到表单
* 程序会自动把这些脚本抓下来存进 `logs/`，并按流程调用接口；
  如果学校升级了系统，照着 `logs\a40.js` 里的实际调法改 `_login_drcom()` 即可

> 经验：**不要靠 URL 里的关键字猜认证系统**。Dr.COM 的登录路径里也含 `eportal` 字样，
> 早期按关键字优先匹配 `eportal`，把本校门户误判成锐捷，白白排查了很久。
> 更可靠的做法是读**门户页/脚本里自己声明的配置**（`authloginpath`、`authuserfield` 等）。

---

## 七、开机自启动

### 启用 / 关闭

* 控制面板 →「开机自动登录」开关，点一下即可
* 或命令：`python campus_login.py --autostart on` / `--autostart off`

实现方式：写入当前用户的注册表启动项

```
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run   项名：CampusNetAutoLogin
```

用 `HKCU` 而不是 `HKLM`，**不需要管理员权限**，也不会影响其他用户。
开机后程序会等待网络就绪（最长 `startup_wait` 秒），再延迟 `delay` 秒开始登录，
避免开机瞬间网卡还没准备好导致误判。

### 如何查看当前自启动状态（三种方式）

1. **程序内**：控制面板「开机自动登录」开关的位置就是当前状态（开=已启用），
   下方还会直接显示注册表里记录的具体启动命令。
2. **命令行**：`python campus_login.py --autostart status`
3. **系统里**：
   * 按 `Win + R` 输入 `regedit` → 定位到
     `计算机\HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run`，
     找 `CampusNetAutoLogin` 这一项；
   * 或打开**任务管理器 → 启动**选项卡，找同名条目。

---

## 八、命令行参数

```
python campus_login.py                  # 打开图形控制面板（默认）
python campus_login.py --startup        # 开机自启模式：自动登录 + 最小化窗口 + 断线重连
python campus_login.py --silent         # 无窗口后台守护，只写日志
python campus_login.py --connect        # 立即登录一次后退出
python campus_login.py --connect --force  # 即使已在线也强制重新登录
python campus_login.py --status         # 打印当前联网状态
python campus_login.py --probe          # 探测认证页并打印表单结构
python campus_login.py --set-account 账号 密码
python campus_login.py --set-url http://10.10.10.10/
python campus_login.py --autostart on|off|status
python campus_login.py --show-config    # 查看配置路径与内容（密码自动打码）
```

登录成功返回 `0`，失败返回 `1`，网络未就绪返回 `2`。方便被其他脚本调用。

---

## 九、异常处理说明

程序对下列情况都有明确提示，并写入日志：

| 情况 | 程序行为 |
| --- | --- |
| 网络不通（链路/DNS/网关异常） | 判定为「网络不通」，**不发起登录**，直接提示具体原因（超时 / DNS 解析失败 / 网络不可达），开机模式下会继续等待 |
| 未认证被劫持到认证页 | 从 302 跳转里取出真实认证地址，并接着登录 |
| 页面元素变化、表单字段识别不出 | 提示「表单字段无法自动识别」并给出已解析到的字段名，引导改用 `custom` 模式；不会静默失败 |
| 请求超时 | 按 `retry` 次数重试，每次间隔 `retry_interval` 秒，日志逐个记录 |
| 认证失败（密码错误/账号被锁） | **立即停止，不重试** —— 避免连续错误提交导致账号被锁 |
| 提交成功但仍未认证 | 复检发现状态未变，判定为「需要重新登录」，重试若干次后如实报告 |
| 配置缺失 | 明确指出缺哪一项（网址 / 账号 / 密码），不会抛异常 |
| 配置文件损坏 | 备份为 `config.json.broken` 后自动重建默认配置 |
| 界面操作中 | 按钮自动禁用，后台线程执行，不会卡死界面；任何异常都会在状态栏和日志里显示 |

日志位置：程序目录下 `logs/campus_login.log`，控制面板里可一键查看、复制、打开文件。

---

## 十、不同系统环境的适配

| 环境 | 支持情况 |
| --- | --- |
| **Windows 10 / 11** | 完整支持。DPAPI 加密、注册表开机自启、`pythonw.exe` 无黑窗启动全部可用 |
| **Windows 7 / 8.1** | 可用，但需用 Python 3.8（3.9+ 官方已不支持 Win7）。程序本身只用标准库，无兼容性障碍 |
| **精简版 Python（无 tkinter）** | 图形界面不可用，但**命令行功能全部正常**（`--connect` / `--status` / `--probe` / `--autostart`）。程序会自动提示并提供替代命令 |
| **macOS / Linux** | 代码可运行（`python3-tk` 需另行安装）。密码加密会**自动降级**为混淆存储（非 Windows 没有 DPAPI），启动时会给出提示；开机自启需自行配置 `launchd` 或 `systemd` / `crontab @reboot` |
| **无网络环境首次运行** | 正常启动，`--status` 报告「网络不通」，不会卡死 |
| **高 DPI 屏幕（125% / 150%）** | 窗口尺寸与字体自动适配，不会出现底部按钮被裁掉的问题 |
| **certifi / 自签证书** | HTTPS 认证页使用了自签证书时也不会因证书校验失败而中断 |

**换电脑 / 换用户要注意**：DPAPI 密文与「当前 Windows 用户」绑定，
把 `config.json` 拷到别的电脑或别的用户下无法解密，需要重新设置一次密码（这是设计如此，防止配置泄露）。

---

## 十一、安全说明

* 源码中**没有任何形式的明文账号密码**，密码只以密文形式存在于 `config.json`。
* 加密使用 Windows 自带的 `CryptProtectData`（DPAPI），密钥由操作系统按当前用户账户派生，
  并叠加了应用专属的附加熵（entropy）。除本机本用户外无法解密。
* 若只是想临时跑一次而**不落盘**，可以用环境变量传密码：

  ```bash
  set CAMPUS_PWD=你的密码
  python campus_login.py --connect
  ```

  环境变量优先级高于配置文件。
* **运行日志里的口令一律打码**（形如 `user_password=***`）。日志经常要被贴出来排障，
  所以在写盘前会把 `password` / `pwd` / `upass` / `user_password` 等字段的值替换掉，
  但请求本身仍用原值发送。
* 程序不采集、不上传任何数据，除认证请求外不访问其他网络地址。

---

## 十二、锐捷 ePortal 登录流程（通用参考）

> 本节是对**锐捷 ePortal** 这类系统的通用说明，**并非本校的实际协议** ——
> 本校是 Dr.COM，见第六章「本校实测」。

ePortal 的登录有两个「坑」，网页端因为浏览器自动处理而看不出来，程序直连却会失败：

### 坑 1：必须带会话 Cookie

ePortal 要求**先访问门户页拿到服务器下发的 `JSESSIONID`**，之后带着同一个 Cookie
提交登录。裸 POST 会被判「找不到登录上下文」，返回 `Error code: 203 Bad request(2)`。
程序已改为全程复用同一个会话（`HttpSession`）。

### 坑 2：请求行里的查询串被拼错

原实现用 `urlunparse` 拼请求行，而它的第 4 个参数是 `params`、第 5 个才是 `query`。
参数位置一错，`/eportal/InterFace.do?method=login` 就被拼成了
`/eportal/InterFace.do;method=login`，服务器解析不到 `method`，同样是 203。
这个 bug 影响所有带查询串的请求，已修复并加了回归测试。

### queryString 从哪来

ePortal 登录必须带一个 `queryString` 参数（内容是 `wlanuserip=...&wlanacname=...&ac_id=1`）。
两种门户给法程序都支持：

1. 门户根地址 **302 跳转**到 `a70.htm?wlanuserip=...` → 从最终 URL 取；
2. 门户根地址直接返回页面，参数**只写在页面里**（JS 变量或表单隐藏域）→ 从页面兜底提取。

两种情况都取不到时，程序会在日志里明确预警（而不是闷头提交等一个 203）。

### 离线验证方法（不用真的断网）

```bash
python tests/test_eportal_e2e.py           # 起仿真服务器 + 跑 9 个端到端场景
python tests/mock_eportal.py --port 8888   # 也可以单独把仿真服务器跑起来
```

`tests/mock_eportal.py` 是一个**仿真锐捷 ePortal 服务器**，行为与真机一致
（包括「不带会话 Cookie 就返回 203」）。把配置里的 `auth.login_url`
指向它，就能在完全离线的环境下验证登录流程：

```bash
python campus_login.py --set-url "http://127.0.0.1:8888/"
python campus_login.py --set-account student001 Passw0rd
python campus_login.py --connect
```

验证完记得把 `login_url` 改回学校地址。

---

## 十三、在真实校园网上的验证步骤

真实门户**只在未认证状态下可达**，所以验证必须在「连着校园网但尚未认证」时做。

### 一键自测（推荐）

双击 **`测试校园网.bat`**。它自动完成八步：

> ① 检查配置 → ② 打印网络接口 → ③ 打印默认路由（判断流量走哪张网卡）
> → ④ 程序状态判定 → ⑤ 门户可达性 → ⑥ 认证页探测 → ⑦ 尝试登录 → ⑧ 给出结论

结果同时显示在屏幕，并保存为根目录的 **`测试结果.txt`**（UTF-8，含日志末尾，可直接发人分析）。

需要「强制登录一次」（跳过"已在线就跳过"的逻辑）时加参数：

```
测试校园网.bat --force
```

### 前提：让校园网那张网卡成为出口

门户地址通常只在**校园网网段内**可达。如果机器同时连着手机热点，
系统只会用 metric 更小的那条默认路由发外网流量，门户就连不上。
`测试校园网.bat` 的第 ③ 步能直接看出这种现象。

**方案 A：断开热点，只留校园网（最简单，最贴近真实场景）**

1. 点任务栏 WiFi 图标 → 断开手机热点；
2. 双击 `测试校园网.bat`；
3. 测完重新连回热点即可（若登录成功，外网会自动恢复）。

**方案 B：保留热点，单独把门户路由到校园网网卡（需要管理员权限）**

在**以管理员身份**打开的命令提示符里执行：

```bat
route add 10.0.0.1 mask 255.255.255.255 10.0.0.254 metric 1
```

> `10.0.0.1` 换成你的门户地址，`10.0.0.254` 换成有线口的网关
> （`ipconfig /all` 里看）。这条路由只影响这一个地址，外网不受影响。

然后双击 `测试校园网.bat`，测完删除：

```bat
route delete 10.0.0.1
```

### 看结果

* **成功** → 外网立刻恢复，之后把「开机自动登录」开关打开即可。
* **失败** → 把 `测试结果.txt` 发出来分析（里面已含日志末尾与服务器原始响应）。

> 单无线网卡的笔记本无法同时连校园 WiFi 和热点：方案 A 会短暂断网，
> 方案 B 全程不断网。

---

## 十四、自测

```bash
python tests/test_core.py -v            # 主自测，48 项
python tests/test_eportal_e2e.py        # 登录流程端到端，9 项
```

**`test_core.py`（48 项）** 覆盖四层：逻辑层（加解密往返、配置读写、表单解析、
适配器识别、URL 拼接与 queryString 兜底提取）、引擎层（打桩网络调用，验证
「已在线跳过 / 成功 / 失败不重试 / 重试后判定需重新登录」四种编排分支）、
界面层（构建窗口 + 灌入最长文本断言布局不被撑破）、命令行层
（`--force` 传递、`--set-url`/`--set-account` 落盘、手动连接等待上限）。

**`test_eportal_e2e.py`（9 项）** 用仿真服务器跑真实 HTTP，覆盖：复现 203 错误、
会话流程登录成功、自动识别类型、密码错误不重试、完整编排成功、已在线跳过、
缺失 queryString 的告警、注销、「参数只在页面里」的兜底提取。

# 单文件安全审计分析指令

## 1. 任务概述

安全审计——分析单个源码文件，提取风险线索为后续跨文件研判提供依据。单文件分析通常无法确认真实漏洞（漏洞依赖跨文件数据流），因此你的任务是**提取完整线索而非确认漏洞**。

## 2. 分析前预判

开始详细分析前，先判定文件属性，不同角色聚焦不同：

- **语言**：Python / Java / Go / JS/TS / PHP / Ruby / C# / C/C++ / 其他
- **文件作用**：控制器（侧重 sinks） / 服务层 / 工具库（侧重调用链） / 配置（侧重敏感信息） / 模型（侧重 SQL） / 测试（降级处理） / 前端（侧重 XSS/CORS）
- **框架特征**：有无鉴权装饰器/中间件？有无路由/端点注解？ORM 是否参数化？

## 3. 扫描方法（两阶段）

**阶段一 · 全文候选扫描（仅在心中标记，不输出）**

逐行扫读，标记所有包含以下特征的代码位置（不分析、不写、不停留）：
- 系统命令 / 进程创建调用
- 文件 I/O / 路径拼接 / 文件上传
- 网络请求 / Socket / URL 构造
- SQL / NoSQL 查询执行或拼接
- 密码 / API Key / Token / Secret 赋值或引用
- 日志 / print 输出
- 反序列化 / XML 解析 / 模板渲染
- 正则表达式字面量
- 高危三方组件 import/require
- ≥3 层嵌套的控制流 / 递归

**阶段二 · 逐项分析**

对阶段一标记的每个位置，按以下九大关注点分类、定级、写说明。每完成一条即从候选清单中划除。

**自检规则（必须遵守）：** 阶段二完成后，确认清单是否为空。仍有余项则补完，无遗漏再输出。若全文件无任何匹配，输出"文件整体评级：无"。

## 4. 外部输入定义

判定数据是否"外部可控"或"半可信"：

| 来源 | 标签 | 说明 |
|------|------|------|
| HTTP 参数/Body/Header/Cookie | **外部** | 直接可控 |
| WebSocket/RPC 消息、MQ 消息 | **外部** | 直接可控 |
| 命令行参数、stdin | **外部** | 直接可控 |
| 环境变量 | **外部** | 间接可控 |
| 上传文件内容 | **外部** | 直接可控 |
| 读取的外部文件内容 | **外部** | 间接可控 |
| 数据库查询结果字段 | **半可信*** | 需跨文件确认来源 |
| Session / JWT Payload | **半可信*** | 需跨文件确认鉴权 |
| 内部常量 / 字面量 / 无可变入参 | **不可控** | — |

*半可信在说明中标注为"外部（需跨文件确认可信性）"。

## 5. 九大关注点

### 5.1 命令执行

**触发线索：**
- Python: `os.system/popen`、`subprocess.*`、`exec/eval/compile`、`ctypes.CDLL`
- Java: `Runtime.getRuntime().exec`、`ProcessBuilder`、`ProcessImpl`
- Go: `exec.Command`、`os.StartProcess`
- JS/TS: `child_process.exec/spawn`、`eval`、`Function("")`、`new Worker`
- PHP: `system/exec/shell_exec/passthru/popen`、反引号、`eval/assert/preg_replace`(e)
- Ruby: 反引号、`system/exec/IO.popen/Open3`
- C#: `Process.Start`、`ProcessStartInfo`

**必答字段：** 行号 / 命令模板（变量用 `{var}` 标出） / 数据来源 / 是否已执行

**评级要点：**
- 外部可控 + 已执行 → **高**（有防御降一档）
- 不可控 + 已执行 → **中**
- 仅构造未执行 → **信息**
- 有效防御：`shlex.quote`、参数数组无 shell=True、白名单枚举

---

### 5.2 文件操作

**触发线索：**
- Python: `open`、`os.remove/unlink/rename`、`shutil.*`、`Path.*`、`tempfile.*`、上传 `save/write`
- Java: `java.io.File*`、`Files.*`、`Paths.get`、`MultipartFile.transferTo`
- Go: `os.Open/Create/Remove/Rename/WriteFile`、`ioutil.*`
- JS/TS: `fs.*`、`fs.promises.*`、上传 `multer/busboy`
- PHP: `fopen/file_get_contents/file_put_contents/unlink/rename/move_uploaded_file`
- Ruby: `File.*`、`IO.*`、`Pathname.*`
- C#: `File.*`、`FileStream`、`Path.Combine`

**必答字段：** 行号 / 路径（含拼接方式） / 操作类型（读/写/删/上传/移动） / 数据来源

**路径穿越判定：** 外部变量拼接路径时，检查是否有：`..` 拦截、`os.path.realpath/abspath` 解析与白名单前缀比较、`startswith` 检测。

**评级要点：**
- 外部可控 + 写/删/上传/读（已执行）→ **高**（有防御降一档）
- 半可信 + 写/删 → **高**（跨文件确认）
- 外部可控仅构造未使用 → **信息**
- 有效防御：显式 `..` 过滤 + realpath 比较 + 白名单前缀

---

### 5.3 网络操作

**触发线索：**
- Python: `requests.*`、`urllib.*`、`httpx`、`aiohttp.*`、`http.client`、`socket.*`、`websockets`
- Java: `HttpURLConnection`、`HttpClient`、`OkHttp`、`RestTemplate`、`WebClient`、`Socket`
- Go: `http.Get/Post/Do`、`net.Dial`、`tls.Dial`
- JS/TS: `fetch`、`axios.*`、`got`、`superagent`、`WebSocket`、`node-fetch`
- PHP: `curl_exec`、`file_get_contents`(URL)、`fsockopen`、`SoapClient`
- Ruby: `Net::HTTP`、`Faraday`、`HTTParty`、`RestClient`、`socket`
- C#: `HttpClient`、`WebRequest/WebClient`、`Socket`

**必答字段：** 行号 / URL（含拼接方式） / 请求方法 / 数据来源 / TLS 校验状态

**额外关注：** `verify=False`、`check_hostname=False`、警告抑制 → 不安全 TLS；URL 外部可控 → SSRF；协议外部可控 → file/gopher/dict 协议 SSRF

**评级要点：**
- 外部可控 URL + 已请求 → **高**（SSRF，有白名单降一档）
- 不安全 TLS（verify=False）→ **高**（URL 固定同样高）
- 常量 URL + 安全 TLS → **中**
- 仅拼接未请求 → **信息**

---

### 5.4 SQL 执行

**触发线索：**
- Python: `cursor.execute`、`db.execute`、`session.query`、`raw()`、`text()`
- Java: `Statement.execute`、`PreparedStatement`(检查是否拼接)、`JdbcTemplate`、MyBatis `${}`、JPA `@Query` 拼接
- Go: `db.Query/Exec`、`gorm.Raw`、`sql.DB`
- JS/TS: `query/execute/raw`、`sequelize.query`、`knex.raw`、`prisma.$queryRawUnsafe`
- PHP: `mysqli_query/query`、`PDO.*`、`whereRaw/raw`
- Ruby: `execute/query/find_by_sql`、`where(条件 #{拼接})`
- C#: `SqlCommand.Execute`、`ExecuteSqlRaw`、`Dapper` 拼接

**必答字段：** 行号 / SQL 模板 / 参数化方式（参数化/拼接） / 数据来源

**评级要点：**
- 拼接 + 外部可控 → **高**（SQL 注入）
- 拼接 + 半可信 → **高**（跨文件确认）
- 参数化查询 → **无**（安全，不列出）
- 仅定义 SQL 字符串未执行 → **信息**
- ORM 特别注意：`raw()`、`$queryRawUnsafe`、`@Query(nativeQuery=true)`、`${}` 中拼接仍是注入

---

### 5.5 敏感信息

**定义：仅限以下**——认证凭据、用户手机号、用户邮箱。其他不视为敏感信息。

**清单：**
- 密码 / API Key / Token / Secret
- 数据库连接字符串（含密码）
- 云服务凭证（AWS AK/SK、GCP Key、Azure ConnectionString）
- JWT Secret / HMAC Secret / 加密密钥 / 证书私钥
- 用户手机号 / 用户邮箱

**必答字段：** 行号 / 完整值（中间用 `***` 替换） / 来源（字面量/环境变量/外部传入）

**评级要点：**
- 生产/业务代码中硬编码字面量 → **高**
- 测试代码中的测试凭证 → **中**
- 来源为环境变量调用（`os.getenv`、`System.getenv`）→ **中**（值不在文件内）
- 仅引入配置 Key 名未赋值 → **信息**

---

### 5.6 日志操作

**触发线索：** `logger.*`、`print`、`console.log`、`fmt.Print*`、`System.out.*`、`Log.*`、`var_dump`、`puts`、`Debug.WriteLine`

**必答字段：** 行号 / 输出模板 / 是否含敏感信息（按 5.5 定义）

- 含敏感信息（密码/Token/Key/手机号/邮箱）→ 标记 **敏感日志**，评 **高**
- 普通日志 → **低**

---

### 5.7 其他明显安全问题

（不需跨文件追踪即可初步判定的安全问题）

#### a）反序列化
`pickle.loads/load`、`yaml.load`、`ObjectInputStream.readObject`、`unserialize`、`Marshal.load`、`SnakeYAML.parse`、`fastjson<1.2.83` autotype、`Jackson enableDefaultTyping`、`Json.Net TypeNameHandling`
→ 用户数据进入 → **高**；仅引入库 → **信息**

#### b）不安全算法
- MD5/SHA1（无盐，用于密码）→ **高**
- ECB 加密模式 / DES → **高**
- SSLv3 / TLSv1.0 → **高**
- 自定义加密实现 → **中**
- MD5（用于校检和/非安全场景）→ **无**（不列出）

#### c）不安全随机数
`random`/`java.util.Random`/`Math.random`/`rand`(Go标准库)/`mt_rand`/`Random`(C#) **用于 Token/密码/会话ID/CSRF Token 等安全目的**
→ **高**
→ 仅用于非安全场景（蒙特卡洛、洗牌、随机展示）→ **无**

#### d）XXE
XML 解析器未禁用外部实体（`etree.parse` / `SAXParser` / `DocumentBuilder` / `xml.Decoder` / `SimpleXML` / `XmlDocument`）
→ 用户数据进入 → **高**；仅引入 → **信息**

#### e）SSTI
模板引擎接收用户渲染数据：`render_template_string`(Jinja2)、`Velocity.evaluate`、`Freemarker` 传用户数据、`Thymeleaf` 字符串模板、`pug.compile`(用户输入)、`ejs.render`(用户输入)
→ **高**

#### f）XSS sink（前端）
`innerHTML=`、`outerHTML=`、`document.write`、`dangerouslySetInnerHTML`、`v-html`、`ReactDOMServer.renderToString`(用户输入)
→ **高**

#### g）Open Redirect
重定向 URL 来自用户控制：`redirect(url)`、`res.redirect`、`response.sendRedirect`、`header("Location: ".$url)`
→ **高**

#### h）Zip Slip
文件解压时未校验文件名是否含 `../`：`ZipFile.extract`、`tar.extract`、`unzip`、`archive/tar`
→ **高**

#### i）不安全 CORS
`Access-Control-Allow-Origin: *` **且** `Access-Control-Allow-Credentials: true`
→ **高**

#### j）ReDoS（灾难性回溯）
正则含嵌套量词重复（如 `(a+)+b`、`(\\w+([._-]\\w+)*)+`）
→ 正则字面量存在且无超时保护 → **高**

---

### 5.8 复杂逻辑

标记逻辑复杂度高的区域，供安全测试人员重点审查：

- ≥3 层 if/for/while 嵌套
- 递归函数
- 复杂权限/状态判断（角色矩阵、多条件鉴权、状态机）
- 多层回调/事件嵌套
- 需要重点关注的复杂逻辑

**评级：统一标注"中"，必须附代码片段和复杂在哪的说明。**

---

### 5.9 高危三方组件

**触发线索：** import/include/using/require 引入以下组件：
- 未鉴权中间件客户端：Elasticsearch、Kafka、RabbitMQ、MongoDB、Redis、Cassandra、Zookeeper、Consul
- 已知严重 CVE 组件：Log4j、SnakeYAML、fastjson(老)、Struts2、Spring4Shell
- 容器组件：Docker SDK、K8s API
- 服务器软件：Nginx、Tomcat、Jetty、Apache

**评级要点：**
- 文件内实际用于远程调用或用户输入可控 → **高**
- 仅引入/配置声明无外部交互 → **信息**

---

## 6. 评级规则

### 6.1 "已实际执行"判定标准

| 类别 | 判定为使用 |
|------|-----------|
| 命令 | 调用了系统命令执行 API |
| 路径 | 执行了文件 I/O 操作 |
| URL | 发起了网络请求或连接 |
| SQL | 执行了数据库查询 |
| 反序列化 | 调用了反序列化函数 |

仅拼接/赋值/定义不视为使用。

### 6.2 防御降级

文件内**可见明确防御代码**时评级**降一档**：

| 类别 | 可降级的防御 |
|------|-------------|
| 命令 | `shlex.quote`、参数数组模式、白名单枚举 |
| 文件 | `os.path.realpath` 比对、`..` 显式拦截、前缀白名单 |
| 网络 | URL/域名白名单、解析后内网检测 |
| SQL | 参数化查询、白名单（仅列名后缀等） |
| 其他 | 输入长度+字符集+escape 三重防御 |

**防御必须在代码中可见可证**，仅文字描述不降级。

### 6.3 文件整体评级

取所有关注点的最高评级。无任何匹配 → **无**。

---

## 7. 输出格式

### 通用规则

- 每个关注点下按发现顺序逐条列出，未发现则不展示
- **禁止用"等"、"…"、"..."省略**——全部列出
- 中及以上条目必须附代码片段和行号
- 多行代码标注起止行号（如 `85-90`）
- 代码片段用 `` ` `` 单行或 ``` 代码块

### 字段要求

| 评级 | 必填字段 |
|------|---------|
| **高/中** | 行号 / 代码片段 / 数据来源 / 文件内防御（如有） / 跨文件待确认 |
| **低** | 行号 / 一行简述 |
| **信息** | 行号 / 一行简述 |

### 固定模板（高/中级条目）

```
**N. 简要标题 · 行号 M**
**风险评级：** 高/中
**代码片段：**
```lang
code
```
**数据来源：** 描述变量来源链
**文件内防御：** 有→列出具体代码 / 无
**跨文件待确认：** 具体需要确认什么
```
低/信息级省略后两个字段。

---

## 8. 迷你示例

### 示例一：高（命令注入，外部输入直入 sink）

```
**1. 命令注入 · 行号 85-90**
**风险评级：** 高
**代码片段：**
```python
cmd = f"ffmpeg -i {video_path} -vcodec libx265 output.mp4"
os.system(cmd)
```
**数据来源：** `video_path` ← `request.files['video'].filename`（外部直连）
**文件内防御：** 无
**跨文件待确认：** 上游是否有文件名重命名逻辑；调用方鉴权
```

### 示例二：中（文件写入，有部分防御）

```
**1. 文件写入 · 行号 150-156**
**风险评级：** 中
**代码片段：** `filename = request.json['filename']`；检测 `..` 和 `/` 后 `open(os.path.join(BASE_DIR, filename), "w")`
**数据来源：** `filename` ← `request.json['filename']`（外部）
**文件内防御：** 拦截 `..` 和 `/`，但仅两种字符，不全面
**跨文件待确认：** `BASE_DIR` 目录权限；调用方鉴权
```

### 示例三：信息（命令仅定义未执行）

```
**1. 命令定义 · 行号 42**
**风险评级：** 信息
**代码片段：** `cmd = "df -h"`
**说明：** 仅赋常量子符串，文件中无实际执行调用。
```

---

## 9. 完成自检

输出末尾必须包含以下自检句，精确填写数字：

> 本次共发现 **N** 项关注点（高 X 项 / 中 X 项 / 低 X 项 / 信息 X 项），全部完整列出无省略。文件整体评级：**高/中/低/信息/无**。

若全文件无任何匹配 → **文件整体评级：无 — 该文件无匹配关注点的代码。**

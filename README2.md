# Reader Explorer：用 OkHttp 观察图片请求链路

Java 17+、Maven、OkHttp。实现对应用户提供的阅读器 8.0.422 抓包，不保证适用于网站后续版本。

提供两个入口：

- `verify-har`：完全离线，用 HAR 中的上游响应重新计算 once/get 和 lmg 的 k，并比较原始 URL 参数。
- `fetch`：使用当前浏览器会话，逐步执行某一页的正常请求链，保存预览、高清分片和不含凭据的过程记录。

## 快速使用

命令均在本项目目录运行。发行包内的 `reader-explorer.jar` 已包含运行依赖，只需要 Java 17 或更高版本。

### 先验证已有抓包，不需要 Cookie 配置，也不会联网

```bash
java -jar reader-explorer.jar verify-har \
  --har /Users/fuchunming/Downloads/1111.har \
  --out runs/har-check
```

查看 `runs/har-check/verification.json`。每条成功记录会标注对应的 read/k、imgs、once/get 索引，以及是否精确重算一致。

失败业务请求单独进入 `observations`。用户在 Charles 中修改的第 120 页请求会记录外层页码和加密页码，不用于推断正常流程或错误码语义。缺少响应体、Cookie 或上游请求会进入 `incomplete`，不会假称验证通过。

输出目录必须为空；再次运行请换目录名。

### 配置当前浏览器会话

复制 `session.example.json` 为 `session.json`，填入当前阅读器请求的值：

```json
{
  "cookie": "gidf=当前值; PHPSESSID=当前值; 其他Cookie=当前值",
  "userAgent": "浏览器请求的 User-Agent 原值",
  "requestId": "0",
  "accessToken": "",
  "frameUrl": ""
}
```

- `cookie`：浏览器当前同一会话的完整 Cookie 请求头，必须包含 `gidf`。不要凭空生成指纹或把其他会话的指纹混进来。
- `requestId`：从浏览器预览图片请求的 `RequestID` 头取得。用户这份访客抓包为 `0`；其他登录状态不应默认照抄。
- `accessToken`：只有原阅读入口确实携带该参数时填写。
- `frameUrl`：普通顶层阅读页面为空。只有已确认该阅读器的 iframe 分支使用当前文档 URL 时才填写。

项目未内置用户 HAR、Cookie 或真实阅读凭据。session.json 也不会被自动生成或保存到日志。

### 逐步探索第 100 页

先走到预览阶段：

```bash
java -jar reader-explorer.jar fetch \
  --book 3258702 --page 100 \
  --session session.json \
  --stop-after preview \
  --out runs/page-100-preview
```

完整执行单页流程并保存高清分片：

```bash
java -jar reader-explorer.jar fetch \
  --book 3258702 --page 100 \
  --session session.json \
  --out runs/page-100-full
```

这两次执行各自从初始化开始，不共享中途的临时凭据。若需要从已有阶段继续或查看完整内存对象，建议在 IDE 中调试同一次执行。

目前抓包显示 canread=0、canreadpages=30，因此不能保证该会话能读取第 100 页。客户端使用服务端正常接口；业务失败时显示发生步骤和 code，并停止后续请求。它不会把错误解释为某种确定的权限原因，也不会自动反复申请凭据。

多册书可增加 `--volume 1`。

### 停止阶段

| 参数 | 执行到哪里 |
|---|---|
| `--stop-after base` | initread + read/k |
| `--stop-after preview` | 再请求 imgs，解析预览与分片元数据 |
| `--stop-after credentials` | 再为各分片申请临时凭据、生成最终 k；不请求高清图 |
| `--stop-after images` | 请求并保存高清分片，默认值 |

## 输出

在线成功后得到：

```text
preview.webp                 预览，扩展名按真实图像头决定
fragment-000.webp            分片编号 0
fragment-001.webp            分片编号 1
...
manifest.json                页码、分片文件、原始分片顺序、尺寸/旋转信息、完成状态
trace.json                   每个步骤的 HTTP 状态、数据大小、分片编号和结果
```

真实图像也可能是 PNG/JPEG，文件扩展名会相应变化。请求中途失败仍保存 manifest 和 trace，`completed=false`。

本工具的输出单位是高清分片，不自动拼成整页。`manifest.geometry` 保留服务器参数：通常依次为普通分片宽、末片宽、显示高度、旋转角度、原始宽和原始高，具体使用方式见捕获脚本的 getJK。不能按请求完成顺序简单左右排列；还需考虑分片编号、旋转和缩放。

日志不会写完整 k、Cookie、指纹或临时凭据；请求载荷可在 IDE 的局部变量中查看。

## 源码阅读顺序

| 文件 | 作用 |
|---|---|
| `src/main/java/lab/reader/Main.java` | 命令行入口 |
| `src/main/java/lab/reader/ReaderClient.java` | OkHttp 在线调用顺序、会话与错误处理 |
| `src/main/java/lab/reader/ReaderProtocol.java` | ChaCha20、AES、MD5、预览二进制解析、URL 编码 |
| `src/main/java/lab/reader/HarVerifier.java` | 对照上游响应重建捕获的请求参数，不联网 |
| `src/main/java/lab/reader/BrowserSession.java` | Cookie 载入与 Set-Cookie 更新 |

在 IDE 中导入 pom.xml，Main Class 为 `lab.reader.Main`。建议给以下位置设置断点：

1. `ReaderProtocol.oncePayload`：看 p 是字符串，zn 是数字。
2. `ReaderProtocol.decryptTemporary`：看服务端临时凭据解密结果，zn 已变成编码字符串。
3. `ReaderProtocol.finishTemporary`：看小图 salt、字段排序及 xx。
4. `ReaderProtocol.finalPayload`：看嵌套 JSON 字符串。
5. `ReaderProtocol.onceUrl` / `imageUrl`：看两层和一层 URL 编码的区别。

核心调用顺序：

```text
GET initread
 → GET read/k
 → GET imgs/{bid}/{page}
 → 解析尾部并解密分片信息
 → 每个分片 GET once/get
 → AES 解密 → 补 w → MD5 xx → 最终 k
 → 每个分片 GET lmg/{bid}/{page}
```

ChaCha20 使用 Java 标准库，不需要运行原站点脚本或 WASM。最终载荷的时间戳按整秒毫秒值生成，保留 JSON 字段插入顺序，页码保持字符串。once/get 使用两层 URL 编码，lmg 使用一层。

## 构建与测试

```bash
mvn clean verify
java -jar target/reader-explorer.jar --help
```

测试包含独立 Node 生成的合成向量和合成 HAR；没有用户真实凭据。通过本机 HTTP 服务测试 OkHttp 发出的实际查询串、Cookie、业务错误停止、重定向停止与预览阶段停止。

实际网站的在线请求没有在交付过程中运行；真实抓包验证是离线执行。当前工具覆盖这次 HAR 中的网页图片链路，机构单点登录、客户端 SDK、新版阅读器、额外握手或验证码流程可能需要另行适配。服务端策略变化时应先用新 HAR 离线对照。

默认不自动重试网络错误、不跟随重定向。每个请求有超时与 64 MiB 响应上限，保留正常 TLS 校验。一次执行只处理一个页码；服务端失败就停止，不自动刷新令牌或批量遍历页码。

## 依赖依据

- OkHttp JVM/Maven 坐标参考 [OkHttp 官方 README](https://github.com/square/okhttp/blob/master/README.md)，本项目固定 `okhttp-jvm:5.3.0`。
- JSON 使用 `jackson-databind:2.22.4`，版本依据 [官方发布说明](https://github.com/FasterXML/jackson/wiki/Jackson-Release-2.22.4)。

这些外部依赖与项目自身逻辑分开；协议行为依据用户提供的 HAR 和其中的阅读器代码。

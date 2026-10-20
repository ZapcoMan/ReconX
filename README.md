# Recon Lens — 授权范围信息收集（Chrome 扩展）

面向**已授权目标**的浏览器侦察助手，把 `recon`（侦察/信息收集）与 `web-architectural`（指纹识别）两条技能落到一个可直接加载的 Chrome（Manifest V3）扩展里。适用场景：渗透测试、漏洞赏金（在计划 scope 内）、对自己站点的自查、以及针对公开资源的 OSINT 研究。

> ⚠️ 合规：本工具内置「允许域白名单 + 逐目标授权」护栏。请勿用于未授权目标——越权扫描/探测可能违法。所有命中均为**线索**，须人工复核。

## 为什么不是全部 5 个技能都能进插件

你点名的 5 个技能里，只有 **recon** 与 **web-architectural 的指纹部分**能在浏览器扩展沙箱内落地。**binary-exploitation（内存破坏/ROP/堆利用）、wireless（802.11 监听/破解）、crypto（离线数学破解/padding oracle）** 属于本地进程 / 内核 / 无线硬件层能力，扩展无法也不应实现，因此本插件不包含它们，避免做成不可用的伪攻击面板。

## 功能

| 模块 | 能力 | 来源规则 |
|---|---|---|
| 技术栈 / WAF / 版本指纹 | 从 Server、X-Powered-By、meta generator、Cookie 名、资源 URL、`window` 全局变量、HTML 特征识别框架/CMS/CDN/WAF 及版本线索 | `lib/fingerprints.js` |
| 响应头与 Cookie 分析 | 安全头缺失/弱配置、CSP 指令评估、CORS、`Set-Cookie` 属性（HttpOnly/Secure/SameSite）、缓存与凭据风险 | `lib/header-checks.js` |
| JS 敏感信息扫描 | 抓取外链/内联 JS，正则检测云密钥、各类 Token、私钥、JWT、内网/元数据地址、source map、Git 痕迹（命中默认掩码） | `lib/sensitive-rules.js` |
| 链接 / 端点 / 参数收集 | DOM 链接、表单与隐藏字段、iframe、资源清单、运行时资源、内联脚本里的 `/api` 端点，按主机与参数归一去重 | `content-dom.js` |
| 主动探测（默认关闭） | 对 `.git/.env/.svn/actuator/swagger/security.txt` 等敏感路径做范围 GET 探测（串行限流） | `lib/sensitive-rules.js` |
| 范围管控 / 导出 | 允许域白名单、逐目标 host 权限授权、结果窗口、JSON/CSV/Markdown 导出 | `background.js` |

## 安装（开发者模式加载）

1. 打开 `chrome://extensions`，右上角开启「开发者模式」。
2. 点「加载已解压的扩展程序」，选择本目录 `recon-chrome-extension/`。
3. 需要 **Chrome 111+**（`world: MAIN` 注入用于读取 `window` 全局变量；旧版本会优雅降级、跳过该项）。

## 使用流程

1. 打开你**已获得授权**的目标站点。
2. 点击工具栏图标 → 「加入范围并授权」：扩展会向浏览器申请该站点的主机权限（这是用户手势触发的授权弹窗）。
3. 「开始收集」：注入采集 DOM、抓取并扫描 JS、分析已捕获的响应头、汇总技术栈/WAF，结果写入本地存储。
4. 「打开详情」查看全部分栏结果；弹窗或详情页可导出 JSON / CSV / Markdown。
5. 如需主动探测：先到「设置与合规 → 启用主动路径探测」，再在弹窗点「主动探测」（每次都要显式点击）。

## 权限模型（最小化）

- 安装期权限：`tabs`、`scripting`、`storage`、`downloads`、`webRequest`。
- **不在安装期请求任何 `host_permissions`**；改为 `optional_host_permissions: <all_urls>`，仅在你把某个域名加入白名单并点击授权时，按 `scheme://host/*` 逐站点申请。
- 因此默认安装警告面很小；只有你主动授权过的站点，扩展才能读取其响应头 / 抓取 JS / 注入采集。

## 隐私与数据

- 所有结果只存在本机 `chrome.storage.local`，不向任何第三方服务器上传。
- 采集的密钥/令牌在报告中默认**掩码**（仅保留首尾若干字符）。
- JS 抓取仅对**同源或已在白名单内**的主机发起，且限制文件数、并发与单文件体积，避免对目标造成压力或越界。

## 已知限制

- Cookie 分析依赖 `webRequest` 在页面加载时捕获的 `Set-Cookie`：若扩展在页面加载后才授权，需**刷新目标页面**再采集才能拿到 Cookie 头（否则走 fetch 兜底，但 JS 无法读取 `Set-Cookie`）。
- 受页面 CSP 限制时，`window` 全局变量的「版本」可能读不到，但「是否存在」仍可用。
- 指纹命中是基于已知特征的启发式判断，存在误报/漏报，务必人工确认。

## 目录结构

```
manifest.json            MV3 清单与权限
background.js            收集/权限/抓取/导出中枢（service worker）
content-dom.js           注入采集（DOM/链接/表单/资源）
lib/fingerprints.js      技术栈/WAF/版本规则
lib/sensitive-rules.js   密钥/Token/泄露 正则 + 主动探测路径
lib/header-checks.js     安全头/Cookie/CSP/CORS 分析
popup/  弹窗            授权 + 触发收集/探测/导出
result/ 详情窗口         分栏展示 + 原始 JSON
options/ 设置            白名单 / 规则开关 / 权限撤销 / 合规声明
icons/  gen-icons.js     内置无依赖 PNG 图标生成脚本
```

## 重新生成图标

```bash
node gen-icons.js
```

仅使用 Node 内置模块（`fs`/`path`/`zlib`），无第三方依赖。

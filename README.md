# ReconX — 授权范围信息收集（Chrome 扩展）

> 仅用于**已授权目标**的浏览器侦察助手（渗透测试 / 漏洞赏金 / OSINT / 自有站点自查）。
> 功能来源、技能映射、能力边界与移植进度见 [docs/技能来源与能力映射.md](docs/技能来源与能力映射.md)。

## 功能

| 模块 | 能力 |
|---|---|
| 技术栈 / WAF / 版本指纹 | 从 Server、X-Powered-By、meta generator、Cookie、资源 URL、`window` 全局、HTML 特征识别框架/CMS/CDN/WAF 与版本线索 |
| 响应头与 Cookie 分析 | 安全头缺失/弱配置、CSP 指令、CORS、`Set-Cookie` 属性（HttpOnly/Secure/SameSite）、缓存与凭据风险 |
| JS 敏感信息扫描 | 外链/内联 JS 中的云密钥、Token、私钥、JWT、内网/元数据地址、source map、Git 痕迹（命中默认掩码） |
| 链接 / 端点 / 参数收集 | DOM 链接、表单与隐藏字段、iframe、运行时资源、内联 `/api` 端点，按主机/参数归一去重 |
| URL 规范化与敏感分级 | 跳转还原、去跟踪参数、域名/通配/正则黑名单；端点按 critical/warn/info 三级排序 |
| 资产测绘 / Dork 查询生成 | 生成 Fofa/Quake/Hunter/ZoomEye 与搜索引擎查询语句（**仅生成查询，不自动开标签**） |
| 主动探测（默认关闭） | 对 `.git/.env/.svn/actuator/swagger/security.txt` 等做范围 GET 探测（串行限流，需显式开启） |
| 范围管控 / 导出 | 允许域白名单 + 逐目标 host 授权；多格式导出（见下） |

## 安装（开发者模式加载）

1. 打开 `chrome://extensions`，右上角开启「开发者模式」。
2. 点「加载已解压的扩展程序」，选择本目录 **`ReconX/`**。
3. 需要 **Chrome 111+**（`world: MAIN` 注入读取 `window` 全局；旧版本会优雅降级、跳过该项）。

## 快速开始

1. 打开你**已获得授权**的目标站点。
2. 点击工具栏图标 → 「加入范围并授权」（浏览器弹出主机权限授权，由你的点击手势触发）。
3. 「开始收集」：注入采集 DOM、抓取并扫描 JS、分析已捕获响应头、汇总技术栈/WAF。
4. 「打开详情」查看全部分栏；在弹窗或详情页选择导出格式。
5. 如需主动探测：先到「设置 → 启用主动路径探测」，再在弹窗点「主动探测」（每次显式点击）。

## 导出

统一导出在扩展页面内用 `<a download>` 触发（不依赖 `chrome.downloads`）。格式：

- **JSON**：完整结构化结果
- **CSV**：发现项 / 技术栈 / WAF / 端点 / 路由 多维
- **Markdown**：人类可读报告
- **HTML**：自包含样式报告，可直接打开/打印转 PDF
- **SRC 报告**：面向漏洞赏金提交的草稿骨架（等级/位置/证据/复现/影响/建议）
- **端点 TXT**：URL 列表，可直接粘贴 Burp

支持**按等级筛选**、**多目标聚合导出**、**规则/Dork 库 JSON 导入导出**。

## 权限模型（最小化）

- 安装期权限：`tabs`、`scripting`、`storage`、`webRequest`（**不含 `downloads`**，导出走页面 `<a download>`）。
- 安装期**不请求任何 `host_permissions`**；改用 `optional_host_permissions: <all_urls>`，仅在你把域名加入白名单并点击授权时，按 `scheme://host/*` 逐站点申请。
- 因此默认安装警告面很小；只有你主动授权过的站点，扩展才能读取响应头 / 抓取 JS / 注入采集。

## 隐私与数据

- 结果只存本机 `chrome.storage.local`，不外传。
- 密钥/令牌在报告中默认**掩码**。
- JS 抓取仅对**同源或已在白名单内**的主机发起，并限制文件数、并发与单文件体积。

## 已知限制

- Cookie 分析依赖 `webRequest` 在页面加载时捕获的 `Set-Cookie`：若授权发生在加载之后，需**刷新目标页面**再采集（fetch 兜底读不到 `Set-Cookie`）。
- 受页面 CSP 限制时，`window` 全局变量可能读不到版本，但“是否存在”仍可用。
- 指纹命中为启发式线索，存在误报/漏报，须人工确认。

## 目录结构

```
manifest.json            MV3 清单与权限
background.js            收集/权限中枢（service worker）
content-dom.js           注入采集（DOM/链接/表单/资源）
lib/fingerprints.js      技术栈/WAF/版本规则
lib/sensitive-rules.js   密钥/Token/泄露 正则 + 主动探测路径
lib/header-checks.js     安全头/Cookie/CSP/CORS 分析
lib/exporter.js          统一导出中枢（JSON/CSV/MD/HTML/SRC/TXT + 筛选/聚合/导入导出）
lib/url-classify.js      URL 规范化 + 敏感三级分类
lib/asset-search.js      资产测绘查询生成（仅生成查询）
popup/  弹窗            授权 + 触发收集/探测/导出
result/ 详情窗口         分栏展示 + 筛选导出 + 原始 JSON
options/ 设置            白名单 / 规则开关 / 权限撤销 / 合规声明
docs/                    技能来源与能力映射（深度文档）
icons/  gen-icons.js     内置无依赖 PNG 图标生成脚本
```

## 重新生成图标

```bash
node gen-icons.js
```

仅使用 Node 内置模块（`fs`/`path`/`zlib`），无第三方依赖。

## 致敬与来源

ReconX 整合、参考了以下开源项目，谨向其作者致谢，并遵循各自原有许可证：

- [**crazy_edusrc**](https://github.com/dollmarker/crazy_edusrc) — EduSRC 猎洞工具的**原版**（dollmarker）。
- [**CrazyEdusrcX**](https://github.com/ZapcoMan/CrazyEdusrcX) — 在 crazy_edusrc 基础上的**二次开发**（ZapcoMan）：贡献 Dork 语法库、资产测绘四档联动、敏感 URL 三级分类、URL 规范化等。
- [**King-Crack**](https://github.com/chaojiwudichoubie1-arch/King-Crack) — 前端框架/路由/API 侦察工具的**纯正原版**（纯 JS）。
- [**King-CrackX**](https://github.com/ZapcoMan/King-CrackX) — 在 King-Crack 基础上将纯 JS **重构为 Vue3 + TypeScript** 的二次开发（ZapcoMan）：贡献框架/路由枚举、API 端点提取、前端安全审计、导出实现与“梭哈模式”。

> 各能力在 ReconX 中的映射与移植进度见 [docs/技能来源与能力映射.md](docs/技能来源与能力映射.md)。

## 许可证

本项目以 **GNU GPL v2** 发布，全文见 [LICENSE](LICENSE)。整合的上游组件遵循各自原有许可证（如 crazy_edusrc / CrazyEdusrcX 为 MIT，King-Crack / King-CrackX 为 GPL 系列）。

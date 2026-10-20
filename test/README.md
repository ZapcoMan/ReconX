# 验证说明

ReconX 是无构建的纯 JavaScript MV3 扩展，未引入测试框架或第三方依赖。验证分两层：

## 1. 静态校验（已执行）

- 所有扩展 JS 通过 `node --check`（Node v24）。
- `manifest.json` 通过 `JSON.parse` 解析。
- `background.js` 的 `importScripts` 所列 11 个库文件均存在。
- `result.html` 引用的脚本（exporter / url-classify / asset-search / dork-library / result / result-extra / result-king）均存在。

## 2. 纯逻辑就地验证（已执行，Node）

各逻辑库把对象挂到 `self`（浏览器/扩展上下文里即 `globalThis`）。在 Node 下用 `globalThis.self=globalThis` 后 `require` 这些库、从 `globalThis.X` 取实例即可调用其纯函数。示例：

```bash
node -e 'globalThis.self=globalThis;require("./lib/fingerprints.js");const F=globalThis.Fingerprints;console.log(F.identifyFromUrl("https://cdn/x/vue@3.4.21/dist/vue.global.prod.js").name);'
```

实测断言（节选，均通过）：

| 模块 | 输入 | 结果 |
|---|---|---|
| Fingerprints.identifyFromUrl | vue@3.4.21 资源 URL | `Vue` |
| UrlClassify.classify | `https://x/.git/config` | `critical` |
| UrlClassify.normalize | Google `/url?q=https://a.com/b&ved=0` | `https://a.com/b`（还原+去跟踪） |
| SensitiveRules.scanText | 含 `AKIA…` 的 JS | 命中 `aws-akid`，样本已掩码 |
| HeaderChecks.analyze | 缺 CSP/HSTS、`Set-Cookie` 无 HttpOnly、`ACAO:*` | missing≥2、cors 告警、cookie 标记齐全 |
| RouteUrls.buildRouteUrlList | Vue hash 路由 `/home`、`user` | 2 条完整 URL 均含 `#` |
| ApiExtract | `"/api/user/list"`/`"/v1/order/create"`/`"sys/User/login"` | 静态端点≥2、已调用标记、fullUrl 正确 |
| SecurityAudit | live `/api/admin/del` + 未保护 `/pay` 路由 | critical≥1、未授权线索≥1、建议≥1 |
| TechStack.detect | Vue+Vue Router+nginx 信号 | 条目≥2、`enableRouteProbe=true` |
| TechStack.detect（非 SPA） | 仅 IIS | `enableRouteProbe=false` |
| Exporter | 样例 bundle | JSON/CSV/MD/HTML/SRC/TXT 均生成、collectFindings/filter 正常 |

## 3. 需 Chrome 实测（本环境无法执行）

以下依赖真实浏览器 API / DOM / 目标站点，请在 `chrome://extensions` 加载扩展后实测：

- `content-dom.js` 的 DOM 采集、`router-probe.js` 读取框架内部对象（需 `world: MAIN`，Chrome 111+）。
- `chrome.scripting.executeScript` 注入、`chrome.webRequest` 捕获响应头/`Set-Cookie`、`chrome.permissions.request` 授权弹窗。
- popup / result / options 的 DOM 渲染与标签互斥（含 `.raw` 隐藏）。

> 说明：本测试以 `node -e` 内联方式执行，未将测试脚本纳入扩展加载路径（避免 `require`/全局模拟被当作非标准操作）。

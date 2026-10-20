# ReconX

<div align="center">

![Manifest V3](https://img.shields.io/badge/Manifest%20V3-Extension-2dd4bf)
![Vue 3](https://img.shields.io/badge/Vue-3.x-42b883)
![TypeScript](https://img.shields.io/badge/TypeScript-5.x-3178c6)
![Element Plus](https://img.shields.io/badge/UI-Element--Plus-409eff)
![Vite](https://img.shields.io/badge/Build-Vite%20%2B%20crxjs-646cff)
![License](https://img.shields.io/badge/License-GPL--v2-yellow)

**面向已授权目标的浏览器侦察 / 信息收集扩展**

[快速开始](#-快速开始) • [核心特性](#-核心特性) • [使用流程](#-使用流程) • [文档](#-文档) • [合规](#️-合规与能力边界)

</div>

---

## 📋 项目简介

ReconX 是一个 Chrome（Manifest V3）扩展，把 **recon（侦察/信息收集）** 与前端技术栈 / 路由 / API 分析能力整合为统一采集与统一导出，面向**渗透测试 / 漏洞赏金 / OSINT / 自有站点自查**。内置「允许域白名单 + 逐目标 host 授权」范围护栏，所有采集与探测只在已授权主机上发生。

基于 **Vue 3 + TypeScript + Vite + @crxjs/vite-plugin + Element Plus + Pinia** 构建，`npm run build` 后在 `chrome://extensions` 加载已解压的 `dist/` 目录。

> 本 README 仅作门面速览。各模块能力矩阵、真实运行架构、构建与验证方法、来源与能力边界，详见 [`docs/`](docs/) 目录。

### ✨ 核心特性

- 🔍 **Wappalyzer 式技术栈合并**：交叉 HTTP 头 / Cookie / meta / 资源 URL / HTML / `window` 全局 / 路由结构，输出带**置信度**的技术栈与 Vue/React SPA 判定
- 🧱 **技术栈 / WAF / 版本指纹**：框架、CMS、CDN、边缘防护与版本线索识别
- 📮 **响应头与 Cookie 分析**：安全头缺失、CSP/CORS、`Set-Cookie`（HttpOnly/Secure/SameSite）风险
- 🔑 **JS 敏感信息扫描**：云密钥 / Token / 私钥 / JWT / 内网元数据 / Sourcemap（命中默认**掩码**）
- 🧭 **前端路由枚举 + API 端点提取**：识别 Vue/React 路由、生成完整 URL、抽取实际/静态/Sourcemap 端点
- 🛡️ **前端安全审计**：敏感 API、未保护路由线索、Sourcemap 泄露 → 风险评级与建议
- ⚡ **主动探测（默认关闭）**：敏感路径可达性核验，以及对判定为 Vue/React 站点的前端路由接管（梭哈模式，见合规说明）
- 🛰️ **资产测绘 / Dork 查询生成**：Fofa/Quake/Hunter/ZoomEye 与搜索引擎查询（**仅生成查询，不自动开标签**）
- 🎨 **主题**：暗色 / 亮色 / 极客三套，可切换并持久化，联动 Element Plus 配色
- 📦 **多格式统一导出** + **范围管控**

---

## 🚀 快速开始

```bash
npm install          # 安装依赖
npm run build        # vue-tsc 类型检查 + vite build → 产出 dist/
npm run dev          # 开发热更新（@crxjs HMR）
```

1. 打开 `chrome://extensions`，开启右上角「开发者模式」。
2. 点「加载已解压的扩展程序」，选择构建产物目录 **`dist/`**。
3. 需要 Chrome 111+（旧版本对 `window` 全局读取与 MAIN world 注入会优雅降级）。

### 🪜 使用流程

1. 打开你**已获得授权**的目标站点。
2. 点击图标 → 「授权并加入范围」（逐站点 host 权限，由你的点击手势触发）。
3. 「开始采集」：采集 DOM / JS / 响应头，只读枚举前端路由、提取 API、做技术栈合并判定与前端安全审计，统一并入结果。
4. 「查看结果」分栏浏览；在弹窗或详情页选择导出格式。
5. 「主动探测」（默认关闭，需先采集）：对范围内站点执行敏感路径探测；判定为 Vue/React 时追加路由可达性探测与前端路由接管。

---

## 📦 导出

在扩展页面内用 `<a download>` 触发（不依赖 `chrome.downloads`）：

**JSON** 完整结构化结果 ｜ **CSV** 多维 ｜ **Markdown** 报告 ｜ **HTML** 自包含可打印 ｜ **SRC 报告** 赏金提交草稿 ｜ **端点 TXT** 可贴 Burp

支持**按等级筛选**、**多目标聚合**、**规则 / Dork 库 JSON 导入导出**。

---

## 📚 文档

| 文档 | 内容 |
|------|------|
| [docs/功能与模块说明.md](docs/功能与模块说明.md) | 能力矩阵、真实运行架构（background / content / 注入脚本 / core 库）、导出、目录结构 |
| [docs/已知限制与运行验证.md](docs/已知限制与运行验证.md) | 已知限制、构建与验证方法、需 Chrome 实测清单 |
| [docs/技能来源与能力映射.md](docs/技能来源与能力映射.md) | 来源技能映射、复用插件、能力边界与移植进度 |

---

## ⚠️ 合规与能力边界

- 仅用于**已授权**目标；命中皆为**线索**，须人工确认；密钥/令牌默认掩码，数据仅存本机。
- **主动探测为显式动作**，默认关闭，且只对「已加入允许域并授权」的主机执行。
- **梭哈模式（前端路由接管）**：对判定为 Vue/React 的站点，`all-in` 脚本会在页面主世界**屏蔽前端路由守卫、改写鉴权 meta、拦截 `router.push/replace`、`navigate`、`history/location` 跳转**，使受保护的前端路由可直接访问。这是**客户端层面**的路由接管，**不绕过服务端鉴权**——受保护接口仍由服务器返回 401/403，须自行在授权范围内核验。
- 内存利用 / 无线 / 密码学破解类不在浏览器扩展职责内（详见技能来源文档）。

---

## 🙏 致敬与来源

ReconX 整合、参考了以下开源项目，谨向其作者致谢，并遵循各自原有许可证：

- [**crazy_edusrc**](https://github.com/dollmarker/crazy_edusrc) — EduSRC 猎洞工具原版（dollmarker）
- [**CrazyEdusrcX**](https://github.com/ZapcoMan/CrazyEdusrcX) — 二次开发：Dork 库、资产测绘、敏感分级、URL 规范化
- [**King-Crack**](https://github.com/chaojiwudichoubie1-arch/King-Crack) — 前端框架/路由/API 侦察原版（纯 JS）
- [**King-CrackX**](https://github.com/ZapcoMan/King-CrackX) — 二次开发（Vue3 + TS）：框架/路由枚举、API 提取、安全审计、导出实现

来源与映射细节见 [docs/技能来源与能力映射.md](docs/技能来源与能力映射.md)。

---

## 📄 许可证

本项目以 **GNU GPL v2** 发布，全文见 [LICENSE](LICENSE)。整合的上游组件遵循各自原有许可证（crazy_edusrc / CrazyEdusrcX 为 MIT，King-Crack / King-CrackX 为 GPL 系列）。

---

*最后更新时间：2026-10-21 ｜ 版本：0.2.0*

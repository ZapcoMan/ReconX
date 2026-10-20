# ReconX

<div align="center">

![Manifest V3](https://img.shields.io/badge/Manifest%20V3-Extension-2dd4bf)
![Vue 3](https://img.shields.io/badge/Vue-3.x-42b883)
![TypeScript](https://img.shields.io/badge/TypeScript-5.x-3178c6)
![Element Plus](https://img.shields.io/badge/UI-Element--Plus-409eff)
![Vite](https://img.shields.io/badge/Build-Vite%20%2B%20crxjs-646cff)
![License](https://img.shields.io/badge/License-GPL--v2-yellow)

**面向已授权目标的浏览器侦察 / 信息收集扩展**

[快速开始](#-快速开始) • [核心特性](#-核心特性) • [导出](#-导出) • [文档](#-文档) • [合规](#️-合规与能力边界) • [致敬](#-致敬与来源)

</div>

---

## 📋 项目简介

ReconX 是一个 Chrome（Manifest V3）扩展，把 **recon（侦察/信息收集）** 与前端技术栈/路由/API 分析能力整合为统一采集与统一导出，面向**渗透测试 / 漏洞赏金 / OSINT / 自有站点自查**。内置「允许域白名单 + 逐目标 host 授权」范围护栏。基于 **Vue 3 + TypeScript + Vite + @crxjs/vite-plugin + Element Plus** 构建，`npm run build` 后加载已解压的 `dist/` 目录。

### ✨ 核心特性

- 🔍 **Wappalyzer 式技术栈合并**：交叉 HTTP 头/Cookie/meta/资源 URL/HTML/`window` 全局/路由结构，输出带**置信度**的技术栈与 Vue/React SPA 判定
- 🧱 **技术栈 / WAF / 版本指纹**：框架、CMS、CDN、边缘防护与版本线索识别
- 📮 **响应头与 Cookie 分析**：安全头缺失、CSP/CORS、`Set-Cookie`（HttpOnly/Secure/SameSite）风险
- 🔑 **JS 敏感信息扫描**：云密钥/Token/私钥/JWT/内网元数据/Sourcemap（命中默认**掩码**）
- 🧭 **前端路由枚举 + API 端点提取**：只读识别 Vue/React 路由、生成完整 URL、抽取实际/静态/Sourcemap 端点
- 🛡️ **前端安全审计**：敏感 API、未保护路由线索、Sourcemap 泄露 → 风险评级与建议
- 🛰️ **资产测绘 / Dork 查询生成**：Fofa/Quake/Hunter/ZoomEye 与搜索引擎查询（**仅生成查询，不自动开标签**）
- 🎨 **主题**：暗色 / 亮色 / 极客三套，可切换并持久化，联动 Element Plus 配色（弹窗与设置页即时切换）
- 📦 **多格式统一导出** + **范围管控**

### 🛠️ 技术栈

| 分类 | 技术 |
|------|------|
| **运行环境** | Manifest V3、Chrome 111+（`world: MAIN`）、ES module Service Worker |
| **UI / 框架** | Vue 3（Composition API）+ Element Plus（按需自动导入）+ Pinia |
| **语言 / 构建** | TypeScript + Vite + @crxjs/vite-plugin + vue-tsc |
| **能力模块** | `src/core/*.ts` 规则库与只读探测；`src/background.ts` 中枢；`src/{popup,result,options}` 页面 |
| **验证** | `vue-tsc --noEmit` + `vite build` + esbuild 打包后 Node 行为断言 |

---

## 🚀 快速开始

### ⚡ 构建并加载扩展

```bash
npm install          # 安装依赖（npmmirror 源）
npm run build        # vue-tsc 类型检查 + vite build → 产出 dist/
```

1. 打开 `chrome://extensions`，开启右上角「开发者模式」。
2. 点「加载已解压的扩展程序」，选择构建产物目录 **`dist/`**。
3. 需要 Chrome 111+（旧版本对 `window` 全局读取优雅降级、跳过该项）。
4. 开发热更新：`npm run dev`（@crxjs 提供 HMR）。

### 🪜 使用流程

1. 打开你**已获得授权**的目标站点。
2. 点击图标 → 「加入范围并授权」（逐站点主机权限，由你的点击手势触发）。
3. 「开始收集」：采集 DOM/JS/响应头，并只读枚举前端路由、提取 API、做技术栈合并判定与前端安全审计，统一并入结果。
4. 「打开详情」分栏查看；在弹窗或详情页选择导出格式。
5. 主动探测（默认关闭）：设置开启后点「主动探测」，对判定为 Vue/React 的站点追加前端路由 HTTP 可达性探测。

---

## 📦 导出

在扩展页面内用 `<a download>` 触发（不依赖 `chrome.downloads`）：

- **JSON** 完整结构化结果 ｜ **CSV** 多维 ｜ **Markdown** 报告 ｜ **HTML** 自包含可打印 ｜ **SRC 报告** 赏金提交草稿 ｜ **端点 TXT** 可贴 Burp

支持**按等级筛选**、**多目标聚合**、**规则/Dork 库 JSON 导入导出**。

---

## 🧪 验证

| 层级 | 方式 | 状态 |
|------|------|------|
| 类型 | `vue-tsc --noEmit`（src 全量，含 core 与页面） | ✅ |
| 构建 | `vite build` + @crxjs（manifest/SW/三页/war 全部产出） | ✅ |
| 纯逻辑 | esbuild 打包 `src/core` 后 Node 运行 26 项断言（含只读探测五适配器） | ✅ |
| 运行时 | 注入/采集/剪贴板/UI 渲染 | ⚠️ 需在 Chrome 加载 `dist/` 实测 |

详见：[docs/已知限制与运行验证.md](docs/已知限制与运行验证.md)

---

## 📚 文档

- [docs/技能来源与能力映射.md](docs/技能来源与能力映射.md) — 来源技能、上游插件复用、能力边界、移植进度
- [docs/功能与模块说明.md](docs/功能与模块说明.md) — 各模块能力、导出方式、完整目录结构
- [docs/已知限制与运行验证.md](docs/已知限制与运行验证.md) — 已知限制、验证方法与需实测清单

---

## ⚠️ 合规与能力边界

- 仅用于**已授权**目标；命中皆为**线索**，须人工确认；密钥/令牌默认掩码，数据仅存本机。
- **不接管前端 Router、不绕过服务端鉴权**：原“梭哈”的意图并入主动探测，仅为对枚举路由做 HTTP 可达性核验。
- 内存利用/无线/密码学破解类不在浏览器扩展职责内（详见技能来源文档）。

---

## 🤝 贡献指南

1. Fork / 复制本目录
2. 新建分支：`git checkout -b feature/xxx`
3. 提交：`git commit -m 'feat: ...'`
4. 推送并发起 Pull Request

---

## 🙏 致敬与来源

ReconX 整合、参考了以下开源项目，谨向其作者致谢，并遵循各自原有许可证：

- [**crazy_edusrc**](https://github.com/dollmarker/crazy_edusrc) — EduSRC 猎洞工具**原版**（dollmarker）
- [**CrazyEdusrcX**](https://github.com/ZapcoMan/CrazyEdusrcX) — crazy_edusrc 的**二次开发**（ZapcoMan）：Dork 库、资产测绘、敏感分级、URL 规范化
- [**King-Crack**](https://github.com/chaojiwudichoubie1-arch/King-Crack) — 前端框架/路由/API 侦察**纯正原版**（纯 JS）
- [**King-CrackX**](https://github.com/ZapcoMan/King-CrackX) — King-Crack 的**二次开发**（ZapcoMan，纯 JS 重构为 Vue3 + TS）：框架/路由枚举、API 提取、安全审计、导出实现

---

## 📄 许可证

本项目以 **GNU GPL v2** 发布，全文见 [LICENSE](LICENSE)。整合的上游组件遵循各自原有许可证（如 crazy_edusrc / CrazyEdusrcX 为 MIT，King-Crack / King-CrackX 为 GPL 系列）。

---

*最后更新时间：2026-10-21*
*本轮更新：架构重构为 Vue 3 + TypeScript + Vite + @crxjs + Element Plus + Pinia；core 逻辑库 TS 化为 `src/core`，三页重写为 Vue SFC*

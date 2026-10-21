# ReconX

<div align="center">

![Manifest V3](https://img.shields.io/badge/Manifest%20V3-Extension-2dd4bf)
![Vue 3](https://img.shields.io/badge/Vue-3.x-42b883)
![TypeScript](https://img.shields.io/badge/TypeScript-5.x-3178c6)
![Element Plus](https://img.shields.io/badge/UI-Element--Plus-409eff)
![Vite](https://img.shields.io/badge/Build-Vite%20%2B%20crxjs-646cff)
![License](https://img.shields.io/badge/License-GPL--v2-yellow)

**面向已授权目标的浏览器端安全侦察工作台**

[这是什么](#-这是什么) • [使用前必须知道](#️-使用前必须知道) • [快速开始](#-快速开始) • [文档](#-文档) • [致敬与许可](#-致敬与来源)

</div>

---

## 📋 这是什么

ReconX 是一个 Chrome（Manifest V3）扩展，把三条能力线整合到一份采集结果与一套导出里：

- **被动采集与指纹分析** — 技术栈 / WAF / 版本、响应头与 Cookie、JS 敏感信息、链接与参数、前端路由与 API 端点。页面侧探测脚本 `router-probe` 经逐函数核验为纯只读。
- **主动探测与前端接管核验** — 敏感路径可达性 GET、路由可达性 GET，以及「梭哈模式」的客户端路由接管（屏蔽前端守卫、改写鉴权 meta、拦截跳转），用来核验受保护前端路由能否直达。
- **OSINT 查询生成** — Dork 语法库与资产测绘查询，**只生成语法与地址文本，不打开标签页、不跳转**。

面向渗透测试 / 漏洞赏金 / OSINT / 自有站点自查。基于 Vue 3 + TypeScript + Vite + @crxjs + Element Plus + Pinia 构建，无构建产物外的运行时依赖。

## ⚠️ 使用前必须知道

1. **它不是只读工具。** 第 2 条能力线会向目标发出真实请求，并在页面主世界改写前端路由对象。只在你对该资产有测试授权时使用。
2. **接管是常驻的，不是点一次算一次。** 主机一旦加入允许域，`all-in.js` 就以 `document_start` 注册进该站点的每次页面加载，无需你再点「主动探测」。当前从设置页移除允许域**不会立刻注销**这份注册——要彻底停止，需在设置页「撤销全部主机权限」并重载扩展。详见 [已知限制](docs/已知限制与运行验证.md)。
3. **接管只发生在客户端。** 服务端仍按真实凭据校验，401/403 与数据级鉴权照样拦得住；页面拿得到路由不等于拿得到数据。
4. **命中都是线索，不是结论。** 指纹、风险分级、"未受保护路由"等判定基于关键词与启发式，误报率不低，须人工确认后再据此提交漏洞。
5. **数据留在本机，但请注意导出内容。** 结果存在 `chrome.storage.local`，不外发。多数密钥命中做了掩码，但 JWT 的解码载荷与完整 URL/参数会原样进入结果与导出文件——别把导出随手贴给第三方。

## 🚀 快速开始

```bash
npm install          # 安装依赖
npm run build        # vue-tsc 类型检查 + vite build → 产出 dist/
npm run dev          # 开发热更新（@crxjs HMR）
```

1. 打开 `chrome://extensions`，开启「开发者模式」。
2. 点「加载已解压的扩展程序」，选择构建产物目录 **`dist/`**。
3. 需要 Chrome 111+（旧版本对 `window` 全局读取与 MAIN world 注入会优雅降级）。

使用流程：**打开已授权目标 → 弹窗「授权并加入范围」→「开始采集」→「查看结果」/导出 →（可选）「主动探测」**。逐条能力与交互细节见 [功能与模块说明](docs/功能与模块说明.md)。

## 📚 文档

| 文档 | 管什么 |
|---|---|
| [docs/功能与模块说明.md](docs/功能与模块说明.md) | 能力矩阵、三层运行架构与调用链、双源探测主次判定、梭哈模式、导出、目录结构 |
| [docs/已知限制与运行验证.md](docs/已知限制与运行验证.md) | 能力边界分级、已确认的代码级限制、判定可靠性风险、验证方法与需 Chrome 实测清单 |
| [docs/技能来源与能力映射.md](docs/技能来源与能力映射.md) | 来源技能映射、两个上游插件各自的贡献、移植进度与缺口 |

本 README 只保留门面与风险告知，细节以上述三份为唯一出处。

## 🙏 致敬与来源

ReconX 整合、参考了以下开源项目，谨向其作者致谢，并遵循各自原有许可证：

- [**crazy_edusrc**](https://github.com/dollmarker/crazy_edusrc) — EduSRC 猎洞工具原版（dollmarker）
- [**CrazyEdusrcX**](https://github.com/ZapcoMan/CrazyEdusrcX) — 二次开发：Dork 库、资产测绘、敏感分级、URL 规范化
- [**King-Crack**](https://github.com/chaojiwudichoubie1-arch/King-Crack) — 前端框架/路由/API 侦察原版（纯 JS）
- [**King-CrackX**](https://github.com/ZapcoMan/King-CrackX) — 二次开发（Vue3 + TS）：框架/路由枚举、API 提取、安全审计、梭哈模式

## 📄 许可证

本项目以 **GNU GPL v2** 发布，全文见 [LICENSE](LICENSE)。整合的上游组件遵循各自原有许可证（crazy_edusrc / CrazyEdusrcX 为 MIT，King-Crack / King-CrackX 为 GPL 系列）。

---

*版本 0.2.0 ｜ 最后更新：2026-10-21（依据逐文件读码结果重写门面，能力细节下沉 `docs/`）*

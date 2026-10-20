/* global self */
// 统一导出中枢：在扩展页面上下文（popup/result/options）通过 <a download> 触发下载。
// —— 根治旧实现“在 MV3 service worker 里用 chrome.downloads 下载 SW blob 不可靠”的问题。
// 不依赖 chrome.downloads；纯 DOM，可被任何扩展页面直接 import。
(function () {
  const X = {};

  const ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const SEV_CN = { critical: "严重", high: "高危", medium: "中危", low: "低危", info: "提示", warn: "需核验", safe: "安全" };
  X.SEV_CN = SEV_CN;

  function esc(s) {
    return String(s == null ? "" : s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  }
  function escMd(s) {
    return String(s == null ? "" : s).replace(/\|/g, "\\|").replace(/\r?\n/g, " ");
  }
  function escCsv(s) {
    return '"' + String(s == null ? "" : s).replace(/"/g, '""') + '"';
  }

  function stamp() {
    const n = new Date();
    const p = (x) => String(x).padStart(2, "0");
    return n.getFullYear() + p(n.getMonth() + 1) + p(n.getDate()) + "-" + p(n.getHours()) + p(n.getMinutes()) + p(n.getSeconds());
  }
  X.buildFilename = function (bundle, ext) {
    let host = "site";
    try {
      host = new URL(bundle.meta.url).hostname.replace(/[^a-zA-Z0-9.-]/g, "_");
    } catch (e) {
      host = (bundle.meta && bundle.meta.host) || "site";
    }
    return "recon-" + host + "-" + stamp() + "." + ext;
  };

  // ---- 下载：页面上下文 a[download] ----
  X.download = function (filename, content, mime) {
    if (typeof document === "undefined") throw new Error("download 只能在扩展页面(popup/result/options)调用，不能在 service worker 调用");
    const blob = new Blob([content], { type: (mime || "text/plain") + ";charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 20000);
  };

  // ---- 收集“发现项”（赏金模板与风险汇总的公共底座） ----
  X.collectFindings = function (bundle) {
    const items = [];
    const add = (o) => items.push(o);
    // JS 密钥/凭据
    (bundle.js ? bundle.js.findings : []).concat(bundle.js ? bundle.js.inlineFindings : []).forEach((f) => {
      if (ORDER[f.severity] <= ORDER.medium) {
        add({ category: "敏感信息泄露", title: f.name, level: f.severity, target: f.url || "inline", evidence: (f.samples || []).map((s) => s.masked), description: f.desc });
      }
    });
    // 响应头/配置
    (bundle.headers ? bundle.headers.missing : []).forEach((m) => {
      if (ORDER[m.level] <= ORDER.medium) add({ category: "安全头", title: m.header + " 缺失", level: m.level, evidence: [m.advice] });
    });
    (bundle.headers ? bundle.headers.advisories : []).forEach((a) => {
      if (ORDER[a.level] <= ORDER.medium) add({ category: "配置", title: a.type, level: a.level, detail: a.detail, evidence: [a.advice] });
    });
    // Sourcemap
    (bundle.js ? bundle.js.sourcemaps : []).forEach((s) => add({ category: "源码泄露", title: "Source Map 可还原源码", level: "low", target: s.from, evidence: [s.map] }));
    // 主动探测命中
    if (bundle.probes && bundle.probes.performed && bundle.probes.results) {
      bundle.probes.results.filter((p) => p.matched).forEach((p) => add({ category: "信息泄露", title: p.desc, level: p.severity, target: p.path, evidence: ["HTTP " + p.status + " / " + p.bytes + " bytes"] }));
    }
    // —— 以下为 King 移植后新增字段（不存在则跳过） ——
    (bundle.security && bundle.security.sensitiveApis ? bundle.security.sensitiveApis : []).forEach((s) => add({ category: "敏感 API", title: s.category || "敏感接口", level: s.riskLevel || "medium", target: s.fullUrl || s.path, evidence: [s.matchedKeyword].filter(Boolean) }));
    (bundle.security && bundle.security.unauthorizedRoutes ? bundle.security.unauthorizedRoutes : []).forEach((r) => add({ category: "未授权访问路径", title: r.path, level: r.riskLevel || "medium", evidence: [r.riskDescription].filter(Boolean) }));
    // 端点分级（来自 url-classify 之后写入 links.classified）
    (bundle.links && bundle.links.classified ? bundle.links.classified : []).forEach((c) => {
      if (c.level === "critical") add({ category: "敏感端点", title: (c.labels || []).join("/"), level: "high", target: c.url, evidence: c.labels });
    });
    items.sort((a, b) => (ORDER[a.level] || 9) - (ORDER[b.level] || 9));
    return items;
  };

  // ---- 筛选：按最低等级 + 类别白名单裁剪 bundle（返回浅拷贝副本） ----
  X.filterBundle = function (bundle, opts) {
    opts = opts || {};
    const minRank = opts.minSeverity ? ORDER[opts.minSeverity] : 99;
    const keepCat = Array.isArray(opts.categories) && opts.categories.length ? new Set(opts.categories) : null;
    const bySev = (s) => (s in ORDER ? ORDER[s] <= minRank : true);
    const out = JSON.parse(JSON.stringify(bundle));
    if (out.js) {
      const f = (arr) => (arr || []).filter((x) => bySev(x.severity));
      out.js.findings = f(out.js.findings);
      out.js.inlineFindings = f(out.js.inlineFindings);
    }
    if (out.headers) {
      out.headers.missing = (out.headers.missing || []).filter((x) => bySev(x.level));
      out.headers.advisories = (out.headers.advisories || []).filter((x) => bySev(x.level));
    }
    if (out.probes && out.probes.results) out.probes.results = out.probes.results.filter((p) => bySev(p.severity));
    out.risks = (out.risks || []).filter((r) => bySev(r.level) && (!keepCat || keepCat.has(r.category)));
    return out;
  };

  // ---- 各格式生成 ----
  X.toJson = (b) => JSON.stringify(b, null, 2);

  X.toCsv = function (b) {
    const rows = [["section", "level", "name", "target", "detail", "evidence"]];
    X.collectFindings(b).forEach((f) => rows.push(["finding", f.level, f.title, f.target || "", (f.description || f.detail || ""), (f.evidence || []).join(" ; ")]));
    (b.tech || []).forEach((t) => rows.push(["tech", "", t.name + (t.version ? " " + t.version : ""), t.category, "", (t.evidence || []).join(" ; ")]));
    (b.waf || []).forEach((w) => rows.push(["waf", "", w.name, w.vendor || "", w.note || "", (w.evidence || []).join(" ; ")]));
    if (b.links) (b.links.endpoints || []).forEach((e) => rows.push(["endpoint", "", e.url, e.same ? "same" : "cross", e.ctx || "", (e.params || []).join(",")]));
    if (b.routes) (b.routes.allRoutes || []).forEach((r) => rows.push(["route", "", r.path, r.name || "", "", JSON.stringify(r.meta || {})]));
    return rows.map((r) => r.map(escCsv).join(",")).join("\r\n");
  };

  function counts(items) {
    const c = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    items.forEach((i) => { if (c[i.level] != null) c[i.level]++; });
    return c;
  }

  X.toMarkdown = function (b) {
    const f = X.collectFindings(b);
    const c = counts(f);
    const L = [];
    L.push("# Recon 采集报告 — " + (b.meta.host || ""));
    L.push("");
    L.push("- 生成时间：" + new Date().toLocaleString("zh-CN"));
    L.push("- 目标 URL：" + (b.meta.url || ""));
    L.push("- 是否在允许域范围：" + (b.meta.inScope ? "是" : "否"));
    if (b.meta.headerNote) L.push("- 采集备注：" + b.meta.headerNote);
    L.push("");
    L.push("## 发现汇总");
    L.push("");
    L.push("| 严重 | 高危 | 中危 | 低危 | 提示 |");
    L.push("|---|---|---|---|---|");
    L.push("| " + c.critical + " | " + c.high + " | " + c.medium + " | " + c.low + " | " + c.info + " |");
    L.push("");
    L.push("## 技术栈");
    (b.tech || []).forEach((t) => L.push("- " + t.name + (t.version ? " " + t.version : "") + "（" + t.category + "）" + (t.evidence && t.evidence[0] ? " — " + t.evidence[0] : "")));
    if (!b.tech || !b.tech.length) L.push("- （无）");
    L.push("");
    L.push("## WAF / 边缘防护线索");
    (b.waf || []).forEach((w) => L.push("- " + w.name + (w.vendor ? " (" + w.vendor + ")" : "") + " — " + (w.evidence || []).join(", ")));
    if (!b.waf || !b.waf.length) L.push("- （未发现）");
    L.push("");
    L.push("## 发现项（已掩码，需人工复核）");
    f.forEach((it, i) => {
      L.push("### " + (i + 1) + ". [" + (SEV_CN[it.level] || it.level) + "] " + it.category + "：" + it.title);
      if (it.target) L.push("- 位置：" + escMd(it.target));
      if (it.description) L.push("- 说明：" + it.description);
      if (it.detail) L.push("- 详情：" + escMd(it.detail));
      if (it.evidence && it.evidence.length) L.push("- 证据：" + it.evidence.map(escMd).join(" ; "));
      L.push("");
    });
    if (!f.length) L.push("- （无显著发现）");
    if (b.links) {
      L.push("## 端点与参数");
      L.push("- 端点总数 " + b.links.total + "，同源 " + b.links.sameOriginCount);
      (b.links.params || []).slice(0, 40).forEach((p) => L.push("  - 参数 `" + p.name + "` ×" + p.count));
      L.push("");
    }
    if (b.probes && b.probes.performed) {
      L.push("## 主动探测");
      (b.probes.results || []).filter((p) => p.matched).forEach((p) => L.push("- [" + (SEV_CN[p.severity] || p.severity) + "] " + p.path + " -> " + p.status + " " + p.desc));
      L.push("");
    }
    L.push("---");
    L.push("> 仅用于已授权目标（渗透测试/漏洞赏金/OSINT/自查）。命中皆为线索，需人工确认。");
    return L.join("\n");
  };

  X.toSrcMarkdown = function (b) {
    // 面向 SRC/众测提交：每条发现给 复现/影响/建议 占位骨架，证据自带。
    const f = X.collectFindings(b);
    const L = [];
    L.push("# SRC 漏洞提交草稿 — " + (b.meta.host || ""));
    L.push("");
    L.push("- 目标资产：" + (b.meta.url || ""));
    L.push("- 发现数量：" + f.length);
    L.push("- 提示：以下为基于自动采集的草稿骨架，请按实际验证补充复现步骤与 PoC 后再提交。");
    L.push("");
    if (!f.length) L.push("（无可用发现）");
    f.forEach((it, i) => {
      L.push("## " + (i + 1) + ". " + it.title + "　【" + (SEV_CN[it.level] || it.level) + "】");
      L.push("");
      L.push("- **类型**：" + it.category);
      L.push("- **影响 URL/路径**：" + (it.target || "—"));
      L.push("- **证据（掩码）**：" + (it.evidence || []).map(escMd).join(" ; ") + " " + (it.detail ? "/ " + escMd(it.detail) : ""));
      L.push("- **复现步骤**：（待补充）");
      L.push("- **影响说明**：（待补充，结合业务）");
      L.push("- **修复建议**：" + (it.description ? it.description + "（请据此评估）" : "（待补充）"));
      L.push("");
    });
    return L.join("\n");
  };

  X.toHtml = function (b) {
    const f = X.collectFindings(b);
    const c = counts(f);
    const chip = (k, v) => '<div class="chip"><b>' + v + "</b><span>" + k + "</span></div>";
    const find = (it) =>
      '<tr><td><span class="lvl ' + it.level + '">' + (SEV_CN[it.level] || it.level) + "</span></td><td>" + esc(it.category) + "</td><td>" + esc(it.title) + "</td><td class=\"mono\">" + esc(it.target || "") + "</td><td>" + esc((it.evidence || []).join(" ; ")) + "</td></tr>";
    const tech = (b.tech || []).map((t) => "<li>" + esc(t.name + (t.version ? " " + t.version : "")) + " <i>(" + esc(t.category) + ")</i></li>").join("");
    const waf = (b.waf || []).map((w) => "<li>" + esc(w.name) + " — " + esc((w.evidence || []).join(", ")) + "</li>").join("");
    return (
      "<!doctype html><html lang=\"zh-CN\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>Recon " + esc(b.meta.host) + "</title><style>" +
      ":root{--b:#0f1620;--p:#16212e;--i:#d7e2ee;--m:#7c8c9e;--a:#2dd4bf;--l:#223043}body{margin:0;font:14px/1.6 system-ui,'Microsoft YaHei',sans-serif;background:var(--b);color:var(--i)}" +
      ".wrap{max-width:980px;margin:0 auto;padding:24px 18px 60px}h1{color:var(--a)}h2{margin-top:26px;border-left:3px solid var(--a);padding-left:8px}.mono{font-family:Consolas,monospace;font-size:12px;word-break:break-all}" +
      ".meta{color:var(--m);font-size:13px}.chips{display:flex;gap:10px;flex-wrap:wrap;margin:14px 0}.chip{background:var(--p);border:1px solid var(--l);border-radius:10px;padding:8px 14px}.chip b{display:block;font-size:20px;color:var(--a)}" +
      "table{width:100%;border-collapse:collapse;margin:10px 0}th,td{border-bottom:1px solid var(--l);padding:6px 8px;text-align:left;vertical-align:top;font-size:13px}th{color:var(--m)}" +
      "ul{padding-left:18px}.lvl{padding:1px 6px;border-radius:4px;font-size:12px;font-weight:700}.lvl.critical{background:#4a0d0d;color:#ff8a80}.lvl.high{background:#5a1500;color:#ffab91}.lvl.medium{background:#4a3600;color:#ffe082}.lvl.low{background:#0b3a4a;color:#80deea}.lvl.info{background:#243042;color:#9ab}" +
      "footer{color:var(--m);margin-top:30px;border-top:1px solid var(--l);padding-top:12px;font-size:12px}" +
      "</style></head><body><div class=\"wrap\"><h1>Recon 采集报告</h1>" +
      "<div class=\"meta\">目标：" + esc(b.meta.url) + " ｜ 生成：" + new Date().toLocaleString("zh-CN") + " ｜ 在允许域：" + (b.meta.inScope ? "是" : "否") + "</div>" +
      "<div class=\"chips\">" + chip("严重", c.critical) + chip("高危", c.high) + chip("中危", c.medium) + chip("低危", c.low) + chip("端点", b.links ? b.links.total : 0) + "</div>" +
      "<h2>发现项（已掩码）</h2><table><thead><tr><th>等级</th><th>类别</th><th>标题</th><th>位置</th><th>证据</th></tr></thead><tbody>" + (f.map(find).join("") || "<tr><td colspan=5>无</td></tr>") + "</tbody></table>" +
      "<h2>技术栈</h2><ul>" + (tech || "<li>无</li>") + "</ul>" +
      "<h2>WAF / 边缘防护</h2><ul>" + (waf || "<li>未发现</li>") + "</ul>" +
      "<footer>本报告由 ReconX 生成，仅用于已授权目标。命中皆为线索，需人工确认。</footer></div></body></html>"
    );
  };

  X.toTxtEndpoints = function (b) {
    const L = ["# Recon 端点导出", "# 目标: " + (b.meta.url || ""), "# 时间: " + new Date().toLocaleString(), "", "## 全部 URL（Burp Intruder/Scanner 可直接粘贴）"];
    const seen = new Set();
    (b.links ? b.links.endpoints : []).forEach((e) => { if (!seen.has(e.url)) { seen.add(e.url); L.push(e.url); } });
    if (b.routes && b.routes.fullUrls) {
      L.push("", "## 路由完整 URL");
      b.routes.fullUrls.forEach((r) => { if (!seen.has(r.url)) { seen.add(r.url); L.push(r.url); } });
    }
    return L.join("\n");
  };

  X.GENERATORS = {
    json: { fn: (b) => X.toJson(b), ext: "json", mime: "application/json" },
    csv: { fn: (b) => X.toCsv(b), ext: "csv", mime: "text/csv" },
    md: { fn: (b) => X.toMarkdown(b), ext: "md", mime: "text/markdown" },
    src: { fn: (b) => X.toSrcMarkdown(b), ext: "md", mime: "text/markdown" },
    html: { fn: (b) => X.toHtml(b), ext: "html", mime: "text/html" },
    txt: { fn: (b) => X.toTxtEndpoints(b), ext: "txt", mime: "text/plain" },
  };

  // fmt: 单格式或格式数组；opts: {minSeverity, categories, download:true|false}
  X.export = function (bundle, fmt, opts) {
    opts = opts || {};
    const b = X.filterBundle(bundle, opts);
    const list = Array.isArray(fmt) ? fmt : [fmt];
    const made = [];
    list.forEach((k) => {
      const g = X.GENERATORS[k];
      if (!g) return;
      const content = g.fn(b);
      const filename = X.buildFilename(b, g.ext);
      if (opts.download === false) made.push({ fmt: k, filename, content });
      else X.download(filename, content, g.mime);
    });
    return made.length ? made : { ok: true };
  };

  // 多目标聚合导出（合并成一份综合 Markdown/HTML/JSON）
  X.exportMulti = function (bundles, fmt) {
    const merged = { meta: { host: "multi-" + bundles.length, url: "(多目标聚合 " + bundles.length + " 个)", collectedAt: Date.now(), inScope: true, headerNote: "" }, tech: [], waf: [], links: { total: 0, sameOriginCount: 0, endpoints: [], params: [] }, js: { findings: [], inlineFindings: [], sourcemaps: [] }, headers: { missing: [], advisories: [], raw: [] }, risks: [], _targets: [] };
    bundles.forEach((b) => {
      merged._targets.push({ host: b.meta.host, url: b.meta.url, time: b.meta.collectedAt });
      merged.tech = merged.tech.concat((b.tech || []).map((t) => Object.assign({ host: b.meta.host }, t)));
      merged.waf = merged.waf.concat((b.waf || []).map((t) => Object.assign({ host: b.meta.host }, t)));
      merged.js.findings = merged.js.findings.concat(b.js ? b.js.findings : []);
      merged.js.sourcemaps = merged.js.sourcemaps.concat(b.js ? b.js.sourcemaps : []);
      merged.headers.missing = merged.headers.missing.concat(b.headers ? b.headers.missing : []);
      if (b.links) { merged.links.total += b.links.total; merged.links.sameOriginCount += b.links.sameOriginCount; merged.links.endpoints = merged.links.endpoints.concat(b.links.endpoints || []); }
    });
    const g = X.GENERATORS[fmt] || X.GENERATORS.md;
    const content = g.fn(merged);
    X.download("recon-multi-" + bundles.length + "-" + stamp() + "." + g.ext, content, g.mime);
  };

  // Dork / 规则库 导入导出
  X.exportJson = function (obj, name) {
    X.download(name + "-" + stamp() + ".json", JSON.stringify(obj, null, 2), "application/json");
  };
  X.parseJson = function (text) {
    try { return { ok: true, data: JSON.parse(text) }; } catch (e) { return { ok: false, error: String((e && e.message) || e) }; }
  };

  self.Exporter = X;
})();

/* global chrome */
(async function () {
  const $ = (id) => document.getElementById(id);
  const SEV_CN = { critical: "严重", high: "高危", medium: "中危", low: "低危", info: "提示" };
  const el = (tag, cls, ...kids) => {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    for (const k of kids) e.append(k && k.nodeType ? k : document.createTextNode(String(k == null ? "" : k)));
    return e;
  };
  const sevSpan = (lvl) => el("span", "lvl " + lvl, SEV_CN[lvl] || lvl);
  function table(headers, rows) {
    const t = el("table");
    const thead = el("thead");
    const tr = el("tr");
    headers.forEach((h) => tr.append(el("th", null, h)));
    thead.append(tr);
    t.append(thead);
    const tb = el("tbody");
    for (const r of rows) {
      const row = el("tr");
      for (const c of r) row.append(el("td", null, c && c.nodeType ? c : document.createTextNode(String(c == null ? "" : c))));
      tb.append(row);
    }
    if (!rows.length) {
      const row = el("tr");
      const cell = el("td", "muted");
      cell.colSpan = headers.length;
      cell.textContent = "（无）";
      row.append(cell);
      tb.append(row);
    }
    t.append(tb);
    return t;
  }
  const panel = (id, title, body) => ({ id, title, render: () => el("section", "block", el("h2", null, title), body) });

  const { lastBundle: bundle } = await chrome.storage.local.get("lastBundle");

  if (!bundle) {
    $("panels").append(el("p", "muted", "尚无结果。回到网页的插件弹窗点击“开始收集”后，再打开此窗口。"));
    return;
  }

  $("meta").textContent = bundle.meta.host + " · " + new Date(bundle.meta.collectedAt).toLocaleString();

  // ---- 概览 ----
  const ovBody = el("div");
  ovBody.append(el("p", "muted", bundle.meta.url));
  if (bundle.meta.headerNote) ovBody.append(el("p", "note", "ⓘ " + bundle.meta.headerNote));
  ovBody.append(
    table(["项目", "数量"], [
      ["技术栈条目", bundle.tech.length],
      ["WAF 线索", bundle.waf.length],
      ["链接/端点（同源/总）", bundle.links.sameOriginCount + " / " + bundle.links.total],
      ["JS 扫描文件", (bundle.js.scanned || []).length],
      ["JS 高危/严重命中", (bundle.js.findings || []).concat(bundle.js.inlineFindings || []).filter((f) => f.severity === "high" || f.severity === "critical").length],
      ["缺失安全头", (bundle.headers.missing || []).length],
      ["配置建议项", (bundle.headers.advisories || []).length],
    ])
  );
  if (bundle.risks.length) {
    ovBody.append(el("h3", null, "风险摘要"));
    const ul = el("ul", "risks");
    bundle.risks.forEach((r) => ul.append(el("li", null, sevSpan(r.level), " ", el("b", null, r.category), "： " + r.summary)));
    ovBody.append(ul);
  }
  // ---- 技术栈 & WAF ----
  const techBody = el("div");
  techBody.append(el("h3", null, "技术栈"));
  techBody.append(
    table(["名称", "类别", "版本", "证据"], bundle.tech.map((t) => [t.name, t.category, t.version || "-", (t.evidence || []).join("; ")]))
  );
  techBody.append(el("h3", null, "WAF / 边缘防护线索"));
  techBody.append(table(["名称", "厂商", "证据", "说明"], bundle.waf.map((w) => [w.name, w.vendor || "-", (w.evidence || []).join(", "), w.note || ""])));
  // ---- 响应头 & Cookie ----
  const hdBody = el("div");
  hdBody.append(el("p", "muted", "Server: " + (bundle.headers.server || "-") + "   X-Powered-By: " + (bundle.headers.poweredBy || "-")));
  hdBody.append(el("h3", null, "缺失的安全头"));
  hdBody.append(table(["安全头", "级别", "建议"], bundle.headers.missing.map((m) => [m.header, sevSpan(m.level), m.advice])));
  hdBody.append(el("h3", null, "配置建议"));
  hdBody.append(table(["级别", "类型", "详情", "建议"], bundle.headers.advisories.map((a) => [sevSpan(a.level), a.type, a.detail || a.header || "", a.advice])));
  hdBody.append(el("h3", null, "Cookie"));
  hdBody.append(
    table(["名称", "值(掩码)", "HttpOnly", "Secure", "SameSite", "Domain", "标记问题"], bundle.headers.cookies.map((c) => [
      c.name, c.valueMasked, c.httponly ? "✓" : "✗", c.secure ? "✓" : "✗", c.samesite || "-", c.domain || "-", (c.flags || []).join("; "),
    ]))
  );
  hdBody.append(el("h3", null, "CORS"));
  hdBody.append(table(["项", "值"], [
    ["Access-Control-Allow-Origin", bundle.headers.cors.allowOrigin || "-"],
    ["Allow-Credentials", bundle.headers.cors.allowCredentials ? "true" : "false"],
    ["Allow-Methods", bundle.headers.cors.allowMethods || "-"],
    ["Allow-Headers", bundle.headers.cors.allowHeaders || "-"],
  ]));
  hdBody.append(el("h3", null, "CSP"));
  if (bundle.headers.csp && bundle.headers.csp.directives) {
    hdBody.append(table(["directive", "sources"], Object.entries(bundle.headers.csp.directives).map(([k, v]) => [k, (v || []).join(" ")])));
  } else {
    hdBody.append(el("p", "muted", "无 CSP。"));
  }
  hdBody.append(el("h3", null, "原始响应头"));
  hdBody.append(table(["头", "值"], (bundle.headers.raw || []).map((h) => [h.name, h.value])));
  // ---- JS 敏感信息 ----
  const jsBody = el("div");
  jsBody.append(el("p", "muted", "已扫描文件：" + (bundle.js.scanned || []).length + "   跳过(过大等)：" + (bundle.js.scanned || []).filter((s) => s.skipped).length + "   失败：" + (bundle.js.scanned || []).filter((s) => !s.ok).length));
  jsBody.append(el("h3", null, "外链 JS 命中"));
  jsBody.append(
    table(["级别", "类型", "次数", "样本(掩码)", "位置"], bundle.js.findings.map((f) => [sevSpan(f.severity), f.name, f.count, (f.samples || []).map((s) => s.masked).join(" , "), f.url]))
  );
  if (bundle.js.findings.some((f) => f.jwtDecoded)) {
    jsBody.append(el("h3", null, "JWT 解码示例"));
    const jwt = bundle.js.findings.find((f) => f.jwtDecoded);
    const d = jwt.jwtDecoded;
    jsBody.append(el("pre", null, JSON.stringify(d, null, 2)));
  }
  jsBody.append(el("h3", null, "内联脚本命中"));
  jsBody.append(table(["级别", "类型", "次数", "样本(掩码)"], bundle.js.inlineFindings.map((f) => [sevSpan(f.severity), f.name, f.count, (f.samples || []).map((s) => s.masked).join(" , ")])));
  jsBody.append(el("h3", null, "Source Map"));
  jsBody.append(table(["来源", "map"], (bundle.js.sourcemaps || []).map((s) => [s.from, s.map])));
  // ---- 链接 & 端点 ----
  const lkBody = el("div");
  const byHost = el("div", "chips");
  bundle.links.byHost.slice(0, 30).forEach((h) => byHost.append(el("span", "chip", h.host + ": " + h.count)));
  lkBody.append(el("h3", null, "按主机"));
  lkBody.append(byHost);
  lkBody.append(el("h3", null, "高频参数"));
  lkBody.append(table(["参数名", "出现次数"], bundle.links.params.slice(0, 60).map((p) => [p.name, p.count])));
  lkBody.append(el("h3", null, "端点（前 400）"));
  lkBody.append(
    table(["URL", "同/跨站", "上下文", "参数"], bundle.links.endpoints.slice(0, 400).map((e) => [e.url, e.same ? "同" : "跨", e.ctx, (e.params || []).join(",")]))
  );
  lkBody.append(el("h3", null, "表单"));
  bundle.links.forms.forEach((f) => {
    lkBody.append(el("p", "formline", el("b", null, f.method + " " + (f.action || "#")), " 字段: " + (f.fields || []).map((x) => x.name + "(" + x.type + (x.hidden ? ",hidden" : "") + ")").join(", ")));
  });
  // ---- 主动探测 ----
  const prBody = el("div");
  if (bundle.probes && bundle.probes.performed && bundle.probes.results) {
    const hits = bundle.probes.results.filter((p) => p.matched);
    prBody.append(el("p", "muted", "命中 " + hits.length + " / 共探测 " + bundle.probes.results.length + " 条路径"));
    prBody.append(table(["路径", "状态", "字节", "命中", "级别", "说明"], bundle.probes.results.map((p) => [p.path, p.status || "-", p.bytes || "-", p.matched ? "✅" : "-", sevSpan(p.severity), p.desc])));
  } else {
    prBody.append(el("p", "muted", "未执行主动探测。在弹窗开启“主动探测”后点击执行（务必在授权范围内）。"));
  }

  const TABS = [
    panel("ov", "概览", ovBody),
    panel("tech", "技术栈 & WAF", techBody),
    panel("hd", "响应头 & Cookie", hdBody),
    panel("js", "JS 敏感信息", jsBody),
    panel("lk", "链接 & 端点", lkBody),
    panel("pr", "主动探测", prBody),
  ];
  const nav = $("tabs");
  const panels = $("panels");
  panels.append(el("section", "raw", el("h2", null, "原始 JSON"), el("pre", null, JSON.stringify(bundle, null, 2))));
  const rawSection = panels.lastChild;
  rawSection.style.display = "none";
  TABS.forEach((t, i) => {
    const btn = el("button", "tab" + (i === 0 ? " active" : ""), t.title);
    const body = t.render();
    body.classList.add("panel");
    body.style.display = i === 0 ? "block" : "none";
    panels.insertBefore(body, rawSection);
    btn.addEventListener("click", () => {
      nav.querySelectorAll(".tab").forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
      panels.querySelectorAll(".panel").forEach((p) => (p.style.display = "none"));
      rawSection.style.display = "none";
      body.style.display = "block";
    });
    nav.append(btn);
  });
  const rawBtn = el("button", "tab", "原始 JSON");
  rawBtn.addEventListener("click", () => {
    nav.querySelectorAll(".tab").forEach((b) => b.classList.remove("active"));
    rawBtn.classList.add("active");
    panels.querySelectorAll(".panel").forEach((p) => (p.style.display = "none"));
    rawSection.style.display = "block";
  });
  nav.append(rawBtn);

  document.querySelectorAll(".tools [data-fmt]").forEach((b) =>
    b.addEventListener("click", () => {
      try {
        const minSeverity = (document.getElementById("minSev") || {}).value || "info";
        window.Exporter.export(bundle, b.getAttribute("data-fmt"), { minSeverity });
      } catch (e) { console.error(e); }
    })
  );
})();

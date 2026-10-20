/* global self, Fingerprints, SensitiveRules, HeaderChecks, UrlClassify, RouteUrls, ApiExtract, SecurityAudit */
// background service worker：收集中枢。classic worker，使用 importScripts 加载规则库。
importScripts("lib/fingerprints.js", "lib/sensitive-rules.js", "lib/header-checks.js", "lib/url-classify.js", "lib/route-urls.js", "lib/api-extract.js", "lib/security-audit.js", "lib/router-probe.js", "lib/collect-extras.js", "lib/tech-stack.js", "lib/probe-routes.js");

const DEFAULT_SETTINGS = { activeProbe: false, maxJsFiles: 25, maxConcurrent: 5 };

// ---------------- 范围（允许域白名单） ----------------
async function getScope() {
  const { scope } = await chrome.storage.local.get("scope");
  return scope && Array.isArray(scope.hosts) ? scope : { hosts: [] };
}
async function saveScope(s) {
  await chrome.storage.local.set({ scope: s });
}
async function addHost(host, origin, note) {
  const s = await getScope();
  if (!s.hosts.some((h) => h.host === host)) {
    s.hosts.push({ host, origin, addedAt: Date.now(), note: note || "" });
    await saveScope(s);
  }
  return s;
}
async function removeHost(host) {
  const s = await getScope();
  s.hosts = s.hosts.filter((h) => h.host !== host);
  await saveScope(s);
  return s;
}
async function getSettings() {
  const { settings } = await chrome.storage.local.get("settings");
  return Object.assign({}, DEFAULT_SETTINGS, settings || {});
}
async function inScope(host) {
  const s = await getScope();
  return s.hosts.some((h) => h.host === host);
}

// ---------------- 响应头缓存（来自 webRequest） ----------------
// 只有该 URL 的 host 权限被授予时才会收到事件 —— 天然契合范围管控。
const headersCache = new Map(); // host -> { main: [{name,value}], setCookieCount, subFrames: [] }
function cacheHeaders(details) {
  if (!details.responseHeaders) return;
  let host;
  try {
    host = new URL(details.url).hostname;
  } catch (e) {
    return;
  }
  const entry = headersCache.get(host) || { main: [], subFrames: [] };
  const pairs = details.responseHeaders.map((h) => ({ name: h.name, value: h.value }));
  if (details.type === "main_frame") {
    entry.main = pairs;
  } else if (entry.subFrames.length < 30) {
    entry.subFrames.push({ type: details.type, url: details.url, pairs });
  }
  headersCache.set(host, entry);
}
chrome.webRequest.onHeadersReceived.addListener(cacheHeaders, { urls: ["<all_urls>"], types: ["main_frame", "sub_frame", "xmlhttprequest"] }, ["responseHeaders"]);

// ---------------- DOM 注入结果握手 ----------------
let pendingDom = null;
function collectDom(tabId) {
  return new Promise((resolve, reject) => {
    const to = setTimeout(() => {
      pendingDom = null;
      reject(new Error("DOM 采集超时"));
    }, 5000);
    pendingDom = {
      resolve: (p) => {
        clearTimeout(to);
        pendingDom = null;
        resolve(p);
      },
    };
    chrome.scripting
      .executeScript({ target: { tabId }, files: ["content-dom.js"], injectImmediately: true })
      .catch((e) => {
        clearTimeout(to);
        pendingDom = null;
        reject(e);
      });
  });
}

// ---------------- MAIN world 全局变量探测 ----------------
async function collectWindowVars(tabId) {
  try {
    const [res] = await chrome.scripting.executeScript({
      target: { tabId },
      world: "MAIN",
      func: function (vars) {
        function getPath(o, p) {
          return p.split(".").reduce((a, k) => (a == null ? undefined : a[k]), o);
        }
        const out = [];
        for (const v of vars) {
          try {
            if (window[v.probe] !== undefined) {
              let version = null;
              if (v.versionPaths) {
                for (const path of v.versionPaths) {
                  try {
                    const vv = getPath(window, path);
                    if (vv != null) {
                      version = String(vv);
                      break;
                    }
                  } catch (e) {}
                }
              }
              out.push({ name: v.name, probe: v.probe, weak: !!v.weak, version });
            }
          } catch (e) {}
        }
        return out;
      },
      args: [Fingerprints.GLOBAL_VARS],
    });
    return (res && res.result) || [];
  } catch (e) {
    return [];
  }
}

// ---------------- MAIN world 只读路由/框架探测（引用 lib/router-probe.js 的 ROUTER_PROBE） ----------------
async function detectRouterAndLive(tabId) {
  try {
    const [res] = await chrome.scripting.executeScript({ target: { tabId }, world: "MAIN", func: self.ROUTER_PROBE });
    return (res && res.result) || {};
  } catch (e) {
    return { error: String((e && e.message) || e) };
  }
}

// ---------------- 抓取 JS 并扫描 ----------------
async function fetchText(url) {
  const ctrl = new AbortController();
  const to = setTimeout(() => ctrl.abort(), 5000);
  try {
    const r = await fetch(url, { credentials: "omit", redirect: "follow", signal: ctrl.signal });
    clearTimeout(to);
    const cl = parseInt(r.headers.get("content-length") || "0", 10);
    if (cl > 1500000) return { url, ok: true, skipped: true, reason: "too-large", status: r.status, finalUrl: r.url };
    const t = await r.text();
    return { url, ok: true, status: r.status, size: t.length, text: t.slice(0, 600000), finalUrl: r.url };
  } catch (e) {
    return { url, ok: false, error: String((e && e.message) || e) };
  } finally {
    clearTimeout(to);
  }
}
async function limit(items, n, fn) {
  const out = [];
  let i = 0;
  const workers = new Array(Math.min(n, items.length)).fill(0).map(async () => {
    while (i < items.length) {
      const idx = i++;
      out[idx] = await fn(items[idx]);
    }
  });
  await Promise.all(workers);
  return out;
}
async function scanJs(scriptUrls, inlineText, currentHost, scopeHosts, settings) {
  const endpoints = Object.create(null);
  const shortSource = (u) => {
    try {
      return new URL(u).pathname.split("/").pop();
    } catch (e) {
      return u;
    }
  };
  const uniq = [];
  const seen = new Set();
  for (const u of scriptUrls) {
    let h;
    try {
      h = new URL(u).hostname;
    } catch (e) {
      continue;
    }
    if (h !== currentHost && !scopeHosts.includes(h)) continue; // 仅同源或已授权
    if (seen.has(u)) continue;
    seen.add(u);
    uniq.push(u);
  }
  const targets = uniq.slice(0, settings.maxJsFiles);
  const results = await limit(targets, settings.maxConcurrent, async (u) => {
    const r = await fetchText(u);
    const findings = r.ok && r.text ? SensitiveRules.scanText(r.text, u) : [];
    if (r.ok && r.text) ApiExtract.extractFromText(r.text, endpoints, shortSource(u));
    const maps = r.ok && r.text ? (r.text.match(/[#@]sourceMappingURL=([^\s'"]+)/g) || []).map((s) => s.replace(/[#@]sourceMappingURL=/, "")) : [];
    return { url: u, status: r.status, ok: r.ok, skipped: !!r.skipped, error: r.error, size: r.size, findings, maps };
  });
  // 内联脚本扫描 + 端点提取
  const inlineFindings = inlineText ? SensitiveRules.scanText(inlineText, "inline") : [];
  if (inlineText) ApiExtract.extractFromText(inlineText, endpoints, "inline");
  return { scanned: results.map((r) => ({ url: r.url, status: r.status, ok: r.ok, skipped: r.skipped, size: r.size, error: r.error })), findings: results.flatMap((r) => r.findings), inlineFindings, sourcemaps: results.flatMap((r) => r.maps.map((m) => ({ from: r.url, map: m }))), endpoints };
}

// ---------------- 链接 / 端点 归一 ----------------
function buildLinks(payload, host) {
  const norm = (href) => {
    try {
      const u = new URL(href, payload.url);
      if (!/^https?:$/.test(u.protocol)) return null;
      return u;
    } catch (e) {
      return null;
    }
  };
  const seen = new Set();
  const endpoints = [];
  const paramCount = new Map();
  const byHost = new Map();
  function add(u, ctx) {
    if (!u) return;
    u.hash = "";
    const key = u.href;
    if (seen.has(key)) return;
    seen.add(key);
    const params = Array.from(u.searchParams.keys());
    params.forEach((p) => paramCount.set(p, (paramCount.get(p) || 0) + 1));
    byHost.set(u.hostname, (byHost.get(u.hostname) || 0) + 1);
    endpoints.push({ url: key, host: u.hostname, same: u.hostname === host, path: u.pathname, params, ctx });
  }
  (payload.anchors || []).forEach((a) => add(norm(a.href), "a" + (a.rel ? ":" + a.rel : "")));
  (payload.iframes || []).forEach((s) => add(norm(s), "iframe"));
  (payload.objectEmbed || []).forEach((s) => add(norm(s), "object"));
  (payload.forms || []).forEach((f) => add(norm(f.action), "form"));
  (payload.inlineEndpoints || []).forEach((p) => add(norm(p), "inline"));
  return {
    total: endpoints.length,
    endpoints: endpoints.slice(0, 2000),
    sameOriginCount: endpoints.filter((e) => e.same).length,
    byHost: Array.from(byHost.entries()).map(([h, c]) => ({ host: h, count: c })).sort((a, b) => b.count - a.count),
    params: Array.from(paramCount.entries()).map(([name, count]) => ({ name, count })).sort((a, b) => b.count - a.count),
    forms: payload.forms || [],
  };
}

// ---------------- 资源清单 ----------------
function buildResources(payload) {
  const cls = (u) => {
    const p = u.split("?")[0].toLowerCase();
    if (/\.(js)(\?|$)/.test(p) || /\/js\//.test(p)) return "scripts";
    if (/\.css(\?|$)/.test(p)) return "css";
    if (/\.(png|jpe?g|gif|svg|webp|avif|ico)(\?|$)/.test(p)) return "images";
    if (/\.(woff2?|ttf|otf|eot)(\?|$)/.test(p)) return "fonts";
    if (/\.(json|xml|txt|csv)(\?|$)/.test(p) || /\/(api|graphql|rest)\//.test(p)) return "data";
    return "other";
  };
  const all = Array.from(new Set([...(payload.scripts || []), ...(payload.links || []).map((l) => l.href), ...(payload.images || []), ...(payload.resourceUrls || [])]));
  const out = { scripts: [], css: [], images: [], fonts: [], data: [], other: [] };
  for (const u of all) out[cls(u)].push(u);
  return out;
}

// ---------------- 技术栈 / WAF 汇总 ----------------
function buildTech(payload, headerReport, windowVars, resources) {
  const map = {};
  const add = (name, category, version, evidence) => {
    if (!name) return;
    const k = name.toLowerCase();
    if (!map[k]) map[k] = { name, category, version: version || null, evidence: [] };
    if (!map[k].version && version) map[k].version = version;
    if (evidence && map[k].evidence.length < 4) map[k].evidence.push(evidence);
  };
  // Server
  if (headerReport.server) {
    for (const s of Fingerprints.SERVER_TECH) if (s.re.test(headerReport.server)) add(s.name, "server", Fingerprints.versionFrom(headerReport.server), "Server: " + headerReport.server);
  }
  if (headerReport.poweredBy) {
    for (const p of Fingerprints.POWERED_BY) if (p.re.test(headerReport.poweredBy)) add(p.name, "runtime", Fingerprints.versionFrom(headerReport.poweredBy), "X-Powered-By: " + headerReport.poweredBy);
  }
  // meta generator
  if (payload.metaGenerator) {
    for (const g of Fingerprints.GENERATOR) if (g.re.test(payload.metaGenerator)) add(g.name, "cms", Fingerprints.versionFrom(payload.metaGenerator), "generator: " + payload.metaGenerator);
  }
  // cookies -> tech
  (headerReport.cookies || []).forEach((ck) => {
    for (const c of Fingerprints.COOKIE_TECH) if (c.re.test(ck.name)) add(c.name, "session", null, "cookie: " + ck.name);
  });
  // resources -> libs
  for (const u of (resources.scripts || []).concat(resources.css || [])) {
    const id = Fingerprints.identifyFromUrl(u);
    if (id) add(id.name, "library", id.version, "resource: " + u.split("?")[0].split("/").slice(-1)[0]);
  }
  // html patterns
  const html = payload.htmlEvidence || "";
  for (const p of Fingerprints.HTML_PATTERNS) if (p.re.test(html)) add(p.name, "framework", p.version ? null : null, "html 特征");
  // window globals
  (windowVars || []).forEach((w) => {
    if (w.weak && (windowVars || []).some((x) => !x.weak && x.name === w.name)) return;
    add(w.name, "framework", w.version, "window." + w.probe);
  });
  return Object.values(map).sort((a, b) => a.category.localeCompare(b.category) || a.name.localeCompare(b.name));
}
function detectWaf(headerReport, html) {
  const pairs = headerReport.raw || [];
  const names = new Set(pairs.map((h) => h.name.toLowerCase()));
  const valMap = {};
  pairs.forEach((h) => {
    (valMap[h.name.toLowerCase()] = valMap[h.name.toLowerCase()] || []).push(h.value);
  });
  const cookies = headerReport.cookies || [];
  const hits = [];
  for (const rule of Fingerprints.WAF_RULES) {
    const ev = [];
    (rule.headers || []).forEach((hd) => {
      if (names.has(hd.n.toLowerCase())) {
        if (!hd.v || (valMap[hd.n.toLowerCase()] || []).some((v) => hd.v.test(v))) ev.push("header:" + hd.n);
      }
    });
    (rule.cookies || []).forEach((cr) => {
      cookies.forEach((ck) => {
        if (cr.test(ck.name)) ev.push("cookie:" + ck.name);
      });
    });
    (rule.html || []).forEach((re) => {
      if (re.test(html)) ev.push("html 特征");
    });
    if (ev.length) hits.push({ name: rule.name, vendor: rule.vendor || "", evidence: Array.from(new Set(ev)).slice(0, 6), note: rule.note || "" });
  }
  return hits;
}

// ---------------- 风险摘要 ----------------
function buildRisks(headerReport, js) {
  const risks = [];
  const push = (level, category, summary) => risks.push({ level, category, summary });
  if (js.findings.some((f) => f.severity === "critical") || js.inlineFindings.some((f) => f.severity === "critical")) push("critical", "JS", "JS/内联脚本中发现严重级密钥线索");
  const hi = js.findings.filter((f) => f.severity === "high").length + js.inlineFindings.filter((f) => f.severity === "high").length;
  if (hi) push("high", "JS", "JS 中高危密钥/凭据线索 " + hi + " 类");
  if (js.sourcemaps.length) push("low", "JS", "存在 " + js.sourcemaps.length + " 个 source map，可还原源码");
  (headerReport.missing || []).forEach((m) => {
    if (m.level === "high") push("high", "响应头", m.header + " 缺失：" + m.advice);
  });
  (headerReport.advisories || []).forEach((a) => {
    if (a.level === "critical" || a.level === "high") push(a.level, "配置", (a.detail || "") + " — " + a.advice);
  });
  const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  return risks.sort((a, b) => order[a.level] - order[b.level]);
}

// ---------------- 主动探测（需用户点击 + 范围内） ----------------
async function runProbes(origin, host, tabId) {
  if (!(await inScope(host))) return { ok: false, error: "out_of_scope" };
  const results = [];
  const probes = SensitiveRules.PATH_PROBES;
  for (let i = 0; i < probes.length; i++) {
    const p = probes[i];
    const url = origin.replace(/\/$/, "") + p.path;
    let status = 0;
    let matched = false;
    let bytes = 0;
    let error = null;
    try {
      const ctrl = new AbortController();
      const to = setTimeout(() => ctrl.abort(), 5000);
      const r = await fetch(url, { method: "GET", credentials: "omit", redirect: "follow", signal: ctrl.signal });
      clearTimeout(to);
      status = r.status;
      let text = "";
      try {
        const buf = await r.text();
        text = buf.slice(0, 20000);
        bytes = buf.length;
      } catch (e) {}
      const low = text.toLowerCase();
      matched = p.keywords.some((k) => low.includes(k.toLowerCase()));
      results.push({ path: p.path, status, bytes, matched: status >= 200 && status < 400 && matched, desc: p.desc, severity: p.severity });
    } catch (e) {
      error = String((e && e.message) || e);
      results.push({ path: p.path, status: 0, bytes: 0, matched: false, error, desc: p.desc, severity: p.severity });
    }
    await new Promise((res) => setTimeout(res, 250)); // 限流，避免压垮目标
  }
  // 统一“主动探测”：依合并技术栈的框架决策，对 Vue/React 站点追加前端路由可达性探测（并入原“梭哈”意图）
  let routes = { applicable: false, reason: "未提供标签页，跳过路由探测" };
  try {
    if (tabId) {
      const tab = await chrome.tabs.get(tabId);
      const ri = await detectRouterAndLive(tabId);
      const tech = self.TechStack.detect({ routerInfo: ri });
      if (tech.decision.enableRouteProbe) routes = await self.ProbeRoutes({ routerInfo: ri, currentUrl: tab.url });
      else routes = { applicable: false, reason: tech.decision.reason };
    }
  } catch (e) {
    routes = { applicable: false, reason: String((e && e.message) || e) };
  }
  return { ok: true, results, routes };
}

// ---------------- 主收集流程 ----------------
async function collect(tabId) {
  let tab;
  try {
    tab = await chrome.tabs.get(tabId);
  } catch (e) {
    return { ok: false, error: "tab-unreadable", hint: "无法读取该标签页，可能在 chrome:// 等受限页。" };
  }
  let host, isHttps;
  try {
    const u = new URL(tab.url);
    host = u.hostname;
    isHttps = u.protocol === "https:";
  } catch (e) {
    return { ok: false, error: "bad-url", hint: "当前页面 URL 不受支持。" };
  }
  if (!(await inScope(host))) {
    return { ok: false, error: "out_of_scope", hint: "该主机不在允许域范围内：请先在弹窗把它加入范围并完成授权。", host };
  }
  const scope = await getScope();
  const settings = await getSettings();

  let payload;
  try {
    payload = await collectDom(tabId);
  } catch (e) {
    return { ok: false, error: "inject-failed", hint: "页面注入失败（" + String((e && e.message) || e) + "）。刷新页面后重试。", host };
  }
  if (!payload || !payload.ok) {
    return { ok: false, error: "collect-empty", hint: (payload && payload.error) || "未采集到页面数据。", host };
  }

  const windowVars = await collectWindowVars(tabId);

  let headerPairs = (headersCache.get(host) && headersCache.get(host).main) || [];
  let headerNote = "";
  if (!headerPairs.length) {
    // fallback：用扩展 fetch 读取可读安全头（注意：Set-Cookie 无法经 JS 读取，Cookie 分析会缺失）
    try {
      const r = await fetch(tab.url, { credentials: "omit", redirect: "follow" });
      const arr = [];
      r.headers.forEach((v, k) => arr.push({ name: k, value: v }));
      headerPairs = arr;
      headerNote = arr.length ? "主文档头来自 fetch 兜底（无法获取 Set-Cookie，Cookie 分析缺失，重新加载页面可补全）。" : "未捕获到主文档响应头，请在装好并授权本插件后刷新目标页面再采集。";
    } catch (e) {
      headerNote = "无法获取主文档响应头：" + String((e && e.message) || e);
    }
  }
  const headerReport = HeaderChecks.analyze(headerPairs, isHttps);

  const resources = buildResources(payload);
  const js = await scanJs(resources.scripts.concat(payload.resourceUrls || []), payload.inlineScripts, host, scope.hosts.map((h) => h.host), settings);
  const links = buildLinks(payload, host);
  const tech = buildTech(payload, headerReport, windowVars, resources);
  const waf = detectWaf(headerReport, payload.htmlEvidence || "");

  const bundle = {
    meta: { collectedAt: Date.now(), url: tab.url, title: payload.title, host, isHttps, inScope: true, scopeAddedAt: (scope.hosts.find((h) => h.host === host) || {}).addedAt || null, headerNote },
    links,
    resources: { scripts: resources.scripts.length, css: resources.css.length, images: resources.images.length, fonts: resources.fonts.length, data: resources.data.length, other: resources.other.length, scriptsList: resources.scripts.slice(0, 200) },
    tech,
    waf,
    headers: headerReport,
    js: { scanned: js.scanned, findings: js.findings, inlineFindings: js.inlineFindings, sourcemaps: js.sourcemaps },
    probes: { performed: false },
    risks: buildRisks(headerReport, js),
  };

  // 只读三能力：路由枚举 / API 端点提取 / 前端安全审计（组装见 lib/collect-extras.js）
  try {
    const routerInfo = await detectRouterAndLive(tabId);
    const extras = self.ComputeExtras({ tab, payload, host, scope, settings, js, routerInfo, links });
    bundle.routes = extras.routes;
    bundle.api = extras.api;
    bundle.security = extras.security;
    if (bundle.links) bundle.links.classified = extras.classified;
    if (extras.riskNote) bundle.risks.unshift(extras.riskNote);
    const tech = self.TechStack.detect({ headerReport, metaGenerator: payload.metaGenerator, resourceUrls: (resources.scripts || []).concat(resources.css || [], resources.data || []), htmlEvidence: payload.htmlEvidence, windowVars, routerInfo });
    bundle.techStack = tech;
  } catch (e) {
    bundle.routes = { error: String((e && e.message) || e) };
  }

  await chrome.storage.local.set({ lastBundle: bundle });
  return { ok: true, bundle };
}

// ---------------- 消息路由 ----------------
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (!msg || !msg.type) return;

  if (msg.type === "RECON_DOM_RESULT") {
    if (pendingDom) pendingDom.resolve(msg.payload);
    return; // content 消息无需 response
  }

  switch (msg.type) {
    case "GET_STATE": {
      (async () => {
        const scope = await getScope();
        const settings = await getSettings();
        const last = (await chrome.storage.local.get("lastBundle")).lastBundle || null;
        sendResponse({ ok: true, scope, settings, inScope: msg.host ? scope.hosts.some((h) => h.host === msg.host) : false, hasCache: msg.host ? !!(headersCache.get(msg.host) && headersCache.get(msg.host).main.length) : false, lastBundle: last });
      })();
      return true;
    }
    case "ADD_HOST": {
      (async () => {
        await addHost(msg.host, msg.origin, msg.note);
        sendResponse({ ok: true });
      })();
      return true;
    }
    case "REMOVE_HOST": {
      (async () => {
        const s = await removeHost(msg.host);
        // 同时撤销 host 权限（撤销在 popup 端做手势请求；这里兜底存储）
        try {
          if (msg.origin) await chrome.permissions.remove({ origins: [msg.origin] });
        } catch (e) {}
        sendResponse({ ok: true, scope: s });
      })();
      return true;
    }
    case "SET_SETTINGS": {
      (async () => {
        const cur = await getSettings();
        await chrome.storage.local.set({ settings: Object.assign(cur, msg.patch || {}) });
        sendResponse({ ok: true });
      })();
      return true;
    }
    case "COLLECT": {
      collect(msg.tabId).then((r) => sendResponse(r)).catch((e) => sendResponse({ ok: false, error: "exception", hint: String((e && e.message) || e) }));
      return true;
    }
    case "RUN_PROBES": {
      (async () => {
        const res = await runProbes(msg.origin, msg.host, msg.tabId);
        if (res.ok) {
          const { lastBundle } = await chrome.storage.local.get("lastBundle");
          if (lastBundle) {
            lastBundle.probes = { performed: true, results: res.results, routes: res.routes };
            await chrome.storage.local.set({ lastBundle });
          }
        }
        sendResponse(res);
      })();
      return true;
    }
    case "OPEN_RESULT": {
      chrome.tabs.create({ url: chrome.runtime.getURL("result/result.html") });
      sendResponse({ ok: true });
      return;
    }
  }
});

// 安装提示
chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.local.get("settings").then((d) => {
    if (!d.settings) chrome.storage.local.set({ settings: DEFAULT_SETTINGS });
  });
});

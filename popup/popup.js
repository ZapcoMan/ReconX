/* global chrome */
(async function () {
  const $ = (id) => document.getElementById(id);
  const SEV_CN = { critical: "严重", high: "高危", medium: "中危", low: "低危", info: "提示" };

  let tab = null;
  let url = null;
  let host = "";
  let originPattern = "";
  let originBase = "";
  let state = { scope: { hosts: [] }, settings: {}, inScope: false, lastBundle: null };
  let restricted = false;

  function setStatus(text, kind) {
    const el = $("status");
    el.textContent = text || "";
    el.className = "status" + (kind ? " " + kind : "");
  }
  function show(el, on) {
    el.classList.toggle("hidden", !on);
  }

  async function loadState() {
    const resp = await chrome.runtime.sendMessage({ type: "GET_STATE", host });
    if (resp && resp.ok) state = resp;
  }

  function renderScope() {
    const el = $("scope");
    el.replaceChildren();
    if (restricted) {
      el.textContent = "此页面（受限/内部页）无法采集。请在普通 http(s) 网页使用。";
      el.classList.add("warn");
      return;
    }
    const inS = state.inScope;
    el.classList.toggle("ok", inS);
    el.classList.toggle("warn", !inS);
    const tag = document.createElement("span");
    tag.textContent = inS ? "✓ 在允许域范围内" : "⚠ 不在范围内";
    el.appendChild(tag);
    if (!inS) {
      const note = document.createElement("span");
      note.className = "muted";
      note.textContent = " 请先授权你确有测试许可的站点。";
      el.appendChild(note);
    }
    show($("authorize"), !inS);
    show($("collect"), inS);
    show($("probe"), inS);
  }

  function chip(label, value, cls) {
    const c = document.createElement("div");
    c.className = "chip" + (cls ? " " + cls : "");
    const b = document.createElement("b");
    b.textContent = value;
    c.appendChild(b);
    c.appendChild(document.createTextNode(" " + label));
    return c;
  }

  function renderOverview(bundle) {
    const ov = $("overview");
    ov.replaceChildren();
    show(ov, true);
    const rows = document.createElement("div");
    rows.className = "chips";
    rows.appendChild(chip("技术栈", (bundle.tech || []).length));
    rows.appendChild(chip("WAF 线索", (bundle.waf || []).length, (bundle.waf || []).length ? "blue" : ""));
    const jsHigh = (bundle.js.findings || []).concat(bundle.js.inlineFindings || []).filter((f) => f.severity === "high" || f.severity === "critical").length;
    rows.appendChild(chip("JS 高危", jsHigh, jsHigh ? "red" : ""));
    rows.appendChild(chip("端点", bundle.links.total, ""));
    rows.appendChild(chip("同源", bundle.links.sameOriginCount, ""));
    rows.appendChild(chip("缺失头", (bundle.headers.missing || []).length, (bundle.headers.missing || []).length ? "amber" : ""));
    ov.appendChild(rows);

    if (bundle.risks && bundle.risks.length) {
      const list = document.createElement("ul");
      list.className = "risks";
      bundle.risks.slice(0, 8).forEach((r) => {
        const li = document.createElement("li");
        const s = document.createElement("span");
        s.className = "lvl " + r.level;
        s.textContent = SEV_CN[r.level] || r.level;
        li.appendChild(s);
        li.appendChild(document.createTextNode(" " + r.category + "： " + r.summary));
        list.appendChild(li);
      });
      ov.appendChild(list);
    }
    if (bundle.meta.headerNote) {
      const n = document.createElement("div");
      n.className = "muted";
      n.textContent = bundle.meta.headerNote;
      ov.appendChild(n);
    }
    const open = document.createElement("button");
    open.className = "ghost small";
    open.textContent = "在详情窗口查看全部 →";
    open.addEventListener("click", () => chrome.runtime.sendMessage({ type: "OPEN_RESULT" }));
    ov.appendChild(open);
  }

  // 初始化 tab 信息
  const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  tab = tabs[0];
  if (tab && tab.url) {
    try {
      url = new URL(tab.url);
      host = url.hostname;
      originPattern = url.protocol + "//" + url.host + "/*";
      originBase = url.origin;
      if (!/^https?:$/.test(url.protocol)) {
        restricted = true;
      }
    } catch (e) {
      restricted = true;
    }
  } else {
    restricted = true;
  }
  $("host").textContent = host || "(无)";

  await loadState();
  renderScope();
  if (state.lastBundle && state.lastBundle.meta && state.lastBundle.meta.host === host) {
    renderOverview(state.lastBundle);
  }

  // 授权（用户手势在本按钮内）
  $("authorize").addEventListener("click", async () => {
    if (restricted) return;
    setStatus("请求 host 权限中…");
    const granted = await chrome.permissions.request({ origins: [originPattern] });
    if (!granted) {
      setStatus("未授予权限，无法采集该站点。", "warn");
      return;
    }
    await chrome.runtime.sendMessage({ type: "ADD_HOST", host, origin: originPattern, note: "popup 授权" });
    await loadState();
    renderScope();
    setStatus("已加入范围，可开始收集。", "ok");
  });

  // 收集
  $("collect").addEventListener("click", async () => {
    if (!tab) return;
    setStatus("采集中…");
    const r = await chrome.runtime.sendMessage({ type: "COLLECT", tabId: tab.id });
    if (r && r.ok) {
      state.lastBundle = r.bundle;
      renderOverview(r.bundle);
      setStatus("采集完成。", "ok");
    } else {
      setStatus((r && (r.hint || r.error)) || "采集失败", "warn");
    }
  });

  // 主动探测
  $("probe").addEventListener("click", async () => {
    if (!state.inScope) {
      setStatus("请先授权该站点。", "warn");
      return;
    }
    if (!state.settings.activeProbe) {
      setStatus("主动探测默认关闭。请在“设置”里开启“启用主动路径探测”。", "warn");
      return;
    }
    if (!state.lastBundle) {
      setStatus("请先“开始收集”，再做主动探测。", "warn");
      return;
    }
    setStatus("主动探测敏感路径（串行限流）…");
    const r = await chrome.runtime.sendMessage({ type: "RUN_PROBES", origin: originBase, host });
    if (r && r.ok) {
      const hits = (r.results || []).filter((x) => x.matched);
      setStatus("探测完成：命中 " + hits.length + " 个路径（详见窗口）。", hits.length ? "warn" : "ok");
      await loadState();
      if (state.lastBundle && state.lastBundle.probes && state.lastBundle.probes.results) renderOverview(state.lastBundle);
    } else {
      setStatus("探测失败：" + ((r && r.error) || ""), "warn");
    }
  });

  // 详情窗口
  $("result").addEventListener("click", () => chrome.runtime.sendMessage({ type: "OPEN_RESULT" }));

  // 导出
  document.querySelectorAll(".exports [data-fmt]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const bundle = state.lastBundle;
      if (!bundle) {
        setStatus("还没有采集结果，请先收集。", "warn");
        return;
      }
      const r = await chrome.runtime.sendMessage({ type: "EXPORT", format: btn.getAttribute("data-fmt"), bundle });
      setStatus(r && r.ok ? "已生成下载：" + r.filename : "导出失败", r && r.ok ? "ok" : "warn");
    });
  });

  $("openOptions").addEventListener("click", (e) => {
    e.preventDefault();
    chrome.runtime.openOptionsPage();
  });
})();

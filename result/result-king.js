/* global chrome */
// 结果页扩展：技术栈 / 路由 / API / 审计 摘要面板（与原始JSON、主动探测同级；切换时隐藏 .raw）。
(async function () {
  const { lastBundle: b } = await chrome.storage.local.get("lastBundle");
  const nav = document.getElementById("tabs"), panels = document.getElementById("panels");
  if (!b || !nav || !panels) return;

  const ts = b.techStack || {}, items = ts.items || [], fw = ts.framework || {}, dec = ts.decision || {};
  const rt = b.routes || {}, api = b.api || {}, sc = b.security || {}, sm = sc.summary || {};

  const p = document.createElement("section"); p.className = "panel"; p.style.display = "none";

  const summary = [
    "框架判定: " + (fw.vue ? "Vue " : "") + (fw.react ? "React " : "") + (fw.spa ? "SPA" : "非SPA") + (fw.routerDetected ? " / 路由:" + (fw.routerKind || "") : " / 未检出路由"),
    "主动探测决策: " + (dec.enableRouteProbe ? "启用前端路由探测" : "不启用") + " — " + (dec.reason || ""),
    "技术栈条目: " + items.length + "  |  路由: " + (rt.allRoutesCount || 0) + (rt.anchorFallback ? "(锚点兜底)" : "") + "  |  API 实际/静态/未调用: " + (api.liveApisCount || 0) + "/" + (api.staticApisCount || 0) + "/" + (api.uncalledCount || 0),
    "安全审计整体: " + (sm.overallRisk || "-") + "  严重" + (sm.criticalCount || 0) + "  高" + (sm.highCount || 0) + "  未保护路由线索" + (sm.unprotectedRoutes || 0),
  ].join("\n");
  const pre = document.createElement("pre"); pre.textContent = summary; p.appendChild(pre);

  const h = document.createElement("h3"); h.textContent = "技术栈（按置信度）"; p.appendChild(h);
  const ul = document.createElement("ul"); ul.className = "qlist";
  items.slice(0, 50).forEach(function (it) {
    const li = document.createElement("li");
    li.textContent = it.name + " [" + it.category + "] " + (it.version || "") + "  " + (it.confidence || 0) + "%  — " + (it.evidence || []).join("; ");
    ul.appendChild(li);
  });
  p.appendChild(ul);

  if (items.length === 0) { const e = document.createElement("p"); e.className = "muted"; e.textContent = "未采集到技术栈（请先收集）"; p.appendChild(e); }

  panels.appendChild(p);
  const btn = document.createElement("button"); btn.className = "tab"; btn.textContent = "技术栈/路由/API/审计";
  btn.addEventListener("click", function () {
    nav.querySelectorAll(".tab").forEach(function (x) { x.classList.remove("active"); });
    btn.classList.add("active");
    panels.querySelectorAll(".panel").forEach(function (x) { x.style.display = "none"; });
    const raw = panels.querySelector(".raw"); if (raw) raw.style.display = "none";
    p.style.display = "block";
  });
  nav.appendChild(btn);
})();

/* global chrome, UrlClassify, AssetSearch, DorkLibrary */
// result 页扩展面板：Dork 查询生成 + 资产测绘查询生成 + 敏感端点分级。
// 独立于 result.js，仅追加一个 tab；所有动作“只生成查询”，不自动开标签页。
(async function () {
  const el = (tag, cls, ...kids) => {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    for (const k of kids) e.append(k && k.nodeType ? k : document.createTextNode(String(k == null ? "" : k)));
    return e;
  };
  const { lastBundle: bundle } = await chrome.storage.local.get("lastBundle");
  const defaultHost = bundle && bundle.meta ? bundle.meta.host : "";

  const nav = document.getElementById("tabs");
  const panels = document.getElementById("panels");
  if (!nav || !panels) return;

  // ---- 面板容器 ----
  const panel = el("section", "panel");
  panel.style.display = "none";
  panel.append(el("h2", null, "Dork 与资产测绘（仅生成查询）"));
  panel.append(el("p", "muted", "以下查询在你确认目标处于授权范围内后再自行打开；本工具不会自动跳转。"));

  // 公共：目标域 + 引擎
  const row = el("div", "row2");
  const domainIn = el("input", null);
  domainIn.type = "text";
  domainIn.placeholder = "目标域名，如 example.com";
  domainIn.value = defaultHost;
  const engSel = el("select");
  ["google", "bing", "baidu"].forEach((g) => engSel.append(el("option", null, g)));
  row.append(el("label", null, "目标域 ", domainIn), el("label", null, "引擎 ", engSel));

  function makeResultList() {
    const wrap = el("div", "qresults");
    return wrap;
  }
  function copyBtn(text) {
    const b = el("button", "tiny", "复制");
    b.addEventListener("click", () => navigator.clipboard && navigator.clipboard.writeText(text));
    return b;
  }
  function queryRow(item) {
    const a = el("a", null, "打开");
    a.href = item.url;
    a.target = "_blank";
    a.rel = "noreferrer";
    const li = el("li", null, el("span", "lvl " + (item.risk || "info"), item.risk || ""), el("b", null, " " + item.name + "  "), el("code", "mono", item.query), " ", a, " ", copyBtn(item.query));
    return li;
  }

  // ---- Dork 区块 ----
  panel.append(el("h3", null, "① Dork 语法库"));
  const pkgSel = el("select");
  pkgSel.append(el("option", null, "通用 recon"), el("option", null, "教育行业预设"));
  const highOnly = el("input");
  highOnly.type = "checkbox";
  const genBtn = el("button", "primary", "生成 Dork 查询");
  const dorkRow = el("div", "row2");
  dorkRow.append(pkgSel, el("label", "inline", highOnly, " 仅高危"), genBtn);
  panel.append(row);
  panel.append(dorkRow);
  const dorkOut = makeResultList();
  const dorkUl = el("ul", "qlist");
  dorkOut.append(dorkUl);
  panel.append(dorkOut);

  genBtn.addEventListener("click", () => {
    dorkUl.replaceChildren();
    const domain = domainIn.value.trim();
    if (!domain) {
      dorkUl.append(el("li", "muted", "请先填写目标域"));
      return;
    }
    const pkg = pkgSel.selectedIndex === 1 ? "edu" : "general";
    let entries = DorkLibrary.listPackage(pkg);
    if (highOnly.checked) entries = entries.filter((e) => e.risk === "high");
    const items = DorkLibrary.toSearchItems(entries, domain, engSel.value);
    dorkUl.append(el("li", "muted", "共 " + items.length + " 条（" + pkg + " / " + engSel.value + "）"));
    items.forEach((it) => dorkUl.append(queryRow(it)));
  });

  // ---- 资产测绘区块 ----
  panel.append(el("h3", null, "② 资产测绘查询"));
  const modeSel = el("select");
  (AssetSearch.ASSET_MODES || []).forEach((m) => {
    const o = el("option", null, m.name + " - " + m.hint);
    o.dataset.mode = m.id;
    modeSel.append(o);
  });
  const kwIn = el("input", null);
  kwIn.type = "text";
  kwIn.placeholder = "组件指纹/备案主体时填关键词，如 Nacos / 某某大学";
  const assetBtn = el("button", "primary", "生成测绘查询");
  const aRow = el("div", "row2");
  aRow.append(modeSel, kwIn, assetBtn);
  panel.append(aRow);
  const assetUl = el("ul", "qlist");
  panel.append(assetUl);

  assetBtn.addEventListener("click", () => {
    assetUl.replaceChildren();
    const domain = domainIn.value.trim();
    const mode = modeSel.selectedOptions[0] ? modeSel.selectedOptions[0].dataset.mode : "domain";
    if (!domain) {
      assetUl.append(el("li", "muted", "请先填写目标域"));
      return;
    }
    const target = { domain, keyword: kwIn.value.trim() };
    let n = 0;
    AssetSearch.PLATFORMS.forEach((p) => {
      const r = AssetSearch.buildAsset(p.id, mode, target);
      if (!r) return;
      n++;
      const a = el("a", null, "打开");
      a.href = r.url;
      a.target = "_blank";
      a.rel = "noreferrer";
      assetUl.append(el("li", null, el("b", null, p.name + "  "), el("code", "mono", r.query), " ", a, " ", copyBtn(r.query)));
    });
    (AssetSearch.EXTRA_SOURCES || []).forEach((s) => {
      n++;
      const a = el("a", null, "打开");
      a.href = s.build(domain);
      a.target = "_blank";
      a.rel = "noreferrer";
      assetUl.append(el("li", null, el("b", null, s.name + "  "), el("span", "muted", s.hint + " "), a, " ", copyBtn(a.href)));
    });
    assetUl.append(el("li", "muted", "共 " + n + " 条查询"));
  });

  // ---- 敏感端点分级（来自本次采集） ----
  if (bundle && bundle.links && bundle.links.endpoints) {
    panel.append(el("h3", null, "③ 本次采集的敏感端点（按分级）"));
    const ranked = UrlClassify.rankItems(bundle.links.endpoints).filter((e) => e.level);
    const ul = el("ul", "qlist");
    if (!ranked.length) ul.append(el("li", "muted", "未发现敏感特征端点"));
    ranked.slice(0, 200).forEach((e) => {
      const a = el("a", null, "打开");
      a.href = e.url;
      a.target = "_blank";
      a.rel = "noreferrer";
      ul.append(el("li", null, el("span", "lvl " + (e.level === "critical" ? "critical" : e.level === "warn" ? "high" : "info"), e.level), " ", el("code", "mono", e.url), " ", el("span", "muted", " [" + (e.labels || []).join("/") + "] "), a, " ", copyBtn(e.url)));
    });
    panel.append(ul);
  }

  // ---- 挂到 tab ----
  panels.append(panel);
  const tabBtn = el("button", "tab", "Dork 与测绘");
  function showPanel() {
    nav.querySelectorAll(".tab").forEach((b) => b.classList.remove("active"));
    tabBtn.classList.add("active");
    panels.querySelectorAll(".panel").forEach((p) => (p.style.display = "none"));
    const raw = panels.querySelector(".raw");
    if (raw) raw.style.display = "none";
    panel.style.display = "block";
  }
  tabBtn.addEventListener("click", showPanel);
  nav.append(tabBtn);
})();

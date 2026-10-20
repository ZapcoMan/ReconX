/* content-dom.js — 由 background 通过 chrome.scripting.executeScript({files}) 注入到 ISOLATED world。
 * 采集后通过 chrome.runtime.sendMessage 把结构化 payload 回传给 background。
 * 运行前提：该 tab 的目标 host 已在允许域范围内（background 已校验并授予 host 权限）。
 */
(function () {
  try {
    if (window.__RECON_DOM_INJECTED__) return; // 防重复注入
    window.__RECON_DOM_INJECTED__ = true;

    const txt = (s, n) => String(s || "").replace(/\s+/g, " ").trim().slice(0, n || 120);
    const qsa = (sel) => Array.prototype.slice.call(document.querySelectorAll(sel));

    const payload = {
      ok: true,
      url: location.href,
      title: document.title || "",
      metaGenerator: (() => {
        const g = document.querySelector('meta[name="generator"], meta[name="Generator"]');
        return g ? g.getAttribute("content") : null;
      })(),
      anchors: qsa("a[href]").map((a) => ({ href: a.href, rel: a.getAttribute("rel") || "", text: txt(a.textContent, 80) })),
      scripts: qsa("script[src]").map((s) => s.src),
      inlineScripts: qsa("script:not([src])")
        .map((s) => s.textContent)
        .filter(Boolean)
        .join("\n/* ==== inline ==== */\n")
        .slice(0, 200000),
      links: qsa("link[href]").map((l) => ({ rel: l.getAttribute("rel") || "", href: l.href })),
      styles: qsa("[style]").slice(0, 200).map((e) => txt(e.getAttribute("style"), 160)),
      images: qsa("img[src]").map((i) => i.src).slice(0, 800),
      iframes: qsa("iframe[src]").map((i) => i.src),
      objectEmbed: qsa("object[data],embed[src]").map((i) => i.data || i.src),
      forms: qsa("form").map((f) => ({
        action: f.getAttribute("action") || f.action,
        method: (f.getAttribute("method") || f.method || "GET").toUpperCase(),
        enctype: f.getAttribute("enctype") || null,
        fields: Array.prototype.slice.call(f.elements).map((e) => ({
          name: e.name || "",
          type: e.type || e.tagName.toLowerCase(),
          tag: e.tagName,
          hidden: e.type === "hidden" || e.hidden === true,
        })),
      })),
      buttons: qsa("button[data-action],input[type=submit]").map((b) => b.getAttribute("data-action") || txt(b.value || b.textContent, 40)),
      resourceUrls: performance.getEntriesByType("resource").map((r) => r.name),
      // 用于 HTML_PATTERNS 匹配的证据片段（截断，避免回传整页）
      htmlEvidence: (document.head ? document.head.innerHTML : "").slice(0, 8000) + "\n" + (document.body ? document.body.outerHTML.slice(0, 4000) : ""),
      // 疑似接口端点：内联脚本里匹配 /api/... 之类相对路径
      inlineEndpoints: (() => {
        const src = qsa("script:not([src])").map((s) => s.textContent).join("\n");
        const out = [];
        const re = /(["'`])(\/(?:api|v[0-9]|graphql|rest|admin|internal)[\/][^"'`\s]*)\1/gi;
        let m;
        while ((m = re.exec(src)) && out.length < 200) out.push(m[2]);
        return out;
      })(),
    };

    chrome.runtime.sendMessage({ type: "RECON_DOM_RESULT", payload });
  } catch (err) {
    try {
      chrome.runtime.sendMessage({ type: "RECON_DOM_RESULT", payload: { ok: false, error: String(err && err.message ? err.message : err) } });
    } catch (_) {
      /* 扩展上下文失效（如重载），忽略 */
    }
  }
})();

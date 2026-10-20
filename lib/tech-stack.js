/* global self, Fingerprints */
// Wappalyzer 式技术栈合并探测：交叉多路信号输出带置信度技术栈，并判定是否 Vue/React SPA（决定是否前端路由探测）。
// 合并 ReconX lib/fingerprints.js 被动指纹 + King-CrackX router-probe 框架/路由结构。
(function () {
  const T = {};
  function ver(s) { if (!s) return null; const m = String(s).match(/v?(\d+\.\d+(?:\.\d+)?)/); return m ? m[1] : null; }

  // ctx: { headerReport, metaGenerator, resourceUrls[], htmlEvidence, windowVars[], routerInfo }
  T.detect = function (ctx) {
    ctx = ctx || {};
    const hr = ctx.headerReport || {};
    const router = ctx.routerInfo || {};
    const map = {};
    const add = (name, category, version, evidence, conf) => {
      if (!name) return;
      const k = String(name).toLowerCase();
      if (!map[k]) map[k] = { name: name, category: category, version: version || null, confidence: 0, evidence: [] };
      const it = map[k];
      if (!it.version && version) it.version = version;
      it.confidence = Math.min(100, it.confidence + (conf || 50));
      if (evidence && it.evidence.length < 6 && it.evidence.indexOf(evidence) < 0) it.evidence.push(evidence);
    };

    if (hr.server) for (const s of Fingerprints.SERVER_TECH) if (s.re.test(hr.server)) add(s.name, "server", ver(hr.server), "Server: " + hr.server, 70);
    if (hr.poweredBy) for (const p of Fingerprints.POWERED_BY) if (p.re.test(hr.poweredBy)) add(p.name, "language", ver(hr.poweredBy), "X-Powered-By: " + hr.poweredBy, 70);
    (hr.cookies || []).forEach((ck) => { for (const c of Fingerprints.COOKIE_TECH) if (c.re.test(ck.name)) add(c.name, "framework", null, "cookie: " + ck.name, 55); });
    if (ctx.metaGenerator) for (const g of Fingerprints.GENERATOR) if (g.re.test(ctx.metaGenerator)) add(g.name, "cms", ver(ctx.metaGenerator), "generator: " + ctx.metaGenerator, 80);
    (ctx.resourceUrls || []).forEach((u) => { const id = Fingerprints.identifyFromUrl(u); if (id) add(id.name, "library", id.version, "resource: " + String(u).split("?")[0].split("/").slice(-1)[0], 60); });
    const html = ctx.htmlEvidence || "";
    for (const p of Fingerprints.HTML_PATTERNS) if (p.re.test(html)) add(p.name, "framework", null, "html", 55);
    (ctx.windowVars || []).forEach((w) => { add(w.name, w.weak ? "library" : "framework", w.version, "window." + w.probe, w.weak ? 25 : 60); });

    let isVue = false, isReact = false;
    if (router.framework === "vue") {
      isVue = true;
      add("Vue" + (String(router.vueVersion || "").charAt(0) === "2" ? " 2" : ""), "framework", router.vueVersion, "router-probe", 90);
      if (router.routerDetected) add("Vue Router", "routing", null, "router-probe", 85);
    }
    if (router.framework === "react") {
      isReact = true;
      add("React", "framework", router.reactVersion, "router-probe", 80);
      if (router.routerKind) add(String(router.routerKind).indexOf("Next") >= 0 ? "Next.js" : "React Router", "routing", router.reactRouterVersion, "router-probe", 85);
      if (router.next) add("Next.js", "framework", null, "__NEXT_DATA__", 85);
    }
    const wn = (ctx.windowVars || []).map((w) => w.name).join(" ").toLowerCase();
    if (!isVue && /vue/.test(wn)) isVue = true;
    if (!isReact && (/react/.test(wn) || router.next)) isReact = true;

    const items = Object.values(map).sort((a, b) => b.confidence - a.confidence || String(a.name).localeCompare(String(b.name)));

    let enable = false, reason;
    if (router.routerDetected) { enable = true; reason = "检测到前端路由(" + (router.routerKind || "SPA") + ")，启用路由探测"; }
    else if (isVue || isReact) { enable = true; reason = "技术栈判定 " + (isVue && isReact ? "Vue/React" : isVue ? "Vue" : "React") + " SPA，启用路由探测"; }
    else reason = "未判定为 Vue/React SPA，跳过路由探测";

    return {
      items: items,
      framework: { vue: isVue, react: isReact, spa: isVue || isReact, routerDetected: !!router.routerDetected, routerKind: router.routerKind || null, vueVersion: router.vueVersion || null, reactVersion: router.reactVersion || null, next: !!router.next },
      decision: { enableRouteProbe: enable, reason: reason },
    };
  };

  self.TechStack = T;
})();

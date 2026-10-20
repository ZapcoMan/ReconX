/* global self */
// 只读框架/路由探测：注入到页面 MAIN world 执行（chrome.scripting.executeScript({func: ROUTER_PROBE})）。
// 仅读取 Vue Router / React Router / Next.js 的路由结构与 performance 时间线，返回可序列化结果。
// 不做任何 router 接管、守卫清除或 meta 改写（绕过鉴权的能力被安全护栏禁止，故不实现）。
self.ROUTER_PROBE = function () {
  function safeMeta(m) {
    if (!m || typeof m !== "object") return {};
    var o = {};
    for (var k in m) {
      try {
        var v = m[k];
        var t = typeof v;
        if (t === "string" || t === "number" || t === "boolean") o[k] = v;
        else if (Array.isArray(v)) o[k] = v.map(function (z) { return typeof z === "string" || typeof z === "number" || typeof z === "boolean" ? z : null; }).filter(function (z) { return z !== null; });
        else if (v && t === "object" && v.constructor === Object) o[k] = safeMeta(v);
      } catch (e) {}
    }
    return o;
  }
  function joinBase(base, p) {
    if (!p) return p;
    if (p.charAt(0) === "/") return p;
    return (base && base !== "/" ? base.replace(/\/$/, "") + "/" : "") + p;
  }
  function flattenVue(routes, base) {
    var out = [];
    (routes || []).forEach(function (r) {
      if (!r || typeof r !== "object") return;
      var p = joinBase(base, r.path);
      out.push({ path: p || "/", name: r.name || "", meta: safeMeta(r.meta) });
      if (Array.isArray(r.children)) out.push.apply(out, flattenVue(r.children, p && p.charAt(0) === "/" ? p : base));
    });
    return out;
  }
  function flattenRR(routes, base) {
    var out = [];
    (routes || []).forEach(function (r) {
      if (!r || typeof r !== "object") return;
      var p = (r.index != null || r.path == null) ? (base || "/") : joinBase(base, r.path);
      out.push({ path: p, name: r.name || "", meta: safeMeta(r.handle || r) });
      if (Array.isArray(r.children)) out.push.apply(out, flattenRR(r.children, p));
    });
    return out;
  }

  var r = { framework: null, vueVersion: null, reactVersion: null, reactRouterVersion: null, next: false, routerDetected: false, routerKind: null, allRoutes: [], routerBase: null, perf: [], anchorLinks: [] };
  try { r.perf = performance.getEntriesByType("resource").map(function (e) { return { name: e.name, initiatorType: e.initiatorType }; }); } catch (e) {}
  try { r.anchorLinks = Array.prototype.slice.call(document.querySelectorAll("a[href]")).map(function (a) { return a.href; }); } catch (e) {}

  // ---- Vue ----
  var vueApp = null, vue2 = null;
  var guess = document.querySelector("#app") || document.querySelector("[data-v-app]");
  if (guess && guess.__vue_app__) vueApp = guess.__vue_app__;
  else if (guess && guess.__vue__) vue2 = guess.__vue__;
  else {
    var nodes = document.getElementsByTagName("*");
    var lim = Math.min(nodes.length, 3000);
    for (var i = 0; i < lim; i++) {
      var n = nodes[i];
      if (n.__vue_app__) { vueApp = n.__vue_app__; break; }
      if (n.__vue__) { vue2 = n.__vue__; break; }
    }
  }
  if (vueApp) {
    r.framework = "vue";
    try { r.vueVersion = vueApp.version || "3"; } catch (e) { r.vueVersion = "3"; }
    var router = null;
    try { router = vueApp.config && vueApp.config.globalProperties && vueApp.config.globalProperties.$router; } catch (e) {}
    try { if (!router && vueApp._instance) router = vueApp._instance.appContext.config.globalProperties.$router; } catch (e) {}
    if (router) {
      r.routerDetected = true;
      r.routerKind = "VueRouter";
      try { r.routerBase = (router.options && router.options.base) || router.base || null; } catch (e) {}
      try { if (typeof router.getRoutes === "function") r.allRoutes = router.getRoutes().map(function (x) { return { path: x.path, name: x.name || "", meta: safeMeta(x.meta) }; }); } catch (e) {}
      if (!r.allRoutes.length) { try { r.allRoutes = flattenVue(router.options && router.options.routes, (router.options && router.options.base) || "/"); } catch (e) {} }
    }
  } else if (vue2) {
    r.framework = "vue";
    r.vueVersion = "2";
    var router2 = vue2.$router || (vue2.$root && vue2.$root.$router);
    if (router2) {
      r.routerDetected = true;
      r.routerKind = "VueRouter";
      try { r.routerBase = router2.options && router2.options.base; } catch (e) {}
      try { r.allRoutes = flattenVue(router2.options && router2.options.routes, (router2.options && router2.options.base) || "/"); } catch (e) {}
    }
  }

  // ---- React / Next ----
  if (!r.framework) {
    if (window.__NEXT_DATA__) { r.framework = "react"; r.next = true; }
    else if (window.React || window.__REACT_DEVTOOLS_GLOBAL_HOOK__) { r.framework = "react"; }
    if (window.React && window.React.version) r.reactVersion = window.React.version;

    function findKey(el, prefix) {
      for (var k in el) if (k.indexOf(prefix) === 0) return el[k];
      return null;
    }
    var roots = [];
    var appEl = document.getElementById("root") || document.getElementById("app") || (document.body && document.body.firstElementChild);
    if (appEl) {
      var c = findKey(appEl, "__reactContainer");
      if (c) roots.push(c.current || c);
      var f = findKey(appEl, "__reactFiber");
      while (f && f.return) f = f.return;
      if (f) roots.push(f);
    }
    if (appEl && appEl._reactRootContainer) { try { roots.push(appEl._reactRootContainer._internalRoot.current); } catch (e) {} }
    var seen = new Set(), q = roots.slice(), scanned = 0, foundRR = null;
    while (q.length && scanned < 12000) {
      var node = q.shift();
      scanned++;
      if (!node || typeof node !== "object" || seen.has(node)) continue;
      seen.add(node);
      var cand = [];
      try {
        if (node.memoizedProps) { cand.push(node.memoizedProps.router, node.memoizedProps.__router, node.memoizedProps.value && node.memoizedProps.value.router); }
        if (node.stateNode && node.stateNode.router) cand.push(node.stateNode.router);
        var hk = node.memoizedState, g = 0;
        while (hk && g < 60) { cand.push(hk.memoizedState && hk.memoizedState.router); hk = hk.next; g++; }
      } catch (e) {}
      for (var ci = 0; ci < cand.length; ci++) {
        var o = cand[ci];
        if (o && typeof o === "object" && (Array.isArray(o.routes) || (o.state && (o.state.location || o.state.matches)))) { foundRR = o; break; }
      }
      if (foundRR) break;
      if (node.child) q.push(node.child);
      if (node.sibling) q.push(node.sibling);
    }
    if (foundRR) {
      r.routerDetected = true;
      r.routerKind = r.next ? "Next/React" : "React Router";
      try {
        if (Array.isArray(foundRR.routes)) r.allRoutes = flattenRR(foundRR.routes, "/");
        else if (foundRR.state && Array.isArray(foundRR.state.matches)) r.allRoutes = foundRR.state.matches.map(function (m) { return { path: (m.route && m.route.path) || m.pathname || "/", name: (m.route && m.route.id) || "", meta: safeMeta(m.route && m.route.handle) }; });
        r.reactRouterVersion = foundRR.future ? "v7" : "v6";
      } catch (e) {}
      if (r.next && window.__NEXT_DATA__ && window.__NEXT_DATA__.page) {
        r.allRoutes.push({ path: window.__NEXT_DATA__.page, name: "next-page", meta: {} });
      }
    }
  }
  return r;
};

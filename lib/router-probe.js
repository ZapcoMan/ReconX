/* global self */
// 只读框架/路由探测：注入到页面 MAIN world 执行（chrome.scripting.executeScript({func: ROUTER_PROBE})）。
// 与 King-CrackX detector 的「只读探测深度」对齐：精确版本号、路由枚举回退链、页面链接基础路径推断。
// 全程只读取结构，不改动页面任何对象；返回纯数据供扩展侧消费。
self.ROUTER_PROBE = function () {
  function hasOwn(o, k) { return Object.prototype.hasOwnProperty.call(o, k); }

  // 浅清洗 meta：只保留可序列化的原始值，避免循环引用与不可克隆对象
  function safeMeta(m) {
    if (!m || typeof m !== "object") return {};
    var o = {};
    for (var k in m) {
      if (!hasOwn(m, k)) continue;
      try {
        var v = m[k], t = typeof v;
        if (t === "string" || t === "number" || t === "boolean") o[k] = v;
        else if (Array.isArray(v)) {
          o[k] = v.filter(function (z) { var tz = typeof z; return tz === "string" || tz === "number" || tz === "boolean"; });
        } else if (v && t === "object" && v.constructor === Object) {
          var flat = {};
          for (var kk in v) { if (hasOwn(v, kk) && (typeof v[kk] === "string" || typeof v[kk] === "number" || typeof v[kk] === "boolean")) flat[kk] = v[kk]; }
          o[k] = flat;
        }
      } catch (e) {}
    }
    return o;
  }

  // 父子路径拼接（Vue Router 嵌套语义：子路径以 / 开头视为绝对路径）
  function joinPath(base, path) {
    if (!path) return base || "/";
    if (path.charAt(0) === "/") return path;
    if (!base || base === "/") return "/" + path;
    return (base.charAt(base.length - 1) === "/" ? base.slice(0, -1) : base) + "/" + path;
  }

  // 在元素上按前缀查找属性名（React 内部标记带随机后缀，只能前缀匹配；返回键名，供 el[key] 取值）
  function findKeyByPrefix(el, prefix) {
    for (var k in el) { if (k.indexOf(prefix) === 0) return k; }
    return null;
  }

  // ===== Vue =====

  // 广度优先定位 Vue 根实例（命中 __vue_app__ / __vue__ / _vnode 即挂载点）
  function findVueRoot() {
    var queue = [{ node: document.body, depth: 0 }];
    while (queue.length) {
      var it = queue.shift();
      if (!it || it.depth > 1000) break;
      var el = it.node;
      if (el.__vue_app__ || el.__vue__ || el._vnode) return el;
      if (el.nodeType === 1 && el.childNodes) {
        for (var i = 0; i < el.childNodes.length; i++) queue.push({ node: el.childNodes[i], depth: it.depth + 1 });
      }
    }
    return null;
  }

  // 四级回退取 Vue 版本：app.version → vue2._base.version → window.Vue → DevTools 钩子
  function getVueVersion(root) {
    var v = (root.__vue_app__ && root.__vue_app__.version) ||
      (root.__vue__ && root.__vue__.$root && root.__vue__.$root.$options &&
       root.__vue__.$root.$options._base && root.__vue__.$root.$options._base.version);
    if (!v || v === "unknown") {
      if (window.Vue && window.Vue.version) v = window.Vue.version;
      else if (window.__VUE_DEVTOOLS_GLOBAL_HOOK__ && window.__VUE_DEVTOOLS_GLOBAL_HOOK__.Vue)
        v = window.__VUE_DEVTOOLS_GLOBAL_HOOK__.Vue.version;
    }
    return v || "unknown";
  }

  // 多来源定位 Vue Router 实例（不同构建/版本挂载位置不同）
  function findVueRouter(root) {
    try {
      if (root.__vue_app__) {
        var app = root.__vue_app__;
        if (app.config && app.config.globalProperties && app.config.globalProperties.$router)
          return app.config.globalProperties.$router;
        var inst = app._instance;
        if (inst && inst.appContext && inst.appContext.config &&
            inst.appContext.config.globalProperties && inst.appContext.config.globalProperties.$router)
          return inst.appContext.config.globalProperties.$router;
        if (inst && inst.ctx && inst.ctx.$router) return inst.ctx.$router;
      }
      if (root.__vue__) {
        var vue = root.__vue__;
        return vue.$router || (vue.$root && vue.$root.$router) ||
          (vue.$root && vue.$root.$options && vue.$root.$options.router) || vue._router || null;
      }
    } catch (e) {}
    return null;
  }

  // 基础路径：options.base 优先，其次 history.base
  function extractRouterBase(router) {
    try {
      if (router.options && router.options.base) return router.options.base;
      if (router.history && router.history.base) return router.history.base;
    } catch (e) {}
    return null;
  }

  // 路由枚举四级回退：getRoutes() → options.routes(递归拼路径) → matcher.getRoutes() → history.current.matched
  function listVueRoutes(router) {
    var list = [];
    try {
      if (typeof router.getRoutes === "function") {
        router.getRoutes().forEach(function (r) {
          list.push({ path: r.path || "/", name: r.name || "", meta: safeMeta(r.meta) });
        });
        if (list.length) return list;
      }
      if (router.options && Array.isArray(router.options.routes)) {
        (function traverse(routes, base) {
          (routes || []).forEach(function (r) {
            if (!r || typeof r !== "object") return;
            var full = joinPath(base, r.path);
            list.push({ path: full, name: r.name || "", meta: safeMeta(r.meta) });
            if (Array.isArray(r.children) && r.children.length) traverse(r.children, full);
          });
        })(router.options.routes, "");
        if (list.length) return list;
      }
      if (router.matcher && typeof router.matcher.getRoutes === "function") {
        router.matcher.getRoutes().forEach(function (r) {
          list.push({ path: r.path || "/", name: r.name || "", meta: safeMeta(r.meta) });
        });
        if (list.length) return list;
      }
      if (router.history && router.history.current && Array.isArray(router.history.current.matched)) {
        router.history.current.matched.forEach(function (r) {
          list.push({ path: r.path || "/", name: r.name || "", meta: safeMeta(r.meta) });
        });
      }
    } catch (e) {}
    return list;
  }

  // ===== React =====

  // 广度优先定位 React 挂载容器
  function findReactRoot() {
    var queue = [{ node: document.body, depth: 0 }];
    while (queue.length) {
      var it = queue.shift();
      if (!it || it.depth > 1000) break;
      var el = it.node;
      if (el.nodeType === 1) {
        if (findKeyByPrefix(el, "__reactContainer") || el._reactRootContainer || findKeyByPrefix(el, "__reactFiber"))
          return el;
        if (el.childNodes) {
          for (var i = 0; i < el.childNodes.length; i++) queue.push({ node: el.childNodes[i], depth: it.depth + 1 });
        }
      }
    }
    return null;
  }

  // 取根 Fiber（容器 current / 旧版 _internalRoot.current / 任意 fiber 上溯）
  function getReactRootFiber(el) {
    try {
      var ck = findKeyByPrefix(el, "__reactContainer");
      if (ck) { var c = el[ck]; if (c) return c.current || c; }
      if (el._reactRootContainer) {
        var ir = el._reactRootContainer._internalRoot;
        if (ir && ir.current) return ir.current;
        if (el._reactRootContainer.current) return el._reactRootContainer.current;
      }
      var fk = findKeyByPrefix(el, "__reactFiber");
      if (fk) { var f = el[fk]; while (f && f.return) f = f.return; return f; }
    } catch (e) {}
    return null;
  }

  // React 版本：window.React.version → DevTools renderers → 按挂载标记给大版本标签
  function getReactVersion(el) {
    try {
      if (window.React && window.React.version) return window.React.version;
      var renderers = window.__REACT_DEVTOOLS_GLOBAL_HOOK__ && window.__REACT_DEVTOOLS_GLOBAL_HOOK__.renderers;
      if (renderers) {
        var keys = Object.keys(renderers);
        for (var i = keys.length - 1; i >= 0; i--) {
          var ver = renderers[keys[i]] && renderers[keys[i]].version;
          if (ver) return ver;
        }
      }
    } catch (e) {}
    if (findKeyByPrefix(el, "__reactContainer")) return "18+ (Concurrent)";
    if (el && el._reactRootContainer) return "≤17 (Legacy)";
    return "unknown";
  }

  // BFS 扫描 Fiber，对每个节点用 pick 判定候选位置（props / props.router / stateNode / hook 链）
  function scanFiber(rootFiber, predicate) {
    if (!rootFiber) return null;
    var queue = [rootFiber], seen = [], scanned = 0;
    function pick(candidates) {
      for (var i = 0; i < candidates.length; i++) {
        var cand = candidates[i];
        if (cand && typeof cand === "object" && predicate(cand)) return cand;
        if (cand && typeof cand === "object" && cand.router && predicate(cand.router)) return cand.router;
      }
      return null;
    }
    while (queue.length && scanned < 6000) {
      var fiber = queue.shift();
      if (!fiber || typeof fiber !== "object") continue;
      if (seen.indexOf(fiber) !== -1) continue;
      seen.push(fiber); scanned++;
      var found = pick([fiber.memoizedProps, fiber.stateNode]);
      if (found) return found;
      var hook = fiber.memoizedState, guard = 0;
      while (hook && guard < 100) {
        var via = pick([hook.memoizedState]);
        if (via) return via;
        hook = hook.next; guard++;
      }
      if (fiber.child) queue.push(fiber.child);
      if (fiber.sibling) queue.push(fiber.sibling);
    }
    return null;
  }

  // data router（v6.4+/v7）：routes 数组 + navigate + state
  function isReactRouterLike(o) {
    return Array.isArray(o.routes) && typeof o.navigate === "function" && !!(o.state && typeof o.state === "object");
  }
  function flattenReactRoutes(routes, basePath, out) {
    (routes || []).forEach(function (r) {
      if (!r || typeof r !== "object") return;
      var raw = typeof r.path === "string" ? r.path : "";
      var full;
      if (!raw || r.index) full = basePath || "/";
      else if (raw.charAt(0) === "/") full = raw;
      else full = (basePath === "/" ? "" : basePath || "") + "/" + raw;
      if (full.charAt(0) !== "/") full = "/" + full;
      full = full.replace(/\/\/+/g, "/");
      out.push({ path: full, name: typeof r.id === "string" ? r.id : (r.name || ""), meta: safeMeta(r.handle) });
      var children = r.children || r.routes;
      if (Array.isArray(children) && children.length) flattenReactRoutes(children, full, out);
    });
  }

  // TanStack Router：navigate + state.location(对象) + options
  function isTanStackLike(o) {
    return typeof o.navigate === "function" && !!(o.state && typeof o.state === "object") &&
      typeof o.state.location === "object" && !!(o.options && typeof o.options === "object");
  }
  function collectTanStackRoutes(router, out) {
    try {
      var flat = [];
      if (router.state && Array.isArray(router.state.routes)) flat = router.state.routes;
      else if (router.routesById && typeof router.routesById === "object") flat = Object.keys(router.routesById).map(function (k) { return router.routesById[k]; });
      else if (router.options && Array.isArray(router.options.routes)) flat = router.options.routes;
      flat.forEach(function (n) {
        if (!n || typeof n !== "object") return;
        var p = n.fullPath || n.path || "";
        if (!p) return;
        if (p.charAt(0) !== "/") p = "/" + p;
        out.push({ path: p.replace(/\/\/+/g, "/"), name: n.id || "", meta: {} });
      });
    } catch (e) {}
  }

  // 声明式路由（<Route> 的 memoizedProps.path + element/component/render/children）
  function harvestDeclarative(rootFiber) {
    var out = [], mode = null;
    scanFiber(rootFiber, function (props) {
      if (typeof props.path === "string" &&
          ("element" in props || "component" in props || "render" in props || "children" in props)) {
        if (!mode) mode = ("element" in props) ? "v6/v7 声明式" : "v4/v5 声明式";
        var p = props.path.charAt(0) === "/" ? props.path : "/" + props.path;
        out.push({ path: p.replace(/\/\/+/g, "/"), name: "", meta: {} });
        return false; // 不作为 router 实例返回，仅收集
      }
      return false;
    });
    // scanFiber 不会收集"返回 false 的命中"，故此处改用独立遍历以累积多条
    if (!out.length) out = declarativeWalk(rootFiber, function (m) { if (!mode) mode = m; });
    return { routes: out, mode: mode };
  }
  // 独立 BFS：收集所有 <Route>，不做单点命中即停
  function declarativeWalk(rootFiber, setMode) {
    var out = [], queue = rootFiber ? [rootFiber] : [], seen = [], scanned = 0, modeTaken = false;
    while (queue.length && scanned < 6000) {
      var f = queue.shift();
      if (!f || typeof f !== "object" || seen.indexOf(f) !== -1) continue;
      seen.push(f); scanned++;
      var p = f.memoizedProps;
      if (p && typeof p === "object" && typeof p.path === "string" &&
          ("element" in p || "component" in p || "render" in p || "children" in p)) {
        if (!modeTaken) { setMode(("element" in p) ? "v6/v7 声明式" : "v4/v5 声明式"); modeTaken = true; }
        var pp = p.path.charAt(0) === "/" ? p.path : "/" + p.path;
        out.push({ path: pp.replace(/\/\/+/g, "/"), name: "", meta: {} });
      }
      if (f.child) queue.push(f.child);
      if (f.sibling) queue.push(f.sibling);
    }
    return out;
  }

  // 锚点内链兜底（过滤外链与带扩展名的静态资源）
  function collectAnchorRoutes() {
    var out = [], seen = {};
    try {
      document.querySelectorAll("a[href]").forEach(function (a) {
        var href = a.getAttribute("href");
        if (!href || href.charAt(0) !== "/" || href.indexOf("//") === 0 || href.indexOf(".") !== -1) return;
        var path = href.split("#")[0].split("?")[0];
        if (!path || seen[path]) return;
        seen[path] = 1;
        out.push({ path: path, name: "", meta: {} });
      });
    } catch (e) {}
    return out;
  }

  // Next.js 路由：window.next.router.components / appRouteCache 的 key + __NEXT_DATA__.page
  function enumerateNextRoutes() {
    var out = [], seen = {};
    try {
      var r = window.next && window.next.router;
      var src = r && (r.components || r.appRouteCache);
      if (src && typeof src === "object") {
        Object.keys(src).forEach(function (p) {
          if (typeof p !== "string" || !p || seen[p]) return;
          seen[p] = 1;
          out.push({ path: p.charAt(0) === "/" ? p : "/" + p, name: "", meta: {} });
        });
      }
    } catch (e) {}
    try {
      var page = window.__NEXT_DATA__ && window.__NEXT_DATA__.page;
      if (page && !seen[page]) { seen[page] = 1; out.push({ path: page.charAt(0) === "/" ? page : "/" + page, name: "next-page", meta: {} }); }
    } catch (e) {}
    return out;
  }

  // 页面链接前缀分析：最高频首段占比 > 60% 时认定为候选基础路径
  function analyzePageLinks() {
    var result = { detectedBasePath: "", commonPrefixes: [] };
    try {
      var links = Array.prototype.slice.call(document.querySelectorAll("a[href]"))
        .map(function (a) { return a.getAttribute("href"); })
        .filter(function (h) { return !!h && h.charAt(0) === "/" && h.indexOf("//") !== 0 && h.indexOf(".") === -1; });
      if (links.length < 3) return result;
      var counts = {};
      links.forEach(function (l) {
        var seg = l.split("/").filter(Boolean);
        if (seg.length) counts[seg[0]] = (counts[seg[0]] || 0) + 1;
      });
      var sorted = Object.keys(counts).map(function (k) { return { prefix: k, count: counts[k] }; })
        .sort(function (a, b) { return b.count - a.count; });
      result.commonPrefixes = sorted;
      if (sorted.length && sorted[0].count / links.length > 0.6) result.detectedBasePath = "/" + sorted[0].prefix;
    } catch (e) {}
    return result;
  }

  // ===== 主流程 =====
  var r = {
    framework: null, vueVersion: null, reactVersion: null, reactRouterVersion: null,
    next: false, routerDetected: false, routerKind: null, allRoutes: [], routerBase: null,
    perf: [], anchorLinks: [], pageAnalysis: { detectedBasePath: "", commonPrefixes: [] }
  };
  try {
    r.perf = performance.getEntriesByType("resource").map(function (e) { return { name: e.name, initiatorType: e.initiatorType }; });
  } catch (e) {}
  try {
    r.anchorLinks = Array.prototype.slice.call(document.querySelectorAll("a[href]")).map(function (a) { return a.href; });
  } catch (e) {}
  try { r.pageAnalysis = analyzePageLinks(); } catch (e) {}

  // ---- Vue 优先 ----
  var vueRoot = findVueRoot();
  if (vueRoot) {
    r.framework = "vue";
    r.vueVersion = getVueVersion(vueRoot);
    var router = findVueRouter(vueRoot);
    if (router) {
      r.routerDetected = true;
      r.routerKind = (typeof router.getRoutes === "function") ? "Vue Router 4" : "Vue Router 2/3";
      r.routerBase = extractRouterBase(router);
      r.allRoutes = listVueRoutes(router);
    }
    return r;
  }

  // ---- React ----
  var reactRoot = findReactRoot();
  if (reactRoot) {
    r.framework = "react";
    r.reactVersion = getReactVersion(reactRoot);
    var rootFiber = getReactRootFiber(reactRoot);

    // 适配器 1：Next.js
    if (window.next) {
      r.next = true;
      r.routerKind = "Next.js";
      r.reactRouterVersion = (window.next && window.next.version) || "未知版本";
      r.allRoutes = enumerateNextRoutes();
      r.routerDetected = r.allRoutes.length > 0;
    } else {
      // 适配器 2：React Router data router
      var dataRouter = scanFiber(rootFiber, isReactRouterLike);
      if (dataRouter) {
        r.routerKind = "React Router";
        r.reactRouterVersion = dataRouter.future ? "v7 data router" : "v6.4+ data router";
        var rr = [];
        flattenReactRoutes(dataRouter.routes, "", rr);
        if (!rr.length && dataRouter.state && Array.isArray(dataRouter.state.matches)) {
          dataRouter.state.matches.forEach(function (m) {
            if (m && typeof m.pathname === "string") rr.push({ path: m.pathname, name: m.routeId || "", meta: {} });
          });
        }
        r.allRoutes = rr;
        r.routerDetected = true;
      } else {
        // 适配器 3：TanStack Router
        var tanstack = scanFiber(rootFiber, isTanStackLike);
        if (tanstack) {
          r.routerKind = "TanStack Router";
          r.reactRouterVersion = "data router";
          var ts = [];
          collectTanStackRoutes(tanstack, ts);
          r.allRoutes = ts;
          r.routerDetected = true;
        } else {
          // 适配器 4：声明式 <Route>
          var dec = harvestDeclarative(rootFiber);
          if (dec.routes.length) {
            r.routerKind = "React Router";
            r.reactRouterVersion = dec.mode;
            r.allRoutes = dec.routes;
            r.routerDetected = true;
          } else {
            // 适配器 5：锚点兜底
            r.routerKind = "未知路由库";
            r.allRoutes = collectAnchorRoutes();
            r.routerDetected = false;
          }
        }
      }
    }
    // 始终纳入当前路径，保证列表至少有一条真实可访问 URL
    try { r.allRoutes.push({ path: window.location.pathname || "/", name: "", meta: {} }); } catch (e) {}
  }

  return r;
};

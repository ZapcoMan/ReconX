/* global self, RouteUrls */
// 统一“主动探测”中的前端路由探测：仅对识别为 Vue/React 的站点，枚举路由 → 拼完整 URL → 逐个 GET 探测可达性。
// 这是“探测”语义（HTTP 可达性核验），不做 router 接管/守卫清除。在 background(SW) 上下文调用。
self.ProbeRoutes = async function (ctx) {
  var ri = ctx.routerInfo || {};
  var fw = ri.framework;
  if (fw !== "vue" && fw !== "react") {
    return { applicable: false, framework: fw || null, reason: fw ? ("框架为 " + fw + "，非 Vue/React，跳过前端路由探测") : "未识别到 Vue/React，跳过前端路由探测" };
  }
  var routes = ri.allRoutes && ri.allRoutes.length ? ri.allRoutes : [];
  var built = { items: [], sectionTitle: "标准 URL" };
  try {
    built = RouteUrls.buildRouteUrlList({ routes: routes, currentUrl: ctx.currentUrl, routerBase: ri.routerBase, detectedBasePath: null });
  } catch (e) {}
  var items = (built.items || []).slice(0, 40);
  var probes = [];
  for (var i = 0; i < items.length; i++) {
    var it = items[i];
    var status = 0, bytes = 0, err = null;
    try {
      var ctrl = new AbortController();
      var to = setTimeout(function () { try { ctrl.abort(); } catch (e) {} }, 5000);
      var r = await fetch(it.url, { credentials: "omit", redirect: "follow", signal: ctrl.signal });
      clearTimeout(to);
      status = r.status;
      try { var t = await r.text(); bytes = t.length; } catch (e) {}
    } catch (e) {
      err = String((e && e.message) || e);
    }
    probes.push({ path: it.path, url: it.url, status: status, bytes: bytes, error: err });
    await new Promise(function (res) { setTimeout(res, 200); });
  }
  return { applicable: true, framework: fw, routerKind: ri.routerKind || null, routerDetected: !!ri.routerDetected, total: items.length, sectionTitle: built.sectionTitle, routeProbes: probes };
};

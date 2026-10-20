/* global self, ApiExtract, RouteUrls, SecurityAudit, UrlClassify */
// collect 的“只读三能力”组装：输入已采集的 js 端点、routerInfo、links，输出可直接并入 bundle 的
// routes / api / security / links.classified / riskNote。纯函数，不执行注入（routerInfo 由 background 提供）。
self.ComputeExtras = function (ctx) {
  var tab = ctx.tab, host = ctx.host, js = ctx.js || {}, routerInfo = ctx.routerInfo || {}, links = ctx.links || { endpoints: [] };
  var origin = "";
  try { origin = new URL(tab.url).origin; } catch (e) {}

  var liveApis = ApiExtract.buildLiveApis(routerInfo.perf || []);
  var livePathnames = liveApis.map(function (a) { try { return new URL(a.url).pathname; } catch (e) { return a.path; } });
  var staticApis = ApiExtract.finalize(js.endpoints || {}, livePathnames, origin);
  var sourceMaps = (js.sourcemaps || []).map(function (m) {
    var mu = m.map;
    try { mu = new URL(m.map, m.from).href; } catch (e) {}
    return { scriptUrl: m.from, mapUrl: mu };
  });

  var routesList = (routerInfo.allRoutes && routerInfo.allRoutes.length) ? routerInfo.allRoutes : null;
  var anchorFallback = false;
  if (!routesList) {
    routesList = [];
    var sp = {};
    (routerInfo.anchorLinks || []).forEach(function (href) {
      try { var u = new URL(href); if (u.hostname === host && !sp[u.pathname]) { sp[u.pathname] = 1; routesList.push({ path: u.pathname, name: "", meta: {} }); } } catch (e) {}
    });
    anchorFallback = routesList.length > 0;
  }

  var routeBuild = { items: [], sectionTitle: "标准 URL", routerBase: null };
  try { routeBuild = RouteUrls.buildRouteUrlList({ routes: routesList, currentUrl: tab.url, routerBase: routerInfo.routerBase, detectedBasePath: null }); } catch (e) {}

  var security = SecurityAudit.performSecurityAudit({ pageUrl: tab.url, liveApis: liveApis, staticApis: staticApis, routes: routesList, sourceMaps: sourceMaps });

  var classified = [];
  try { classified = UrlClassify.rankItems(links.endpoints || []).filter(function (e) { return e.level; }).slice(0, 500); } catch (e) {}

  var routes = {
    framework: routerInfo.framework,
    vueVersion: routerInfo.vueVersion,
    reactVersion: routerInfo.reactVersion,
    reactRouterVersion: routerInfo.reactRouterVersion,
    next: !!routerInfo.next,
    routerDetected: !!routerInfo.routerDetected,
    routerKind: routerInfo.routerKind || null,
    routerBase: routeBuild.routerBase || routerInfo.routerBase || null,
    allRoutesCount: (routesList || []).length,
    allRoutes: (routesList || []).slice(0, 300),
    fullUrls: (routeBuild.items || []).slice(0, 300),
    sectionTitle: routeBuild.sectionTitle,
    anchorFallback: anchorFallback,
    error: routerInfo.error || null,
  };
  var api = {
    liveApisCount: liveApis.length,
    liveApis: liveApis.slice(0, 300),
    staticApisCount: staticApis.length,
    uncalledCount: staticApis.filter(function (a) { return !a.called; }).length,
    staticApis: staticApis.slice(0, 400),
    sourceMaps: sourceMaps,
  };
  var riskNote = null;
  if (security.summary.overallRisk === "critical" || security.summary.overallRisk === "high") {
    riskNote = { level: security.summary.overallRisk, category: "前端审计", summary: "审计整体风险 " + security.summary.overallRisk + "：敏感 API " + security.summary.sensitiveApiCount + " 个，未保护路由线索 " + security.summary.unprotectedRoutes + " 个" };
  }
  return { routes: routes, api: api, security: security, classified: classified, riskNote: riskNote };
};

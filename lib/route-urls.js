/* global self */
// 路由 → 完整 URL 生成（移植自 King-CrackX url.ts + routeUrls.ts 的纯函数，只读分析）
(function () {
  const R = {};

  function cleanUrl(url) {
    return url.replace(/([^:]\/)\/+/g, "$1").replace(/\/$/, "");
  }
  function normalizeUrl(url) {
    if (!url || typeof url !== "string") return "";
    return cleanUrl(url.trim());
  }
  function urlsEqual(l, r) {
    return normalizeUrl(l) === normalizeUrl(r);
  }
  R.cleanUrl = cleanUrl;
  R.normalizeUrl = normalizeUrl;
  R.urlsEqual = urlsEqual;

  R.normalizeBasePath = function (basePath) {
    if (!basePath || typeof basePath !== "string") return "";
    let n = basePath.trim().replace(/\\/g, "/");
    if (!n || n === "/" || n.indexOf("#") >= 0) return "";
    if (/^[a-z][a-z\d+.-]*:\/\//i.test(n)) return "";
    const q = n.indexOf("?");
    if (q >= 0) n = n.substring(0, q);
    if (n.charAt(0) !== "/") n = "/" + n;
    n = cleanUrl(n);
    return n === "/" ? "" : n;
  };

  R.normalizeRoutePath = function (path) {
    if (!path || typeof path !== "string") return "/";
    const t = path.trim();
    if (!t) return "/";
    const withSlash = t.charAt(0) === "/" ? t : "/" + t;
    return cleanUrl(withSlash) || "/";
  };

  R.dedupeRoutes = function (routes) {
    const seen = new Set();
    return (routes || []).reduce((acc, route) => {
      if (!route || typeof route !== "object" || !route.path || typeof route.path !== "string") return acc;
      const np = R.normalizeRoutePath(route.path);
      if (seen.has(np)) return acc;
      seen.add(np);
      acc.push(Object.assign({}, route, { path: np }));
      return acc;
    }, []);
  };

  R.dedupeUrlItems = function (items) {
    const seen = new Set();
    return (items || []).filter((it) => {
      const n = normalizeUrl((it && it.url) || "");
      if (!n || seen.has(n)) return false;
      seen.add(n);
      it.url = n;
      return true;
    });
  };

  // 依据路由表与当前地址构建完整 URL 列表（Hash/History + base 模式）
  R.buildRouteUrlList = function (params) {
    const routes = params.routes || [];
    const currentUrl = params.currentUrl;
    const routerBase = params.routerBase;
    const detectedBasePath = params.detectedBasePath;
    const validRoutes = R.dedupeRoutes(routes);
    const urlObj = new URL(currentUrl);
    const domainBase = urlObj.origin;
    let baseUrl = "";
    let isHistoryMode = false;
    if (currentUrl.indexOf("#") >= 0) {
      baseUrl = currentUrl.substring(0, currentUrl.indexOf("#") + 1);
    } else {
      isHistoryMode = true;
      baseUrl = domainBase;
    }
    const paths = validRoutes.map((r) => r.path).filter(Boolean);
    const trustedBasePath = R.normalizeBasePath(routerBase);
    const candidateBasePath = trustedBasePath ? "" : R.normalizeBasePath(detectedBasePath);
    const availableBasePath = trustedBasePath || candidateBasePath;
    const canUseBaseMode = !!(isHistoryMode && availableBasePath);

    function buildUrl(path, modeBasePath) {
      modeBasePath = modeBasePath || "";
      const np = R.normalizeRoutePath(path);
      const cleanPath = np === "/" ? "" : np.substring(1);
      if (isHistoryMode) {
        if (modeBasePath) {
          if (np === modeBasePath || np.indexOf(modeBasePath + "/") === 0) return baseUrl + np;
          return baseUrl + modeBasePath + (cleanPath ? "/" + cleanPath : "");
        }
        return baseUrl + (cleanPath ? "/" + cleanPath : "/");
      }
      if (baseUrl.charAt(baseUrl.length - 1) === "#") return baseUrl + "/" + cleanPath;
      if (baseUrl.indexOf("#/", baseUrl.length - 2) === baseUrl.length - 2) return baseUrl + cleanPath;
      return baseUrl + "#/" + cleanPath;
    }

    const standardUrls = R.dedupeUrlItems(paths.map((p) => ({ path: p, url: buildUrl(p) })));
    const baseModeUrls = canUseBaseMode ? R.dedupeUrlItems(paths.map((p) => ({ path: p, url: buildUrl(p, availableBasePath) }))) : [];
    const mode = trustedBasePath && canUseBaseMode ? "base" : "standard";
    return {
      mode,
      canUseBaseMode,
      trustedBasePath,
      candidateBasePath,
      availableBasePath,
      sectionTitle: mode === "base" ? "带基础路径 URL：" + (trustedBasePath || candidateBasePath) : "标准 URL",
      items: mode === "base" ? baseModeUrls : standardUrls,
    };
  };

  self.RouteUrls = R;
})();

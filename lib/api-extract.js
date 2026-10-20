/* global self */
// API 端点静态提取（移植自 King-CrackX api-extractor.ts 的正则与判定，纯只读分析）
// 提供纯函数：正则识别、模板参数处理、buildFullUrl、extractFromText、called 标记、liveApis 归一。
// 注入脚本只负责回传原始文本/数据，本库在 background 调用完成提取，规则集中便于维护。
(function () {
  const AE = {};

  AE.STATIC_EXT_RE = /\.(js|mjs|css|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|otf|map|html?|mp4|webp|webm|pdf|zip|txt)(\?|$)/i;
  AE.API_PREFIX_RE = /\/(api|apis|apiv\d|v\d{1,2}|rest|gateway|gw|svc|service|services|auth|oauth|sso|login|logout|register|user|users|admin|sys|system|manage|manager|mgr|portal|open|openapi|internal|backend|server|rpc|graphql)(\/|$)/i;
  AE.REL_API_PREFIX_RE = /^(api|apis|apiv\d|v\d{1,2}|rest|gateway|gw|svc|service|services|auth|oauth|sso|login|logout|register|user|users|admin|sys|system|manage|manager|mgr|portal|open|openapi|internal|backend|server|rpc|graphql)(\/|$)/i;
  AE.STATIC_DIR_RE = /^(\/)?(assets|static|img|images|fonts|icons|css|js|dist|build|public|vendor|lib|libs|media|file|files)(\/|$)/i;
  AE.ACTION_WORD_RE = /(get|list|query|create|add|update|edit|del|delete|remove|export|import|upload|download|search|find|save|submit|check|verify|send|login|logout|register|info|detail|page|count|stat|log|audit|menu|role|perm|token|captcha|sms|mail|notify|order|pay|bill|account)/i;

  AE.isApiLikePath = function (path) {
    if (!path || path.length < 4 || path.length > 200) return false;
    if (path.indexOf("//") === 0) return false;
    if (AE.STATIC_EXT_RE.test(path)) return false;
    const segs = path.split("/").filter(Boolean);
    if (segs.length < 2) return false;
    if (AE.STATIC_DIR_RE.test(path)) return false;
    if (AE.API_PREFIX_RE.test(path)) return true;
    if (AE.ACTION_WORD_RE.test(path)) return true;
    return false;
  };

  AE.isApiLikeRelativePath = function (path) {
    if (!path || path.length < 6 || path.length > 200) return false;
    if (path.indexOf("/") === -1) return false;
    if (/^https?:|^\.\.?\/|^\//.test(path)) return false;
    if (AE.STATIC_EXT_RE.test("/" + path)) return false;
    const segs = path.split("/").filter(Boolean);
    if (segs.length < 2) return false;
    const allShort = segs.every((s) => /^[a-z0-9_\-]{1,6}$/i.test(s));
    if (allShort && !AE.REL_API_PREFIX_RE.test(path) && !AE.ACTION_WORD_RE.test(path)) return false;
    return AE.REL_API_PREFIX_RE.test(path) || AE.ACTION_WORD_RE.test(path);
  };

  AE.cleanTemplatePath = function (path) {
    return path
      .replace(/\$\{[^}]*\}/g, "")
      .replace(/:[A-Za-z0-9_]+/g, "")
      .replace(/\{[^}]*\}/g, "");
  };

  AE.fillTemplateParams = function (pathname) {
    return pathname
      .replace(/\$\{[^}]*\}/g, "1")
      .replace(/:([A-Za-z_][A-Za-z0-9_]*)(?=[/#?]|$)/g, "1")
      .replace(/\{[^}]*\}/g, "1");
  };

  AE.buildFullUrl = function (path, origin) {
    if (/^https?:\/\//i.test(path)) {
      try {
        const u = new URL(path);
        u.pathname = AE.fillTemplateParams(u.pathname);
        return u.href;
      } catch (e) {
        return path;
      }
    }
    const normalized = path.charAt(0) === "/" ? path : "/" + path;
    return origin + AE.fillTemplateParams(normalized);
  };

  // 从一段 JS/文本中抽取端点到累加器 endpoints（Object.create(null)）
  AE.extractFromText = function (text, endpoints, sourceLabel) {
    const add = (p) => {
      if (!p) return;
      if (!endpoints[p]) endpoints[p] = { path: p, sources: [] };
      const e = endpoints[p];
      if (sourceLabel && e.sources.indexOf(sourceLabel) < 0 && e.sources.length < 5) e.sources.push(sourceLabel);
    };
    const stringRe = /(["'`])((?:\/)[A-Za-z0-9_\-./:{}$]+)\1/g;
    const relStringRe = /(["'`])(?!\/|https?:\/\/|\.\.?\/)([A-Za-z0-9_\-./:{}$]+)\1/g;
    const urlRe = /(["'`])(https?:\/\/[A-Za-z0-9_\-./:{}$]+)\1/g;
    let m;
    while ((m = stringRe.exec(text)) !== null) { if (AE.isApiLikePath(m[2])) add(m[2]); }
    while ((m = relStringRe.exec(text)) !== null) { if (AE.isApiLikeRelativePath(m[2])) add(m[2]); }
    while ((m = urlRe.exec(text)) !== null) {
      try { const u = new URL(m[2]); if (AE.API_PREFIX_RE.test(u.pathname)) add(m[2]); } catch (e) {}
    }
  };

  // 累加器 → staticApis 数组（含 called / hasParams 标记），按 path 排序
  AE.finalize = function (endpoints, livePathnames, origin) {
    const list = Object.keys(endpoints).map((path) => ({
      path,
      fullUrl: AE.buildFullUrl(path, origin),
      hasParams: /(\$\{[^}]*\}|\/:[A-Za-z_][A-Za-z0-9_]*|\{[^}]*\})/.test(path),
      sources: endpoints[path].sources,
      called: (livePathnames || []).some((lp) => {
        const cleaned = AE.cleanTemplatePath(path);
        return lp === cleaned || (cleaned.length > 1 && lp.indexOf(cleaned) === 0);
      }),
    }));
    list.sort((a, b) => a.path.localeCompare(b.path));
    return list;
  };

  // 由 performance resource 条目筛出实际调用接口（initiatorType=fetch/xhr，排除静态资源）
  AE.buildLiveApis = function (entries) {
    const out = [];
    const seen = Object.create(null);
    (entries || []).forEach((en) => {
      const t = en.initiatorType;
      if (t !== "xmlhttprequest" && t !== "fetch") return;
      let u;
      try { u = new URL(en.name); } catch (e) { return; }
      if (!/^https?:$/.test(u.protocol)) return;
      if (AE.STATIC_EXT_RE.test(u.pathname)) return;
      if (seen[en.name]) return;
      seen[en.name] = 1;
      out.push({ url: en.name, path: u.pathname + (u.search || "") });
    });
    return out;
  };

  self.ApiExtract = AE;
})();

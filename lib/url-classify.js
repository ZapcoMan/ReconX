/* global self */
// URL 规范化 + 敏感 URL 三级分类（移植自 CrazyEdusrc urlExtractor/sensitive，通用化）
// normalize：还原常见跳转包装、去跟踪参数与 hash；classify：按特征分 critical/warn/info。
// 既用于 Recon 的 links/endpoints 处理，也用于 Dork 结果 URL 的核验排序。
(function () {
  const U = {};

  U.TRACKING_PARAMS = [
    "ved", "usg", "ei", "sa", "cd", "rct", "cad", "uact", "aqs", "sourceid",
    "sxsrf", "gs_lcp", "oq", "gs_lcrp", "sca_esv", "sclient",
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content", "spm",
  ];

  // 搜索引擎自身域名（仅在 SERP 提取场景排除）
  U.ENGINE_DOMAINS = [
    "google.com", "gstatic.com", "googleapis.com", "googleusercontent.com",
    "baidu.com", "bdstatic.com", "bdimg.com",
    "bing.com", "bingapis.com", "microsoft.com", "msn.com", "w3.org", "schema.org",
  ];

  function safeDecode(v) {
    try { return decodeURIComponent(v); } catch (e) { return v; }
  }
  function hostMatches(host, domain) {
    return host === domain || host.endsWith("." + domain);
  }

  // 通用规范化：去跟踪参数/hash，还原 Google url=/Bing ck/a/通用 redirect 参数
  U.normalize = function (raw) {
    if (!raw) return "";
    let u;
    try {
      u = new URL(raw);
    } catch (e) {
      return "";
    }
    const host = u.hostname.toLowerCase();
    // Google /url?q=
    if (/google\.[a-z.]+$/.test(host) && u.pathname === "/url") {
      const t = u.searchParams.get("q") || u.searchParams.get("url");
      if (t && /^https?:\/\//i.test(t)) { try { u = new URL(t); } catch (e) { return ""; } }
    }
    // Bing /ck/a?u=a1<base64>
    if (hostMatches(u.hostname.toLowerCase(), "bing.com") && u.pathname.includes("/ck/a")) {
      const enc = u.searchParams.get("u");
      if (enc) {
        try {
          let d = atob(enc.replace(/^a1/, ""));
          if (!/^https?:\/\//i.test(d)) d = "https://" + d;
          u = new URL(d);
        } catch (e) { return ""; }
      }
    }
    // 通用 redirect 参数
    const r = u.searchParams.get("url") || u.searchParams.get("target") || u.searchParams.get("redirectUrl");
    if (r && /^https?:\/\//i.test(r)) { try { u = new URL(r); } catch (e) {} }
    U.TRACKING_PARAMS.forEach((p) => u.searchParams.delete(p));
    u.hash = "";
    return u.toString();
  };

  U.isEngineUrl = function (url) {
    let host;
    try { host = new URL(url).hostname.toLowerCase(); } catch (e) { return true; }
    if (url.indexOf("chrome-extension://") === 0) return true;
    return U.ENGINE_DOMAINS.some((d) => hostMatches(host, d));
  };

  // 黑名单编译：支持 精确域 / *.通配域 / /正则/ 三种写法
  U.compileBlacklist = function (list) {
    const regex = [];
    const domains = [];
    (list || []).forEach((rule) => {
      const v = String(rule).trim();
      if (!v) return;
      if (v.length > 2 && v[0] === "/" && v[v.length - 1] === "/") {
        try { regex.push(new RegExp(v.slice(1, -1), "i")); } catch (e) {}
      } else if (v.indexOf("*.") === 0) {
        domains.push({ wildcard: true, domain: v.slice(2).toLowerCase() });
      } else {
        domains.push({ wildcard: false, domain: v.toLowerCase() });
      }
    });
    return { regex, domains };
  };
  U.matchBlacklist = function (url, compiled) {
    let host;
    try { host = new URL(url).hostname.toLowerCase(); } catch (e) { return false; }
    return (
      compiled.domains.some((d) => hostMatches(host, d.domain)) ||
      compiled.regex.some((re) => re.test(url))
    );
  };

  // ---- 敏感分级规则 ----
  U.SENSITIVE_RULES = [
    { id: "db", label: "数据库", level: "critical", re: /\.(sql|db|mdb|dump|sqlite)(\?|$|&)/i },
    { id: "backup", label: "备份", level: "critical", re: /(\.bak|\.old|\.zip|\.rar|\.7z|backup|www\.zip|web\.zip|site\.zip)(\?|$|&|\/)/i },
    { id: "config", label: "配置", level: "critical", re: /(\.env|config\.php|web\.config|application\.ya?ml|\.ini|\.properties)(\?|$|&)/i },
    { id: "vcs", label: "版本控制", level: "critical", re: /(\.git\/|\.svn\/|\.git$|\.svn$)/i },
    { id: "admin", label: "后台", level: "warn", re: /(\/admin|\/manage|\/guanli|\/login|\/system)(\/|$|\?)/i },
    { id: "debug", label: "接口调试", level: "warn", re: /(swagger|api-docs|druid|actuator|phpinfo|debug|nacos|jenkins)/i },
    { id: "upload", label: "上传点", level: "warn", re: /(ueditor|umeditor|uploadify|fileupload|kindeditor)/i },
    { id: "student", label: "学生数据", level: "info", re: /(学生|名单|花名册|学籍|录取|成绩|xueji|luqu|chengji)/i, decode: true },
    { id: "idcard", label: "证件信息", level: "info", re: /(身份证|证件|idcard|id_card|sfz)/i, decode: true },
    { id: "doc", label: "文档", level: "info", re: /\.(xls|xlsx|doc|docx|pdf|csv)(\?|$|&)/i },
  ];
  const WEIGHT = { critical: 0, warn: 1, info: 2 };

  U.classify = function (url) {
    const hits = [];
    const decoded = safeDecode(url);
    for (const rule of U.SENSITIVE_RULES) {
      try {
        const target = rule.decode ? decoded : url;
        if (rule.re.test(target)) hits.push(rule);
      } catch (e) {}
    }
    if (!hits.length) return { labels: [], level: null };
    hits.sort((a, b) => WEIGHT[a.level] - WEIGHT[b.level]);
    return { labels: hits.map((h) => h.label), level: hits[0].level };
  };

  // 给一组 URL/endpoint 标注分级并排序（critical 在前）
  U.rankItems = function (items) {
    return items
      .map((it) => {
        const c = U.classify(it.url);
        return Object.assign({}, it, { labels: c.labels, level: c.level });
      })
      .sort((a, b) => (a.level ? WEIGHT[a.level] : 3) - (b.level ? WEIGHT[b.level] : 3));
  };

  self.UrlClassify = U;
})();

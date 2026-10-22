// ReconX background service worker（ES module，@crxjs 编译）。从旧 importScripts 改为 ES import。
import * as Fingerprints from './core/fingerprints'
import * as SensitiveRules from './core/sensitive-rules'
import * as HeaderChecks from './core/header-checks'
import * as UrlClassify from './core/url-classify'
import * as ApiExtract from './core/api-extract'
import * as TechStack from './core/tech-stack'
import * as UrlUtils from './core/url-utils'
import { computeExtras } from './core/collect-extras'
import { probeRoutes } from './core/probe-routes'
import { routerProbe } from './core/router-probe'
import { shrinkForStorage } from './core/storage-fallback'
import type { Scope, Settings } from './types'
import type { LiveSnapshot } from './shared/messaging'

const DEFAULT_SETTINGS: Settings = { activeProbe: false, maxJsFiles: 25, maxConcurrent: 5, theme: 'dark' }

// ---------------- 常驻 Content Script 注册（document_start 时机注入 all-in.js） ----------------
const ALL_IN_SCRIPT_ID = 'reconx-all-in-script'

async function registerAllInContentScript(): Promise<void> {
  try {
    const existing = await chrome.scripting.getRegisteredContentScripts()
    const already = existing.find((s) => s.id === ALL_IN_SCRIPT_ID)
    if (already) {
      await chrome.scripting.unregisterContentScripts({ ids: [ALL_IN_SCRIPT_ID] })
    }
    const scope = await getScope()
    const matches = scope.hosts.map((h) => h.origin + '/*')
    // 允许域为空、或主动探测总开关关闭时，只注销不注册
    if (!matches.length || !(await getSettings()).activeProbe) return
    await chrome.scripting.registerContentScripts([{
      id: ALL_IN_SCRIPT_ID,
      matches,
      js: ['all-in.js'],

      runAt: 'document_start',
      world: 'MAIN',
      allFrames: true
    }])
  } catch (e: any) {
    console.error('[ReconX] registerContentScripts failed:', e)
  }
}

// ---------------- 范围（允许域白名单） ----------------
async function getScope(): Promise<Scope> {
  const { scope } = await chrome.storage.local.get('scope')
  return scope && Array.isArray(scope.hosts) ? (scope as Scope) : { hosts: [] }
}
async function saveScope(s: Scope): Promise<void> {
  await chrome.storage.local.set({ scope: s })
}
async function addHost(host: string, origin: string, note?: string): Promise<Scope> {
  const s = await getScope()
  if (!s.hosts.some((h) => h.host === host)) {
    s.hosts.push({ host, origin, addedAt: Date.now(), note: note || '' })
    await saveScope(s)
    registerAllInContentScript()
  }
  return s
}
async function removeHost(host: string): Promise<Scope> {
  const s = await getScope()
  s.hosts = s.hosts.filter((h) => h.host !== host)
  await saveScope(s)
  registerAllInContentScript()
  return s
}
async function getSettings(): Promise<Settings> {
  const { settings } = await chrome.storage.local.get('settings')
  return Object.assign({}, DEFAULT_SETTINGS, settings || {})
}
async function inScope(host: string): Promise<boolean> {
  const s = await getScope()
  return s.hosts.some((h) => h.host === host)
}

// ---------------- 响应头缓存（来自 webRequest） ----------------
interface HeadersEntry { main: Array<{ name: string; value: string }>; subFrames: Array<{ type: string; url: string; pairs: Array<{ name: string; value: string }> }> }
const headersCache = new Map<string, HeadersEntry>()
function cacheHeaders(details: chrome.webRequest.WebResponseHeadersDetails): void {
  if (!details.responseHeaders) return
  // url-utils：非法/非 http(s) URL 统一返空串，不再局部 try/catch
  const host = UrlUtils.safeHostname(details.url)
  if (!host) return
  const entry = headersCache.get(host) ?? { main: [], subFrames: [] }
  const pairs = details.responseHeaders.map((h) => ({ name: h.name, value: h.value || '' }))
  if (details.type === 'main_frame') entry.main = pairs
  else if (entry.subFrames.length < 30) entry.subFrames.push({ type: String(details.type), url: details.url, pairs })
  headersCache.set(host, entry)
}
chrome.webRequest.onHeadersReceived.addListener(cacheHeaders, { urls: ['<all_urls>'], types: ['main_frame', 'sub_frame', 'xmlhttprequest'] }, ['responseHeaders'])

// ---------------- DOM 采集（函数式注入，直接返回 payload） ----------------
async function collectDom(tabId: number): Promise<any> {
  const [res] = await chrome.scripting.executeScript({
    target: { tabId },
    func: function () {
      const txt = (s: any, n: number): string => String(s || '').replace(/\s+/g, ' ').trim().slice(0, n || 120)
      const qsa = (sel: string): any[] => Array.prototype.slice.call(document.querySelectorAll(sel))
      return {
        ok: true, url: location.href, title: document.title || '',
        metaGenerator: (() => { const g = document.querySelector('meta[name="generator"], meta[name="Generator"]'); return g ? g.getAttribute('content') : null })(),
        anchors: qsa('a[href]').map((a: any) => ({ href: a.href, rel: a.getAttribute('rel') || '', text: txt(a.textContent, 80) })),
        scripts: qsa('script[src]').map((s: any) => s.src),
        inlineScripts: qsa('script:not([src])').map((s: any) => s.textContent).filter(Boolean).join('\n/* ==== inline ==== */\n').slice(0, 200000),
        links: qsa('link[href]').map((l: any) => ({ rel: l.getAttribute('rel') || '', href: l.href })),
        styles: qsa('[style]').slice(0, 200).map((e: any) => txt(e.getAttribute('style'), 160)),
        images: qsa('img[src]').map((i: any) => i.src).slice(0, 800),
        iframes: qsa('iframe[src]').map((i: any) => i.src),
        objectEmbed: qsa('object[data],embed[src]').map((i: any) => i.data || i.src),
        forms: qsa('form').map((f: any) => ({ action: f.getAttribute('action') || f.action, method: (f.getAttribute('method') || f.method || 'GET').toUpperCase(), enctype: f.getAttribute('enctype') || null, fields: Array.prototype.slice.call(f.elements).map((e: any) => ({ name: e.name || '', type: e.type || e.tagName.toLowerCase(), tag: e.tagName, hidden: e.type === 'hidden' || e.hidden === true })) })),
        buttons: qsa('button[data-action],input[type=submit]').map((b: any) => b.getAttribute('data-action') || txt(b.value || b.textContent, 40)),
        resourceUrls: (performance as any).getEntriesByType('resource').map((r: any) => r.name),
        htmlEvidence: (document.head ? document.head.innerHTML : '').slice(0, 8000) + '\n' + (document.body ? document.body.outerHTML.slice(0, 4000) : ''),
        inlineEndpoints: (() => { const src = qsa('script:not([src])').map((s: any) => s.textContent).join('\n'); const out: string[] = []; const re = /(["'`])(\/(?:api|v[0-9]|graphql|rest|admin|internal)[\/][^"'`\s]*)\1/gi; let m; while ((m = re.exec(src)) && out.length < 200) out.push(m[2]); return out })()
      }
    }
  })
  return (res && res.result) || { ok: false, error: 'no-result' }
}

// ---------------- MAIN world 全局变量探测 ----------------
async function collectWindowVars(tabId: number): Promise<Array<{ name: string; probe: string; weak: boolean; version: string | null }>> {
  try {
    const [res] = await chrome.scripting.executeScript({
      target: { tabId },
      world: 'MAIN',
      func: function (vars: any[]) {
        function getPath(o: any, p: string): any { return p.split('.').reduce((a, k) => (a == null ? undefined : a[k]), o) }
        const out: any[] = []
        for (const v of vars) {
          try {
            if ((window as any)[v.probe] !== undefined) {
              let version: string | null = null
              if (v.versionPaths) for (const path of v.versionPaths) { try { const vv = getPath(window, path); if (vv != null) { version = String(vv); break } } catch { /* */ } }
              out.push({ name: v.name, probe: v.probe, weak: !!v.weak, version })
            }
          } catch { /* */ }
        }
        return out
      },
      args: [Fingerprints.GLOBAL_VARS as any]
    })
    return (res && res.result) || []
  } catch {
    return []
  }
}

// ---------------- MAIN world 只读路由/框架探测（注入 routerProbe 函数） ----------------
async function detectRouterAndLive(tabId: number): Promise<any> {
  try {
    const [res] = await chrome.scripting.executeScript({ target: { tabId }, world: 'MAIN', func: routerProbe })
    return (res && res.result) || {}
  } catch (e: any) {
    return { error: String((e && e.message) || e) }
  }
}

// ---------------- 抓取 JS ----------------
async function fetchText(url: string): Promise<any> {
  const ctrl = new AbortController()
  const to = setTimeout(() => ctrl.abort(), 5000)
  try {
    const r = await fetch(url, { credentials: 'omit', redirect: 'follow', signal: ctrl.signal })
    clearTimeout(to)
    const cl = parseInt(r.headers.get('content-length') || '0', 10)
    if (cl > 1500000) return { url, ok: true, skipped: true, reason: 'too-large', status: r.status, finalUrl: r.url }
    const t = await r.text()
    return { url, ok: true, status: r.status, size: t.length, text: t.slice(0, 600000), finalUrl: r.url }
  } catch (e: any) {
    return { url, ok: false, error: String((e && e.message) || e) }
  } finally {
    clearTimeout(to)
  }
}
async function limit<T, R>(items: T[], n: number, fn: (it: T) => Promise<R>): Promise<R[]> {
  const out: R[] = []
  let i = 0
  const workers = new Array(Math.min(n, items.length)).fill(0).map(async () => {
    while (i < items.length) {
      const idx = i++
      out[idx] = await fn(items[idx])
    }
  })
  await Promise.all(workers)
  return out
}

// ---------------- 扫描 JS（敏感信息 + 端点 + sourcemap） ----------------
async function scanJs(scriptUrls: string[], inlineText: string, currentHost: string, scopeHosts: string[], settings: Settings): Promise<any> {
  const endpoints: ApiExtract.EndpointsAccumulator = Object.create(null)
  const shortSource = UrlUtils.filenameOf
  const uniq: string[] = []
  const seen = new Set<string>()
  for (const u of scriptUrls) {
    const h = UrlUtils.safeHostname(u)
    if (!h) continue
    if (h !== currentHost && !scopeHosts.includes(h)) continue
    if (seen.has(u)) continue
    seen.add(u)
    uniq.push(u)
  }
  const targets = uniq.slice(0, settings.maxJsFiles)
  const results = await limit(targets, settings.maxConcurrent, async (u) => {
    const r = await fetchText(u)
    const findings = r.ok && r.text ? SensitiveRules.scanText(r.text, u) : []
    if (r.ok && r.text) ApiExtract.extractFromText(r.text, endpoints, shortSource(u))
    const maps = r.ok && r.text ? (r.text.match(/[#@]sourceMappingURL=([^\s'"]+)/g) || []).map((s: string) => s.replace(/[#@]sourceMappingURL=/, '')) : []
    return { url: u, status: r.status, ok: r.ok, skipped: !!r.skipped, error: r.error, size: r.size, findings, maps }
  })
  const inlineFindings = inlineText ? SensitiveRules.scanText(inlineText, 'inline') : []
  if (inlineText) ApiExtract.extractFromText(inlineText, endpoints, 'inline')
  return { scanned: results.map((r) => ({ url: r.url, status: r.status, ok: r.ok, skipped: r.skipped, size: r.size, error: r.error })), findings: results.flatMap((r) => r.findings), inlineFindings, sourcemaps: results.flatMap((r) => r.maps.map((m: string) => ({ from: r.url, map: m }))), endpoints }
}

// ---------------- 链接 / 端点归一 ----------------
function buildLinks(payload: any, host: string): any {
  // url-utils.toAbsolute：相对 base 解析 + 仅 http/https，与旧 norm() 语义一致
  const norm = (href: string): URL | null => UrlUtils.toAbsolute(href, payload.url)
  const seen = new Set<string>()
  const endpoints: any[] = []
  const paramCount = new Map<string, number>()
  const byHost = new Map<string, number>()
  function add(u: URL | null, ctx: string): void {
    if (!u) return
    u.hash = ''
    const key = u.href
    if (seen.has(key)) return
    seen.add(key)
    const params = Array.from(u.searchParams.keys())
    params.forEach((p) => paramCount.set(p, (paramCount.get(p) || 0) + 1))
    byHost.set(u.hostname, (byHost.get(u.hostname) || 0) + 1)
    endpoints.push({ url: key, host: u.hostname, same: u.hostname === host, path: u.pathname, params, ctx })
  }
  ;(payload.anchors || []).forEach((a: any) => add(norm(a.href), 'a' + (a.rel ? ':' + a.rel : '')))
  ;(payload.iframes || []).forEach((s: string) => add(norm(s), 'iframe'))
  ;(payload.objectEmbed || []).forEach((s: string) => add(norm(s), 'object'))
  ;(payload.forms || []).forEach((f: any) => add(norm(f.action), 'form'))
  ;(payload.inlineEndpoints || []).forEach((p: string) => add(norm(p), 'inline'))
  return {
    total: endpoints.length,
    endpoints,
    sameOriginCount: endpoints.filter((e) => e.same).length,
    byHost: Array.from(byHost.entries()).map(([h, c]) => ({ host: h, count: c })).sort((a, b) => b.count - a.count),
    params: Array.from(paramCount.entries()).map(([name, count]) => ({ name, count })).sort((a, b) => b.count - a.count),
    forms: payload.forms || []
  }
}

// ---------------- 资源清单 ----------------
function buildResources(payload: any): Record<string, string[]> {
  const cls = (u: string): string => {
    const p = u.split('?')[0].toLowerCase()
    if (/\.(js)(\?|$)/.test(p) || /\/js\//.test(p)) return 'scripts'
    if (/\.css(\?|$)/.test(p)) return 'css'
    if (/\.(png|jpe?g|gif|svg|webp|avif|ico)(\?|$)/.test(p)) return 'images'
    if (/\.(woff2?|ttf|otf|eot)(\?|$)/.test(p)) return 'fonts'
    if (/\.(json|xml|txt|csv)(\?|$)/.test(p) || /\/(api|graphql|rest)\//.test(p)) return 'data'
    return 'other'
  }
  const all = Array.from(new Set([...(payload.scripts || []), ...(payload.links || []).map((l: any) => l.href), ...(payload.images || []), ...(payload.resourceUrls || [])]))
  const out: Record<string, string[]> = { scripts: [], css: [], images: [], fonts: [], data: [], other: [] }
  for (const u of all as string[]) out[cls(u)].push(u)
  return out
}

// ---------------- 技术栈汇总（被动指纹） ----------------
function buildTech(payload: any, headerReport: any, windowVars: any[], resources: Record<string, string[]>): any[] {
  const map: Record<string, any> = {}
  const add = (name: string, category: string, version: string | null, evidence: string): void => {
    if (!name) return
    const k = name.toLowerCase()
    if (!map[k]) map[k] = { name, category, version: version || null, evidence: [] }
    if (!map[k].version && version) map[k].version = version
    if (evidence && map[k].evidence.length < 4) map[k].evidence.push(evidence)
  }
  if (headerReport.server) for (const s of Fingerprints.SERVER_TECH) if (s.re.test(headerReport.server)) add(s.name, 'server', Fingerprints.versionFrom(headerReport.server), 'Server: ' + headerReport.server)
  if (headerReport.poweredBy) for (const p of Fingerprints.POWERED_BY) if (p.re.test(headerReport.poweredBy)) add(p.name, 'runtime', Fingerprints.versionFrom(headerReport.poweredBy), 'X-Powered-By: ' + headerReport.poweredBy)
  if (payload.metaGenerator) for (const g of Fingerprints.GENERATOR) if (g.re.test(payload.metaGenerator)) add(g.name, 'cms', Fingerprints.versionFrom(payload.metaGenerator), 'generator: ' + payload.metaGenerator)
  ;(headerReport.cookies || []).forEach((ck: any) => { for (const c of Fingerprints.COOKIE_TECH) if (c.re.test(ck.name)) add(c.name, 'session', null, 'cookie: ' + ck.name) })
  for (const u of (resources.scripts || []).concat(resources.css || [])) { for (const id of Fingerprints.identifyFromUrl(u)) add(id.name, 'library', id.version, 'resource: ' + UrlUtils.filenameOf(u)) }
  const html = payload.htmlEvidence || ''
  for (const p of Fingerprints.HTML_PATTERNS) if (p.re.test(html)) add(p.name, 'framework', null, 'html 特征')
  ;(windowVars || []).forEach((w) => { if (w.weak && (windowVars || []).some((x) => !x.weak && x.name === w.name)) return; add(w.name, 'framework', w.version, 'window.' + w.probe) })
  return Object.values(map).sort((a, b) => a.category.localeCompare(b.category) || a.name.localeCompare(b.name))
}

function detectWaf(headerReport: any, html: string): any[] {
  const pairs = headerReport.raw || []
  const names = new Set<string>(pairs.map((h: any) => h.name.toLowerCase()))
  const valMap: Record<string, string[]> = {}
  pairs.forEach((h: any) => { (valMap[h.name.toLowerCase()] = valMap[h.name.toLowerCase()] || []).push(h.value) })
  const cookies = headerReport.cookies || []
  const hits: any[] = []
  for (const rule of Fingerprints.WAF_RULES) {
    const ev: string[] = []
    ;(rule.headers || []).forEach((hd) => { if (names.has(hd.n.toLowerCase())) { if (!hd.v || (valMap[hd.n.toLowerCase()] || []).some((v) => hd.v!.test(v))) ev.push('header:' + hd.n) } })
    ;(rule.cookies || []).forEach((cr) => { cookies.forEach((ck: any) => { if (cr.test(ck.name)) ev.push('cookie:' + ck.name) }) })
    ;(rule.html || []).forEach((re) => { if (re.test(html)) ev.push('html 特征') })
    if (ev.length) hits.push({ name: rule.name, vendor: rule.vendor || '', evidence: Array.from(new Set(ev)).slice(0, 6), note: rule.note || '' })
  }
  return hits
}

// ---------------- 风险摘要 ----------------
function buildRisks(headerReport: any, js: any): any[] {
  const risks: any[] = []
  const push = (level: string, category: string, summary: string): void => { risks.push({ level, category, summary }) }
  if (js.findings.some((f: any) => f.severity === 'critical') || js.inlineFindings.some((f: any) => f.severity === 'critical')) push('critical', 'JS', 'JS/内联脚本中发现严重级密钥线索')
  const hi = js.findings.filter((f: any) => f.severity === 'high').length + js.inlineFindings.filter((f: any) => f.severity === 'high').length
  if (hi) push('high', 'JS', 'JS 中高危密钥/凭据线索 ' + hi + ' 类')
  if (js.sourcemaps.length) push('low', 'JS', '存在 ' + js.sourcemaps.length + ' 个 source map，可还原源码')
  ;(headerReport.missing || []).forEach((m: any) => { if (m.level === 'high') push('high', '响应头', m.header + ' 缺失：' + m.advice) })
  ;(headerReport.advisories || []).forEach((a: any) => { if (a.level === 'critical' || a.level === 'high') push(a.level, '配置', (a.detail || '') + ' — ' + a.advice) })
  const order: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }
  return risks.sort((a, b) => order[a.level] - order[b.level])
}

// ---------------- 主动探测（需用户点击 + 范围内） ----------------
/** 向 content script 下发一条指令，结果由页面经 content 回推；脚本未就绪时静默忽略 */
function askPage(tabId: number, action: string): void {
  try {
    chrome.tabs.sendMessage(tabId, { action }).catch(() => { /* content script 未注入或非 http 页 */ })
  } catch { /* */ }
}

async function injectAllIn(tabId: number): Promise<{ ok: boolean; injected: boolean; framework: string | null; error?: string }> {
  try {
    const ri = await detectRouterAndLive(tabId)
    const tech = TechStack.detect({ routerInfo: ri })
    const isVue = tech.framework.vue || tech.framework.react
    if (!isVue) {
      return { ok: true, injected: false, framework: null }
    }
    const fw = tech.framework.vue ? 'vue' : 'react'
    const [res] = await chrome.scripting.executeScript({
      target: { tabId },
      world: 'MAIN',
      files: ['all-in.js']
    })
    return { ok: true, injected: true, framework: fw }
  } catch (e: any) {
    return { ok: false, injected: false, framework: null, error: String(e) }
  }
}

async function runProbes(origin: string, host: string, tabId?: number): Promise<any> {
  if (!(await inScope(host))) return { ok: false, error: 'out_of_scope' }
  if (!(await getSettings()).activeProbe) return { ok: false, error: 'probe_disabled' }
  // 探测目标必须是合法 http(s) origin，拒绝脏数据发起的请求
  if (!UrlUtils.isHttpUrl(origin)) return { ok: false, error: 'bad-origin' }
  const results: any[] = []
  const probes = SensitiveRules.PATH_PROBES
  for (let i = 0; i < probes.length; i++) {
    const p = probes[i]
    const url = UrlUtils.joinPath(origin, p.path)
    let status = 0, bytes = 0, error: string | null = null, matched = false
    try {
      const ctrl = new AbortController()
      const to = setTimeout(() => ctrl.abort(), 5000)
      const r = await fetch(url, { method: 'GET', credentials: 'omit', redirect: 'follow', signal: ctrl.signal })
      clearTimeout(to)
      status = r.status
      let text = ''
      try { const buf = await r.text(); text = buf.slice(0, 20000); bytes = buf.length } catch { /* */ }
      const low = text.toLowerCase()
      matched = p.keywords.some((k) => low.includes(k.toLowerCase()))
      results.push({ path: p.path, status, bytes, matched: status >= 200 && status < 400 && matched, desc: p.desc, severity: p.severity })
    } catch (e: any) {
      error = String((e && e.message) || e)
      results.push({ path: p.path, status: 0, bytes: 0, matched: false, error, desc: p.desc, severity: p.severity })
    }
    await new Promise((res) => setTimeout(res, 250))
  }
  let routes: any = { applicable: false, reason: '未提供标签页，跳过路由探测' }
  let allInResult: any = { injected: false }
  try {
    if (tabId) {
      const tab = await chrome.tabs.get(tabId)
      const ri = await detectRouterAndLive(tabId)
      const tech = TechStack.detect({ routerInfo: ri })
      if (tech.decision.enableRouteProbe) routes = await probeRoutes({ routerInfo: ri, currentUrl: tab.url || '' })
      else routes = { applicable: false, reason: tech.decision.reason }
      if (tech.framework.vue || tech.framework.react) {
        allInResult = await injectAllIn(tabId)
        askPage(tabId, 'detectFramework')
        askPage(tabId, 'analyzeRouter')
        askPage(tabId, 'extractApi')
        askPage(tabId, 'getAllInStatus')
      }
    }
  } catch (e: any) {
    routes = { applicable: false, reason: String((e && e.message) || e) }
  }
  return { ok: true, results, routes, allIn: allInResult }
}

// ---------------- 结果落盘（全量优先，超配额才降级截断） ----------------
async function persistBundle(bundle: any): Promise<void> {
  try {
    await chrome.storage.local.set({ lastBundle: bundle })
    return
  } catch (e: any) {
    // 全量写失败（多为配额）时退回截断副本，绝不让整次采集白做
    await chrome.storage.local.set({ lastBundle: shrinkForStorage(bundle, String((e && e.message) || e)) })
    console.warn('[ReconX] bundle over quota, saved truncated copy:', e)
  }
}

// ---------------- 主收集流程 ----------------
async function collect(tabId: number): Promise<any> {
  let tab: chrome.tabs.Tab
  try { tab = await chrome.tabs.get(tabId) } catch { return { ok: false, error: 'tab-unreadable', hint: '无法读取该标签页，可能在 chrome:// 等受限页。' } }
  const pageUrl = UrlUtils.parseHttpUrl(tab.url)
  if (!pageUrl) return { ok: false, error: 'bad-url', hint: '当前页面 URL 不受支持。' }
  const host = pageUrl.hostname
  const isHttps = pageUrl.protocol === 'https:'
  if (!(await inScope(host))) return { ok: false, error: 'out_of_scope', hint: '该主机不在允许域范围内：请先在弹窗把它加入范围并完成授权。', host }
  const scope = await getScope()
  const settings = await getSettings()
  let payload: any
  try { payload = await collectDom(tabId) } catch (e: any) { return { ok: false, error: 'inject-failed', hint: '页面注入失败（' + String((e && e.message) || e) + '）。刷新页面后重试。', host } }
  if (!payload || !payload.ok) return { ok: false, error: 'collect-empty', hint: (payload && payload.error) || '未采集到页面数据。', host }

  const windowVars = await collectWindowVars(tabId)
  const cached = headersCache.get(host)
  let headerPairs = (cached && cached.main) || []
  let headerNote = ''
  if (!headerPairs.length) {
    try {
      const r = await fetch(tab.url as string, { credentials: 'omit', redirect: 'follow' })
      const arr: Array<{ name: string; value: string }> = []
      r.headers.forEach((v, k) => arr.push({ name: k, value: v }))
      headerPairs = arr
      headerNote = arr.length ? '主文档头来自 fetch 兜底（无法获取 Set-Cookie，Cookie 分析缺失，重新加载页面可补全）。' : '未捕获到主文档响应头，请在装好并授权本插件后刷新目标页面再采集。'
    } catch (e: any) { headerNote = '无法获取主文档响应头：' + String((e && e.message) || e) }
  }
  const headerReport = HeaderChecks.analyze(headerPairs, isHttps)
  const resources = buildResources(payload)
  const js = await scanJs(resources.scripts.concat(payload.resourceUrls || []), payload.inlineScripts, host, scope.hosts.map((h) => h.host), settings)
  const links = buildLinks(payload, host)
  const tech = buildTech(payload, headerReport, windowVars, resources)
  const waf = detectWaf(headerReport, payload.htmlEvidence || '')

  const bundle: any = {
    meta: { collectedAt: Date.now(), url: tab.url, title: payload.title, host, isHttps, inScope: true, scopeAddedAt: (scope.hosts.find((h) => h.host === host) || { addedAt: null }).addedAt, headerNote },
    links,
    resources: { scripts: resources.scripts.length, css: resources.css.length, images: resources.images.length, fonts: resources.fonts.length, data: resources.data.length, other: resources.other.length, scriptsList: resources.scripts.slice(0, 200) },
    tech, waf, headers: headerReport,
    js: { scanned: js.scanned, findings: js.findings, inlineFindings: js.inlineFindings, sourcemaps: js.sourcemaps },
    probes: { performed: false },
    risks: buildRisks(headerReport, js)
  }

  try {
    const routerInfo = await detectRouterAndLive(tabId)
    const extras = computeExtras({ tab: { url: tab.url as string }, host, js, routerInfo, links })
    bundle.routes = extras.routes
    bundle.api = extras.api
    bundle.security = extras.security
    if (bundle.links) bundle.links.classified = extras.classified
    if (extras.riskNote) bundle.risks.unshift(extras.riskNote)
    bundle.techStack = TechStack.detect({ headerReport, metaGenerator: payload.metaGenerator, resourceUrls: (resources.scripts || []).concat(resources.css || [], resources.data || []), htmlEvidence: payload.htmlEvidence, windowVars, routerInfo })
  } catch (e: any) {
    bundle.routes = { error: String((e && e.message) || e) }
  }

  await persistBundle(bundle)
  return { ok: true, bundle }
}

// ---------------- 实时状态写入（独立 key，不污染采集结果） ----------------
const liveQueue: Array<() => Promise<void>> = []
let liveProcessing = false

async function processLiveQueue(): Promise<void> {
  if (liveProcessing) return
  liveProcessing = true
  try {
    while (liveQueue.length > 0) {
      const task = liveQueue.shift()!
      // 单条失败（典型为 storage 配额超限）只记日志，不能中断后续任务
      try { await task() } catch (e) { console.error('[ReconX] live write failed:', e) }
    }
  } finally {
    liveProcessing = false
  }
}

function enqueueLive(patch: (s: LiveSnapshot) => void, attempt = 0): void {
  liveQueue.push(async () => {
    const stored = await chrome.storage.local.get('liveState')
    const next: LiveSnapshot = Object.assign({ updatedAt: Date.now() }, stored.liveState || {})
    patch(next)
    try {
      await chrome.storage.local.set({ liveState: next })
    } catch (e) {
      // 只补排一次：写入失败多为配额或瞬时抖动，重排到队尾等前序任务先落地。
      // 第二次仍失败则丢弃，避免持续超配额时无限自循环。
      if (attempt === 0) {
        console.warn('[ReconX] live write failed, requeued once:', e)
        enqueueLive(patch, 1)
      } else {
        console.error('[ReconX] live write failed after retry, dropped:', e)
      }
    }
  })
  processLiveQueue()
}

async function getLiveState(): Promise<LiveSnapshot> {
  const stored = await chrome.storage.local.get('liveState')
  return (stored.liveState as LiveSnapshot) || {}
}

chrome.runtime.onMessage.addListener((msg: any, sender, sendResponse) => {
  if (!msg) return

  // ---- content.ts 推送的 {action: 'reconxXXX'}：仅接受来自页面脚本的转发 ----
  if (msg.action && msg.action.startsWith('reconx')) {
    if (!sender || !sender.tab) return
    // 页面回传统一记录站点键（url-utils.getAllInSiteKey），供结果页区分回传来源
    const siteKey = UrlUtils.getAllInSiteKey(sender.tab.url)
    switch (msg.action) {
      case 'reconxFrameworkDetectionResult':
        enqueueLive((s) => { s.siteKey = siteKey; s.frameworkDetection = msg.result })
        break
      case 'reconxRouterAnalysisResult':
        enqueueLive((s) => { s.siteKey = siteKey; s.routerAnalysis = msg.result })
        break
      case 'reconxAllInStatus':
        enqueueLive((s) => { s.siteKey = siteKey; s.allInStatus = msg.status })
        break
      case 'reconxApiResult':
        enqueueLive((s) => { s.siteKey = siteKey; s.apiExtractResult = msg.result })
        break
      case 'reconxApiProgress':
      case 'reconxApiError':
      case 'reconxRouterAnalysisError':
      case 'reconxDetectorError':
        enqueueLive((s) => {
          s.siteKey = siteKey
          s.errors = Object.assign({}, s.errors, { [msg.action]: msg.result || msg.error })
        })
        break
    }
    return
  }

  // ---- UI 侧 {type: 'XXX'} 请求 ----
  if (!msg.type) return
  switch (msg.type) {
    case 'GET_STATE': {
      ;(async () => {
        const scope = await getScope()
        const settings = await getSettings()
        const { lastBundle } = await chrome.storage.local.get('lastBundle')
        const live = await getLiveState()
        sendResponse({
          ok: true, scope, settings,
          inScope: msg.host ? scope.hosts.some((h) => h.host === msg.host) : false,
          hasCache: msg.host ? !!((headersCache.get(msg.host) || { main: [] }).main.length) : false,
          lastBundle: lastBundle || null,
          live
        })
      })()
      return true
    }
    case 'ADD_HOST': {
      ;(async () => { await addHost(msg.host, msg.origin, msg.note); sendResponse({ ok: true }) })()
      return true
    }
    case 'REMOVE_HOST': {
      ;(async () => {
        const s = await removeHost(msg.host)
        try { if (msg.origin) await chrome.permissions.remove({ origins: [msg.origin] }) } catch { /* */ }
        sendResponse({ ok: true, scope: s })
      })()
      return true
    }
    case 'SET_SETTINGS': {
      ;(async () => {
        const cur = await getSettings()
        await chrome.storage.local.set({ settings: Object.assign(cur, msg.patch || {}) })
        // activeProbe 变化会决定常驻接管脚本是否注册，需同步重算
        await registerAllInContentScript()
        sendResponse({ ok: true })
      })()
      return true
    }
    case 'COLLECT': {
      collect(msg.tabId).then((r) => sendResponse(r)).catch((e) => sendResponse({ ok: false, error: 'exception', hint: String((e && e.message) || e) }))
      return true
    }
    case 'RUN_PROBES': {
      ;(async () => {
        const res = await runProbes(msg.origin, msg.host, msg.tabId)
        if (res.ok) {
          const live = await getLiveState()
          const { lastBundle } = await chrome.storage.local.get('lastBundle')
          // 无采集结果时不写探测结论，避免生成空壳 bundle
          if (lastBundle) {
            lastBundle.probes = {
              performed: true,
              results: res.results,
              routes: res.routes,
              allInStatus: live.allInStatus || null,
              allIn: res.allIn
            }
            await persistBundle(lastBundle)
          }
        }
        sendResponse(res)
      })()
      return true
    }
    case 'OPEN_RESULT': {
      chrome.tabs.create({ url: chrome.runtime.getURL('src/result/result.html') })
      sendResponse({ ok: true })
      return
    }
    case 'FORWARD_TO_CONTENT': {
      ;(async () => {
        if (!msg.tabId) { sendResponse({ ok: false, error: 'no-tabId' }); return }
        try {
          const resp = await chrome.tabs.sendMessage(msg.tabId, {
            action: msg.contentAction,
            forceRefresh: msg.forceRefresh || false
          })
          sendResponse({ ok: true, response: resp })
        } catch (e: any) {
          sendResponse({ ok: false, error: String((e && e.message) || e) })
        }
      })()
      return true
    }
  }
})

chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.local.get('settings').then((d) => { if (!d.settings) chrome.storage.local.set({ settings: DEFAULT_SETTINGS }) })
  registerAllInContentScript()
})

chrome.runtime.onStartup.addListener(() => {
  registerAllInContentScript()
})
// 统一导出中枢（自 lib/exporter.js 迁移为 ES 模块）
// 在扩展页面上下文（popup/result/options）通过 <a download> 触发下载；不依赖 chrome.downloads，纯 DOM。
import { generateBundleReportMarkdown } from './security-report'
import * as UrlUtils from './url-utils'
import { SEVERITY_ORDER } from './sensitive-rules'
import { confidenceOf, tierCn } from './confidence'
import { buildReviewWorklist } from './review'
import type { Severity } from '../types'

// 等级权重只有 sensitive-rules 一处定义，导出层不再自备副本
export const SEV_CN = { critical: '严重', high: '高危', medium: '中危', low: '低危', info: '提示', warn: '需核验', safe: '安全' } satisfies Record<Severity, string>

/** 安全取等级权重：字面量键表用 keyof 索引，未知等级排到末位，避免 any 下标静默返回 undefined */
const rank = (s: unknown): number => SEVERITY_ORDER[String(s) as keyof typeof SEVERITY_ORDER] ?? 99

function esc(s: any): string {
  return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
}
function escMd(s: any): string {
  return String(s == null ? '' : s).replace(/\|/g, '\\|').replace(/\r?\n/g, ' ')
}
function escCsv(s: any): string {
  let v = String(s == null ? '' : s)
  // 防 CSV 公式注入（CWE-1236）：目标可控字段若以 = + - @ 或制表/回车开头，
  // 在 Excel/WPS 打开导出 CSV 时会被当公式执行。前置单引号强制按文本处理。
  if (/^[=+\-@\t\r]/.test(v)) v = "'" + v
  return '"' + v.replace(/"/g, '""') + '"'
}
function stamp(): string {
  const n = new Date()
  const p = (x: number) => String(x).padStart(2, '0')
  return n.getFullYear() + p(n.getMonth() + 1) + p(n.getDate()) + '-' + p(n.getHours()) + p(n.getMinutes()) + p(n.getSeconds())
}

export function buildFilename(bundle: any, ext: string): string {
  // 统一走 url-utils：非法 URL 不抛错，退回 bundle.meta.host
  const host = UrlUtils.safeHostname(bundle.meta?.url).replace(/[^a-zA-Z0-9.-]/g, '_') || String(bundle.meta?.host || 'site').replace(/[^a-zA-Z0-9.-]/g, '_')
  return 'recon-' + host + '-' + stamp() + '.' + ext
}

export function download(filename: string, content: string, mime?: string): void {
  if (typeof document === 'undefined') throw new Error('download 只能在扩展页面(popup/result/options)调用，不能在 service worker 调用')
  const blob = new Blob([content], { type: (mime || 'text/plain') + ';charset=utf-8' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  a.remove()
  setTimeout(() => URL.revokeObjectURL(url), 20000)
}

export interface FindingItem {
  category: string
  title: string
  /** 统一用 Severity 字面量类型，索引 ORDER / SEV_CN 时编译期即可拦截非法等级 */
  level: Severity
  target?: string
  detail?: string
  description?: string
  evidence?: string[]
}

export function collectFindings(bundle: any): FindingItem[] {
  const items: FindingItem[] = []
  const add = (o: FindingItem): void => {
    items.push(o)
  }
  ;((bundle.js && bundle.js.findings) || []).concat((bundle.js && bundle.js.inlineFindings) || []).forEach((f: any) => {
    if (rank(f.severity) <= rank('medium')) add({ category: '敏感信息泄露', title: f.name, level: f.severity, target: f.url || 'inline', evidence: (f.samples || []).map((s: any) => s.value), description: f.desc })
  })
  ;((bundle.headers && bundle.headers.missing) || []).forEach((m: any) => {
    if (rank(m.level) <= rank('medium')) add({ category: '安全头', title: m.header + ' 缺失', level: m.level, evidence: [m.advice] })
  })
  ;((bundle.headers && bundle.headers.advisories) || []).forEach((a: any) => {
    if (rank(a.level) <= rank('medium')) add({ category: '配置', title: a.type, level: a.level, detail: a.detail, evidence: [a.advice] })
  })
  ;((bundle.js && bundle.js.sourcemaps) || []).forEach((s: any) => add({ category: '源码泄露', title: 'Source Map 可还原源码', level: 'low', target: s.from, evidence: [s.map] }))
  if (bundle.probes && bundle.probes.performed && bundle.probes.results) {
    bundle.probes.results.filter((p: any) => p.matched).forEach((p: any) => add({ category: '信息泄露', title: p.desc, level: p.severity, target: p.path, evidence: ['HTTP ' + p.status + ' / ' + p.bytes + ' bytes'] }))
  }
  ;(bundle.security && bundle.security.sensitiveApis ? bundle.security.sensitiveApis : []).forEach((s: any) => add({ category: '敏感 API', title: s.category || '敏感接口', level: s.riskLevel || 'medium', target: s.fullUrl || s.path, evidence: [s.matchedKeyword].filter(Boolean) }))
  ;(bundle.security && bundle.security.unauthorizedRoutes ? bundle.security.unauthorizedRoutes : []).forEach((r: any) => add({ category: '未授权访问路径', title: r.path, level: r.riskLevel || 'medium', evidence: [r.riskDescription].filter(Boolean) }))
  ;(bundle.links && bundle.links.classified ? bundle.links.classified : []).forEach((c: any) => {
    if (c.level === 'critical') add({ category: '敏感端点', title: (c.labels || []).join('/'), level: 'high', target: c.url, evidence: c.labels })
  })
  items.sort((a, b) => rank(a.level) - rank(b.level))
  return items
}

export function filterBundle(bundle: any, opts?: { minSeverity?: string; categories?: string[] }): any {
  const minRank = opts?.minSeverity ? rank(opts.minSeverity) : 99
  const keepCat = Array.isArray(opts?.categories) && opts!.categories!.length ? new Set(opts!.categories!) : null
  const bySev = (s: string) => (s in SEVERITY_ORDER ? rank(s) <= minRank : true)
  // structuredClone（Chrome 98+）：原生深拷贝，不再依赖 JSON 可序列化性
  const out = structuredClone(bundle)
  if (out.js) {
    const f = (arr: any[]) => (arr || []).filter((x) => bySev(x.severity))
    out.js.findings = f(out.js.findings)
    out.js.inlineFindings = f(out.js.inlineFindings)
  }
  if (out.headers) {
    out.headers.missing = (out.headers.missing || []).filter((x: any) => bySev(x.level))
    out.headers.advisories = (out.headers.advisories || []).filter((x: any) => bySev(x.level))
  }
  if (out.probes && out.probes.results) out.probes.results = out.probes.results.filter((p: any) => bySev(p.severity))
  if (out.security) {
    out.security.sensitiveApis = (out.security.sensitiveApis || []).filter((x: any) => bySev(x.riskLevel))
    out.security.unauthorizedRoutes = (out.security.unauthorizedRoutes || []).filter((x: any) => bySev(x.riskLevel))
  }
  if (out.links && out.links.classified) out.links.classified = out.links.classified.filter((x: any) => bySev(x.level))
  out.risks = (out.risks || []).filter((r: any) => bySev(r.level) && (!keepCat || keepCat.has(r.category)))
  return out
}

export const toJson = (b: any): string => JSON.stringify(b, null, 2)

export function toCsv(b: any): string {
  const rows: string[][] = [['section', 'level', 'name', 'target', 'detail', 'evidence']]
  collectFindings(b).forEach((f) => rows.push(['finding', f.level, f.title, f.target || '', f.description || f.detail || '', (f.evidence || []).join(' ; ')]))
  ;(b.tech || []).forEach((t: any) => rows.push(['tech', '', t.name + (t.version ? ' ' + t.version : ''), t.category, '', (t.evidence || []).join(' ; ')]))
  ;(b.waf || []).forEach((w: any) => rows.push(['waf', '', w.name, w.vendor || '', w.note || '', (w.evidence || []).join(' ; ')]))
  if (b.links) (b.links.endpoints || []).forEach((e: any) => rows.push(['endpoint', '', e.url, e.same ? 'same' : 'cross', e.ctx || '', (e.params || []).join(',')]))
  if (b.routes) (b.routes.allRoutes || []).forEach((r: any) => rows.push(['route', '', r.path, r.name || '', '', JSON.stringify(r.meta || {})]))
  return rows.map((r) => r.map(escCsv).join(',')).join('\r\n')
}

function counts(items: FindingItem[]): Record<string, number> {
  const c: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
  items.forEach((i) => {
    if (c[i.level] != null) c[i.level]++
  })
  return c
}

export function toMarkdown(b: any): string {
  const f = collectFindings(b)
  const c = counts(f)
  const L: string[] = []
  L.push('# Recon 采集报告 — ' + (b.meta.host || ''))
  L.push('')
  L.push('- 生成时间：' + new Date().toLocaleString('zh-CN'))
  L.push('- 目标 URL：' + (b.meta.url || ''))
  if (b.meta.favicon && b.meta.favicon.md5) L.push('- 图标指纹（favicon MD5）：`' + b.meta.favicon.md5 + '`（' + b.meta.favicon.url + '）')
  if (b.meta.headerNote) L.push('- 采集备注：' + b.meta.headerNote)
  L.push('')
  L.push('## 发现汇总')
  L.push('')
  L.push('| 严重 | 高危 | 中危 | 低危 | 提示 |')
  L.push('|---|---|---|---|---|')
  L.push('| ' + c.critical + ' | ' + c.high + ' | ' + c.medium + ' | ' + c.low + ' | ' + c.info + ' |')
  L.push('')
  L.push('## 技术栈')
  ;(b.tech || []).forEach((t: any) => L.push('- ' + t.name + (t.version ? ' ' + t.version : '') + '（' + t.category + '）' + (t.evidence && t.evidence[0] ? ' — ' + t.evidence[0] : '')))
  if (!b.tech || !b.tech.length) L.push('- （无）')
  L.push('')
  L.push('## WAF / 边缘防护线索')
  ;(b.waf || []).forEach((w: any) => L.push('- ' + w.name + (w.vendor ? ' (' + w.vendor + ')' : '') + ' — ' + (w.evidence || []).join(', ')))
  if (!b.waf || !b.waf.length) L.push('- （未发现）')
  L.push('')
  L.push('## 发现项（命中原文，需人工复核）')
  f.forEach((it, i) => {
    L.push('### ' + (i + 1) + '. [' + (SEV_CN[it.level] || it.level) + '] ' + it.category + '：' + it.title)
    if (it.target) L.push('- 位置：' + escMd(it.target))
    if (it.description) L.push('- 说明：' + it.description)
    if (it.detail) L.push('- 详情：' + escMd(it.detail))
    if (it.evidence && it.evidence.length) L.push('- 证据：' + it.evidence.map(escMd).join(' ; '))
    L.push('')
  })
  if (!f.length) L.push('- （无显著发现）')
  if (b.links) {
    L.push('## 端点与参数')
    L.push('- 端点总数 ' + b.links.total + '，同源 ' + b.links.sameOriginCount)
    ;(b.links.params || []).slice(0, 40).forEach((p: any) => L.push('  - 参数 `' + p.name + '` ×' + p.count))
    if (b.js && b.js.baseUrls && b.js.baseUrls.length) {
      L.push('- 推断的后端基址（axios baseURL / env / JS 内域名）：')
      b.js.baseUrls.slice(0, 30).forEach((u: any) => L.push('  - `' + u.value + '`（' + u.kind + '｜来源 ' + (u.sources || []).join(', ') + '）'))
    }
    L.push('')
  }
  if (b.probes && b.probes.performed) {
    L.push('## 主动探测')
    L.push('> 置信度：严重度基线 + 响应状态综合（200 直接暴露↑、401/403 存在但被守↓）；被人工标记误报者判为"存疑"。分级只影响阅读优先级，不移除任何命中。')
    ;(b.probes.results || []).filter((p: any) => p.matched).forEach((p: any) => {
      const cf = confidenceOf({ severity: String(p.severity || '').toLowerCase(), status: p.status })
      L.push('- [' + (SEV_CN[p.severity as keyof typeof SEV_CN] || p.severity) + '] ' + p.path + ' -> ' + p.status + '（置信 ' + tierCn(cf.tier) + ' ' + cf.score + '） ' + p.desc)
    })
    L.push('')
  }
  const wl = buildReviewWorklist(b, (b.meta && b.meta.host) || '', new Set())
  if (wl.length) {
    const kindShort: Record<string, string> = { finding: '发现', api: '敏感接口', probe: '探测', route: '路由' }
    L.push('## 复核优先级（按置信降序，前 15 条）')
    L.push('')
    L.push('> 把 JS 发现 / 敏感接口 / 主动探测三类命中汇成一张待复核清单；置信 = 严重度基线 + 来源佐证 + 探测状态。导出为完整取证材料，不含个人误报标记。')
    wl.slice(0, 15).forEach((it, i) => L.push('- ' + (i + 1) + '. [' + tierCn(it.confidence.tier) + ' ' + it.confidence.score + '] ' + (kindShort[it.kind] || it.kind) + ' · ' + it.label + '（' + it.detail + '）'))
    L.push('')
  }
  L.push('## 测试范围与未覆盖项')
  L.push('')
  L.push('本次为浏览器侧被动侦察 + 有限主动探测，以下攻击面**未纳入**，不得据此报告判定为"未发现漏洞"：')
  L.push('- 注入类（SQL / NoSQL / XSS / SSRF / XXE / SSTI / 命令注入）：未做任何 payload 探测')
  L.push('- 架构层（文件上传 / 路径穿越 / 反序列化 / 原型污染 / 请求走私 / 竞态）：未测试')
  L.push('- 认证与授权（登录绕过 / JWT / OAuth / 越权 IDOR / GraphQL 深度）：未测试，路由鉴权判定仅来自前端 meta，非服务端核验')
  L.push('- 后端逻辑、业务流、速率限制、会话管理：未触及')
  L.push('- 主动探测默认仅命中敏感路径状态码比对，未做响应体深度关联或绕过')
  if (!(b.probes && b.probes.performed)) L.push('- 本次未执行主动探测（敏感路径 / 路由可达性均未发起请求）')
  L.push('')
  L.push('如需上述任一维度，须在授权范围内由人工渗透另测；本报告只如实反映已采集到的线索与已探测到的面。')
  L.push('')
  L.push('---')
  L.push('> 仅用于已授权目标（渗透测试/漏洞赏金/OSINT/自查）。命中皆为线索，需人工确认。')
  return L.join('\n')
}

export function toSrcMarkdown(b: any): string {
  const f = collectFindings(b)
  const L: string[] = []
  L.push('# SRC 漏洞提交草稿 — ' + (b.meta.host || ''))
  L.push('')
  L.push('- 目标资产：' + (b.meta.url || ''))
  L.push('- 发现数量：' + f.length)
  L.push('- 提示：以下为基于自动采集的草稿骨架，请按实际验证补充复现步骤与 PoC 后再提交。')
  L.push('')
  if (!f.length) L.push('（无可用发现）')
  f.forEach((it, i) => {
    L.push('## ' + (i + 1) + '. ' + it.title + '　【' + (SEV_CN[it.level] || it.level) + '】')
    L.push('')
    L.push('- **类型**：' + it.category)
    L.push('- **影响 URL/路径**：' + (it.target || '—'))
    L.push('- **证据（原文）**：' + (it.evidence || []).map(escMd).join(' ; ') + ' ' + (it.detail ? '/ ' + escMd(it.detail) : ''))
    L.push('- **复现步骤**：（待补充）')
    L.push('- **影响说明**：（待补充，结合业务）')
    L.push('- **修复建议**：' + (it.description ? it.description + '（请据此评估）' : '（待补充）'))
    L.push('')
  })
  return L.join('\n')
}

export function toHtml(b: any): string {
  const f = collectFindings(b)
  const c = counts(f)
  const chip = (k: string, v: number): string => '<div class="chip"><b>' + v + '</b><span>' + k + '</span></div>'
  const find = (it: FindingItem): string =>
    '<tr><td><span class="lvl ' + it.level + '">' + (SEV_CN[it.level] || it.level) + '</span></td><td>' + esc(it.category) + '</td><td>' + esc(it.title) + '</td><td class="mono">' + esc(it.target || '') + '</td><td>' + esc((it.evidence || []).join(' ; ')) + '</td></tr>'
  const tech = (b.tech || []).map((t: any) => '<li>' + esc(t.name + (t.version ? ' ' + t.version : '')) + ' <i>(' + esc(t.category) + ')</i></li>').join('')
  const waf = (b.waf || []).map((w: any) => '<li>' + esc(w.name) + ' — ' + esc((w.evidence || []).join(', ')) + '</li>').join('')
  return (
    '<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Recon ' + esc(b.meta.host) + '</title><style>' +
    ":root{--b:#0f1620;--p:#16212e;--i:#d7e2ee;--m:#7c8c9e;--a:#2dd4bf;--l:#223043}body{margin:0;font:14px/1.6 system-ui,'Microsoft YaHei',sans-serif;background:var(--b);color:var(--i)}" +
    '.wrap{max-width:980px;margin:0 auto;padding:24px 18px 60px}h1{color:var(--a)}h2{margin-top:26px;border-left:3px solid var(--a);padding-left:8px}.mono{font-family:Consolas,monospace;font-size:12px;word-break:break-all}' +
    '.meta{color:var(--m);font-size:13px}.chips{display:flex;gap:10px;flex-wrap:wrap;margin:14px 0}.chip{background:var(--p);border:1px solid var(--l);border-radius:10px;padding:8px 14px}.chip b{display:block;font-size:20px;color:var(--a)}' +
    'table{width:100%;border-collapse:collapse;margin:10px 0}th,td{border-bottom:1px solid var(--l);padding:6px 8px;text-align:left;vertical-align:top;font-size:13px}th{color:var(--m)}' +
    "ul{padding-left:18px}.lvl{padding:1px 6px;border-radius:4px;font-size:12px;font-weight:700}.lvl.critical{background:#4a0d0d;color:#ff8a80}.lvl.high{background:#5a1500;color:#ffab91}.lvl.medium{background:#4a3600;color:#ffe082}.lvl.low{background:#0b3a4a;color:#80deea}.lvl.info{background:#243042;color:#9ab}" +
    'footer{color:var(--m);margin-top:30px;border-top:1px solid var(--l);padding-top:12px;font-size:12px}' +
    '</style></head><body><div class="wrap"><h1>Recon 采集报告</h1>' +
    '<div class="meta">目标：' + esc(b.meta.url) + ' ｜ 生成：' + new Date().toLocaleString('zh-CN') + (b.meta.favicon && b.meta.favicon.md5 ? ' ｜ 图标指纹：' + esc(b.meta.favicon.md5) : '') + '</div>' +
    '<div class="chips">' + chip('严重', c.critical) + chip('高危', c.high) + chip('中危', c.medium) + chip('低危', c.low) + chip('端点', b.links ? b.links.total : 0) + '</div>' +
    '<h2>发现项（命中原文）</h2><table><thead><tr><th>等级</th><th>类别</th><th>标题</th><th>位置</th><th>证据</th></tr></thead><tbody>' + (f.map(find).join('') || '<tr><td colspan=5>无</td></tr>') + '</tbody></table>' +
    '<h2>技术栈</h2><ul>' + (tech || '<li>无</li>') + '</ul>' +
    '<h2>WAF / 边缘防护</h2><ul>' + (waf || '<li>未发现</li>') + '</ul>' +
    '<footer>本报告由 ReconX 生成，仅用于已授权目标。命中皆为线索，需人工确认。</footer></div></body></html>'
  )
}

export function toTxtEndpoints(b: any): string {
  const L: string[] = ['# Recon 端点导出', '# 目标: ' + (b.meta.url || ''), '# 时间: ' + new Date().toLocaleString(), '', '## 全部 URL（Burp Intruder/Scanner 可直接粘贴）']
  const seen = new Set<string>()
  ;(b.links ? b.links.endpoints : []).forEach((e: any) => {
    if (!seen.has(e.url)) {
      seen.add(e.url)
      L.push(e.url)
    }
  })
  if (b.routes && b.routes.fullUrls) {
    L.push('', '## 路由完整 URL')
    b.routes.fullUrls.forEach((r: any) => {
      if (!seen.has(r.url)) {
        seen.add(r.url)
        L.push(r.url)
      }
    })
  }
  return L.join('\n')
}

export interface GeneratorDef {
  fn: (b: any) => string
  ext: string
  mime: string
}
export const GENERATORS: Record<string, GeneratorDef> = {
  json: { fn: (b) => toJson(b), ext: 'json', mime: 'application/json' },
  csv: { fn: (b) => toCsv(b), ext: 'csv', mime: 'text/csv' },
  md: { fn: (b) => toMarkdown(b), ext: 'md', mime: 'text/markdown' },
  src: { fn: (b) => toSrcMarkdown(b), ext: 'md', mime: 'text/markdown' },
  html: { fn: (b) => toHtml(b), ext: 'html', mime: 'text/html' },
  txt: { fn: (b) => toTxtEndpoints(b), ext: 'txt', mime: 'text/plain' }
}

export function exportBundle(bundle: any, fmt: string | string[], opts?: { minSeverity?: string; categories?: string[]; download?: boolean }): any {
  opts = opts || {}
  const b = filterBundle(bundle, opts)
  const list = Array.isArray(fmt) ? fmt : [fmt]
  const made: Array<{ fmt: string; filename: string; content: string }> = []
  list.forEach((k) => {
    const g = GENERATORS[k]
    if (!g) return
    const content = g.fn(b)
    const filename = buildFilename(b, g.ext)
    if (opts!.download === false) made.push({ fmt: k, filename, content })
    else download(filename, content, g.mime)
  })
  return made.length ? made : { ok: true }
}

export function exportMulti(bundles: any[], fmt: string): void {
  const merged: any = { meta: { host: 'multi-' + bundles.length, url: '(多目标聚合 ' + bundles.length + ' 个)', collectedAt: Date.now(), headerNote: '' }, tech: [], waf: [], links: { total: 0, sameOriginCount: 0, endpoints: [], params: [] }, js: { findings: [], inlineFindings: [], sourcemaps: [] }, headers: { missing: [], advisories: [], raw: [] }, risks: [], _targets: [] }
  bundles.forEach((b) => {
    merged._targets.push({ host: b.meta.host, url: b.meta.url, time: b.meta.collectedAt })
    merged.tech = merged.tech.concat((b.tech || []).map((t: any) => Object.assign({ host: b.meta.host }, t)))
    merged.waf = merged.waf.concat((b.waf || []).map((t: any) => Object.assign({ host: b.meta.host }, t)))
    merged.js.findings = merged.js.findings.concat((b.js && b.js.findings) || [])
    merged.js.sourcemaps = merged.js.sourcemaps.concat((b.js && b.js.sourcemaps) || [])
    merged.headers.missing = merged.headers.missing.concat((b.headers && b.headers.missing) || [])
    if (b.links) {
      merged.links.total += b.links.total
      merged.links.sameOriginCount += b.links.sameOriginCount
      merged.links.endpoints = merged.links.endpoints.concat(b.links.endpoints || [])
    }
  })
  const g = GENERATORS[fmt] || GENERATORS.md
  const content = g.fn(merged)
  download('recon-multi-' + bundles.length + '-' + stamp() + '.' + g.ext, content, g.mime)
}

export function exportJson(obj: any, name: string): void {
  download(name + '-' + stamp() + '.json', JSON.stringify(obj, null, 2), 'application/json')
}

export function parseJson(text: string): { ok: boolean; data?: any; error?: string } {
  try {
    return { ok: true, data: JSON.parse(text) }
  } catch (e: any) {
    return { ok: false, error: String((e && e.message) || e) }
  }
}

/** 导出综合报告 Markdown（含梭哈模式拦截统计、路由分析、API 提取、安全审计） */
export function exportFullReport(bundle: any, pageUrl: string): void {
  const content = generateBundleReportMarkdown(bundle, pageUrl)
  const filename = buildFilename(bundle, 'md')
  download(filename, content, 'text/markdown')
}
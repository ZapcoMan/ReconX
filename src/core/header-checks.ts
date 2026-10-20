// 安全响应头 / Cookie / CORS / CSP 配置分析（自 lib/header-checks.js 迁移为 ES 模块）
import type { HeaderPair } from '../types'

export interface SecurityHeaderSpec {
  header: string
  httpsOnly: boolean
  ifMissing: string
  advice: string
  alt?: string
}

export const SECURITY_HEADERS: SecurityHeaderSpec[] = [
  { header: 'Content-Security-Policy', httpsOnly: false, ifMissing: 'medium', advice: '缺少 CSP，难以约束脚本注入面' },
  { header: 'Strict-Transport-Security', httpsOnly: true, ifMissing: 'high', advice: 'HTTPS 站点缺少 HSTS，存在降级/中间人风险' },
  { header: 'X-Frame-Options', httpsOnly: false, ifMissing: 'low', advice: '缺少点击劫持防护（也可用 CSP frame-ancestors）', alt: 'Content-Security-Policy' },
  { header: 'X-Content-Type-Options', httpsOnly: false, ifMissing: 'low', advice: '建议 nosniff，避免 MIME 嗅探' },
  { header: 'Referrer-Policy', httpsOnly: false, ifMissing: 'low', advice: '建议显式 Referrer-Policy，控制 Referer 泄露' },
  { header: 'Permissions-Policy', httpsOnly: false, ifMissing: 'info', advice: '可选：用 Permissions-Policy 收敛摄像头/麦克风等能力' }
]

export interface ParsedCookie {
  name: string
  valueMasked: string
  path: string | null
  domain: string | null
  secure: boolean
  httponly: boolean
  samesite: string | null
  maxage: string | null
  expires: string | null
  sessionish?: boolean
  flags?: string[]
}

export function mask(value: string | number | boolean | null): string {
  const v = String(value || '')
  if (!v) return ''
  if (v.length <= 8) return '*'.repeat(6)
  return v.slice(0, 3) + '…' + v.slice(-3)
}

export function parseSetCookie(raw: string): ParsedCookie {
  const parts = String(raw).split(';')
  const first = parts[0] || ''
  const eq = first.indexOf('=')
  const name = eq >= 0 ? first.slice(0, eq).trim() : first.trim()
  const value = eq >= 0 ? first.slice(eq + 1).trim() : ''
  const attrs: Record<string, string | boolean> = {}
  for (let i = 1; i < parts.length; i++) {
    const seg = parts[i].trim()
    if (!seg) continue
    const e2 = seg.indexOf('=')
    const k = (e2 >= 0 ? seg.slice(0, e2) : seg).toLowerCase()
    attrs[k] = e2 >= 0 ? seg.slice(e2 + 1).trim() : true
  }
  return {
    name,
    valueMasked: mask(value),
    path: (attrs.path as string) || null,
    domain: typeof attrs.domain === 'string' ? attrs.domain : null,
    secure: 'secure' in attrs,
    httponly: 'httponly' in attrs,
    samesite: typeof attrs.samesite === 'string' ? attrs.samesite.toLowerCase() : null,
    maxage: typeof attrs['max-age'] === 'string' ? attrs['max-age'] : null,
    expires: typeof attrs.expires === 'string' ? attrs.expires : null
  }
}

const SESSION_COOKIE = /(session|sess|sid|auth|token|logged|login|jwt|laravel|wordpress|phpsess|jsession|asp\.net|connect\.sid|remember|csrf)/i

export interface CspResult {
  directives: Record<string, string[]> | null
  raw: string | null
}

export function parseCSP(value: string | null): CspResult {
  const directives: Record<string, string[]> = {}
  if (!value) return { directives: null, raw: null }
  String(value)
    .split(';')
    .forEach((d) => {
      const t = d.trim().split(/\s+/)
      if (!t[0]) return
      directives[t[0].toLowerCase()] = t.slice(1)
    })
  return { directives, raw: String(value) }
}

export interface Advisory {
  type: string
  header?: string
  level: string
  detail?: string
  advice: string
}
export interface MissingHeader {
  header: string
  level: string
  advice: string
}
export interface HeaderReport {
  raw: HeaderPair[]
  server: string | null
  poweredBy: string | null
  present: Record<string, string>
  missing: MissingHeader[]
  advisories: Advisory[]
  cookies: ParsedCookie[]
  cors: Record<string, any>
  csp: CspResult | null
  summary: Record<string, number>
}

export function analyze(headerPairs: HeaderPair[] | null | undefined, isHttps: boolean): HeaderReport {
  headerPairs = headerPairs || []
  const lower: Record<string, string[]> = {}
  for (const hp of headerPairs) {
    const n = String(hp.name || '').toLowerCase()
    ;(lower[n] = lower[n] || []).push(hp.value)
  }
  const first = (n: string): string | null => (lower[n] && lower[n][0]) || null

  const present: Record<string, string> = {}
  const advisories: Advisory[] = []
  const missing: MissingHeader[] = []

  SECURITY_HEADERS.forEach((spec) => {
    const key = spec.header.toLowerCase()
    const val = first(key)
    const cspObj = key === 'x-frame-options' ? parseCSP(first('content-security-policy')).directives : null
    const coveredByAlt = key === 'x-frame-options' && cspObj && cspObj['frame-ancestors']
    if (val) {
      present[spec.header] = val
    } else if (spec.httpsOnly && !isHttps) {
      // 非 https 跳过 https-only 要求
    } else if (coveredByAlt) {
      present['X-Frame-Options (via CSP frame-ancestors)'] = (cspObj!['frame-ancestors'] || []).join(' ')
    } else {
      missing.push({ header: spec.header, level: spec.ifMissing, advice: spec.advice })
    }
  })

  const server = first('server')
  const powered = first('x-powered-by')
  if (server && /\d/.test(server))
    advisories.push({ type: 'info-disclosure', header: 'Server', level: 'low', detail: server, advice: 'Server 头暴露产品/版本，建议脱敏' })
  if (powered)
    advisories.push({ type: 'info-disclosure', header: 'X-Powered-By', level: 'low', detail: powered, advice: '建议移除或改写 X-Powered-By' })

  const xxp = first('x-xss-protection')
  if (xxp) advisories.push({ type: 'deprecated', header: 'X-XSS-Protection', level: 'info', detail: xxp, advice: '该头已废弃，现代浏览器忽略，建议改用 CSP' })

  const aollo = first('access-control-allow-origin')
  const acac = String(first('access-control-allow-credentials') || '').toLowerCase()
  const cors: Record<string, any> = {
    allowOrigin: aollo,
    allowCredentials: acac === 'true',
    allowMethods: first('access-control-allow-methods'),
    allowHeaders: first('access-control-allow-headers')
  }
  if (aollo === '*') {
    advisories.push({
      type: 'cors',
      level: acac === 'true' ? 'critical' : 'high',
      detail: 'Access-Control-Allow-Origin: *',
      advice: acac === 'true' ? '通配来源 + 允许凭据，跨站读取风险' : '通配来源，任意站点可读取响应（视内容而定）'
    })
  } else if (aollo && aollo !== 'null') {
    advisories.push({ type: 'cors', level: 'info', detail: 'ACAO=' + aollo, advice: '存在 CORS 白名单，建议在授权范围内测试是否回显任意 Origin' })
  }

  const csp = parseCSP(first('content-security-policy'))
  if (csp.directives) {
    const flat = JSON.stringify(csp.directives)
    if (/'unsafe-inline'/.test(flat)) advisories.push({ type: 'csp', level: 'medium', detail: "'unsafe-inline'", advice: 'CSP 允许 inline，弱化对 XSS 的约束' })
    if (/'unsafe-eval'/.test(flat)) advisories.push({ type: 'csp', level: 'medium', detail: "'unsafe-eval'", advice: 'CSP 允许 eval，扩大注入利用面' })
    const ds = csp.directives['default-src'] || []
    const ss = csp.directives['script-src'] || ds
    if (ss.includes('*') || ds.includes('*')) advisories.push({ type: 'csp', level: 'high', detail: 'script-src/default-src = *', advice: '脚本来源通配，等同无 CSP' })
    if (!csp.directives['object-src'] && !ds.includes("'none'")) advisories.push({ type: 'csp', level: 'low', detail: 'object-src 未限制', advice: "建议 object-src 'none'" })
    if (!csp.directives['report-to'] && !csp.directives['report-uri']) advisories.push({ type: 'csp', level: 'info', detail: '无 violation 上报', advice: '可配置 report-to/report-uri 监测拦截' })
  }

  const cookies: ParsedCookie[] = (lower['set-cookie'] || []).map((c) => parseSetCookie(c))
  cookies.forEach((ck) => {
    const sessionish = SESSION_COOKIE.test(ck.name)
    ck.sessionish = sessionish
    ck.flags = []
    if (sessionish && !ck.httponly) {
      ck.flags.push('会话 Cookie 缺少 HttpOnly')
      advisories.push({ type: 'cookie', level: 'medium', detail: ck.name, advice: '会话 Cookie 缺 HttpOnly，可被 XSS 窃取' })
    }
    if (isHttps && !ck.secure) {
      ck.flags.push('HTTPS 下缺少 Secure')
      advisories.push({ type: 'cookie', level: 'medium', detail: ck.name, advice: 'Cookie 缺 Secure 标记，可能经明文传输' })
    }
    if (ck.samesite === 'none' && !ck.secure) {
      ck.flags.push('SameSite=None 未带 Secure')
      advisories.push({ type: 'cookie', level: 'high', detail: ck.name, advice: 'SameSite=None 必须配合 Secure，否则浏览器会丢弃' })
    }
    if (!ck.samesite) ck.flags.push('缺少 SameSite')
    if (ck.domain && ck.domain.startsWith('.'))
      advisories.push({ type: 'cookie', level: 'info', detail: ck.name + ' Domain=' + ck.domain, advice: 'Cookie 作用域为父域，范围较宽' })
  })

  const cacheCtl = first('cache-control')
  if (cacheCtl && /public/i.test(cacheCtl) && (lower['set-cookie'] || []).length) {
    advisories.push({ type: 'cache', level: 'medium', detail: 'Cache-Control: public 且下发 Set-Cookie', advice: '带凭据的响应被公共缓存，存在敏感信息缓存风险' })
  }

  const counts: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
  const order: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }
  missing.forEach((m) => counts[m.level]++)
  advisories.forEach((a) => counts[a.level]++)
  advisories.sort((a, b) => order[a.level] - order[b.level])
  missing.sort((a, b) => order[a.level] - order[b.level])

  return {
    raw: headerPairs.map((hp) => ({ name: hp.name, value: hp.value })),
    server,
    poweredBy: powered,
    present,
    missing,
    advisories,
    cookies,
    cors,
    csp: csp.directives ? csp : null,
    summary: counts
  }
}

// API 端点静态提取（自 lib/api-extract.js 迁移为 ES 模块，纯只读分析）
export const STATIC_EXT_RE = /\.(js|mjs|css|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|otf|map|html?|mp4|webp|webm|pdf|zip|txt)(\?|$)/i
export const API_PREFIX_RE = /\/(api|apis|apiv\d|v\d{1,2}|rest|gateway|gw|svc|service|services|auth|oauth|sso|login|logout|register|user|users|admin|sys|system|manage|manager|mgr|portal|open|openapi|internal|backend|server|rpc|graphql)(\/|$)/i
export const REL_API_PREFIX_RE = /^(api|apis|apiv\d|v\d{1,2}|rest|gateway|gw|svc|service|services|auth|oauth|sso|login|logout|register|user|users|admin|sys|system|manage|manager|mgr|portal|open|openapi|internal|backend|server|rpc|graphql)(\/|$)/i
export const STATIC_DIR_RE = /^(\/)?(assets|static|img|images|fonts|icons|css|js|dist|build|public|vendor|lib|libs|media|file|files)(\/|$)/i
export const ACTION_WORD_RE = /(get|list|query|create|add|update|edit|del|delete|remove|export|import|upload|download|search|find|save|submit|check|verify|send|login|logout|register|info|detail|page|count|stat|log|audit|menu|role|perm|token|captcha|sms|mail|notify|order|pay|bill|account)/i

export function isApiLikePath(path: string): boolean {
  if (!path || path.length < 4 || path.length > 200) return false
  if (path.indexOf('//') === 0) return false
  if (STATIC_EXT_RE.test(path)) return false
  const segs = path.split('/').filter(Boolean)
  if (segs.length < 2) return false
  if (STATIC_DIR_RE.test(path)) return false
  if (API_PREFIX_RE.test(path)) return true
  if (ACTION_WORD_RE.test(path)) return true
  return false
}

export function isApiLikeRelativePath(path: string): boolean {
  if (!path || path.length < 6 || path.length > 200) return false
  if (path.indexOf('/') === -1) return false
  if (/^https?:|^\.\.?\/|^\//.test(path)) return false
  if (STATIC_EXT_RE.test('/' + path)) return false
  const segs = path.split('/').filter(Boolean)
  if (segs.length < 2) return false
  const allShort = segs.every((s) => /^[a-z0-9_\-]{1,6}$/i.test(s))
  if (allShort && !REL_API_PREFIX_RE.test(path) && !ACTION_WORD_RE.test(path)) return false
  return REL_API_PREFIX_RE.test(path) || ACTION_WORD_RE.test(path)
}

export function cleanTemplatePath(path: string): string {
  return path
    .replace(/\$\{[^}]*\}/g, '')
    .replace(/:[A-Za-z0-9_]+/g, '')
    .replace(/\{[^}]*\}/g, '')
}

export function fillTemplateParams(pathname: string): string {
  return pathname
    .replace(/\$\{[^}]*\}/g, '1')
    .replace(/:([A-Za-z_][A-Za-z0-9_]*)(?=[/#?]|$)/g, '1')
    .replace(/\{[^}]*\}/g, '1')
}

export function buildFullUrl(path: string, origin: string): string {
  if (/^https?:\/\//i.test(path)) {
    try {
      const u = new URL(path)
      u.pathname = fillTemplateParams(u.pathname)
      return u.href
    } catch {
      return path
    }
  }
  const normalized = path.charAt(0) === '/' ? path : '/' + path
  return origin + fillTemplateParams(normalized)
}

export interface EndpointEntry {
  path: string
  sources: string[]
}
export type EndpointsAccumulator = Record<string, EndpointEntry>

export function extractFromText(text: string, endpoints: EndpointsAccumulator, sourceLabel?: string): void {
  const add = (p: string): void => {
    if (!p) return
    if (!endpoints[p]) endpoints[p] = { path: p, sources: [] }
    const e = endpoints[p]
    if (sourceLabel && e.sources.indexOf(sourceLabel) < 0 && e.sources.length < 5) e.sources.push(sourceLabel)
  }
  const stringRe = /(["'`])((?:\/)[A-Za-z0-9_\-./:{}$]+)\1/g
  const relStringRe = /(["'`])(?!\/|https?:\/\/|\.\.?\/)([A-Za-z0-9_\-./:{}$]+)\1/g
  const urlRe = /(["'`])(https?:\/\/[A-Za-z0-9_\-./:{}$]+)\1/g
  let m: RegExpExecArray | null
  while ((m = stringRe.exec(text)) !== null) {
    if (isApiLikePath(m[2])) add(m[2])
  }
  while ((m = relStringRe.exec(text)) !== null) {
    if (isApiLikeRelativePath(m[2])) add(m[2])
  }
  while ((m = urlRe.exec(text)) !== null) {
    try {
      const u = new URL(m[2])
      if (API_PREFIX_RE.test(u.pathname)) add(m[2])
    } catch {
      /* ignore */
    }
  }
}

export interface StaticApiItem {
  path: string
  fullUrl: string
  hasParams: boolean
  sources: string[]
  called: boolean
}

export function finalize(endpoints: EndpointsAccumulator, livePathnames: string[] | null | undefined, origin: string): StaticApiItem[] {
  const list = Object.keys(endpoints).map((path) => ({
    path,
    fullUrl: buildFullUrl(path, origin),
    hasParams: /(\$\{[^}]*\}|\/:[A-Za-z_][A-Za-z0-9_]*|\{[^}]*\})/.test(path),
    sources: endpoints[path].sources,
    called: (livePathnames || []).some((lp) => {
      const cleaned = cleanTemplatePath(path)
      return lp === cleaned || (cleaned.length > 1 && lp.indexOf(cleaned) === 0)
    })
  }))
  list.sort((a, b) => a.path.localeCompare(b.path))
  return list
}

export interface PerfEntry {
  name: string
  initiatorType: string
}
export interface LiveApiItem {
  url: string
  path: string
}

export function buildLiveApis(entries: PerfEntry[] | null | undefined): LiveApiItem[] {
  const out: LiveApiItem[] = []
  const seen: Record<string, number> = Object.create(null)
  ;(entries || []).forEach((en) => {
    const t = en.initiatorType
    if (t !== 'xmlhttprequest' && t !== 'fetch') return
    let u: URL
    try {
      u = new URL(en.name)
    } catch {
      return
    }
    if (!/^https?:$/.test(u.protocol)) return
    if (STATIC_EXT_RE.test(u.pathname)) return
    if (seen[en.name]) return
    seen[en.name] = 1
    out.push({ url: en.name, path: u.pathname + (u.search || '') })
  })
  return out
}

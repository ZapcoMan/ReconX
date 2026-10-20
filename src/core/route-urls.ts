// 路由 → 完整 URL 生成（自 lib/route-urls.js 迁移为 ES 模块，只读分析）
import type { RouteEntry } from '../types'

export function cleanUrl(url: string): string {
  return url.replace(/([^:]\/)\/+/g, '$1').replace(/\/$/, '')
}
export function normalizeUrl(url: string): string {
  if (!url || typeof url !== 'string') return ''
  return cleanUrl(url.trim())
}
export function urlsEqual(l: string, r: string): boolean {
  return normalizeUrl(l) === normalizeUrl(r)
}

export function normalizeBasePath(basePath: string | null | undefined): string {
  if (!basePath || typeof basePath !== 'string') return ''
  let n = basePath.trim().replace(/\\/g, '/')
  if (!n || n === '/' || n.indexOf('#') >= 0) return ''
  if (/^[a-z][a-z\d+.-]*:\/\//i.test(n)) return ''
  const q = n.indexOf('?')
  if (q >= 0) n = n.substring(0, q)
  if (n.charAt(0) !== '/') n = '/' + n
  n = cleanUrl(n)
  return n === '/' ? '' : n
}

export function normalizeRoutePath(path: string | null | undefined): string {
  if (!path || typeof path !== 'string') return '/'
  const t = path.trim()
  if (!t) return '/'
  const withSlash = t.charAt(0) === '/' ? t : '/' + t
  return cleanUrl(withSlash) || '/'
}

export function dedupeRoutes(routes: RouteEntry[] | null | undefined): RouteEntry[] {
  const seen = new Set<string>()
  return (routes || []).reduce<RouteEntry[]>((acc, route) => {
    if (!route || typeof route !== 'object' || !route.path || typeof route.path !== 'string') return acc
    const np = normalizeRoutePath(route.path)
    if (seen.has(np)) return acc
    seen.add(np)
    acc.push(Object.assign({}, route, { path: np }))
    return acc
  }, [])
}

export interface UrlItem {
  path?: string
  url: string
}
export function dedupeUrlItems(items: UrlItem[] | null | undefined): UrlItem[] {
  const seen = new Set<string>()
  return (items || []).filter((it) => {
    const n = normalizeUrl((it && it.url) || '')
    if (!n || seen.has(n)) return false
    seen.add(n)
    it.url = n
    return true
  })
}

export interface BuildRouteUrlParams {
  routes?: RouteEntry[]
  currentUrl: string
  routerBase?: string | null
  detectedBasePath?: string | null
}
export interface BuildRouteUrlResult {
  mode: string
  canUseBaseMode: boolean
  trustedBasePath: string
  candidateBasePath: string
  availableBasePath: string
  sectionTitle: string
  items: UrlItem[]
}

export function buildRouteUrlList(params: BuildRouteUrlParams): BuildRouteUrlResult {
  const routes = params.routes || []
  const currentUrl = params.currentUrl
  const validRoutes = dedupeRoutes(routes)
  const urlObj = new URL(currentUrl)
  const domainBase = urlObj.origin
  let baseUrl = ''
  let isHistoryMode = false
  if (currentUrl.indexOf('#') >= 0) {
    baseUrl = currentUrl.substring(0, currentUrl.indexOf('#') + 1)
  } else {
    isHistoryMode = true
    baseUrl = domainBase
  }
  const paths = validRoutes.map((r) => r.path).filter(Boolean) as string[]
  const trustedBasePath = normalizeBasePath(params.routerBase)
  const candidateBasePath = trustedBasePath ? '' : normalizeBasePath(params.detectedBasePath)
  const availableBasePath = trustedBasePath || candidateBasePath
  const canUseBaseMode = !!(isHistoryMode && availableBasePath)

  function buildUrl(path: string, modeBasePath?: string): string {
    modeBasePath = modeBasePath || ''
    const np = normalizeRoutePath(path)
    const cleanPath = np === '/' ? '' : np.substring(1)
    if (isHistoryMode) {
      if (modeBasePath) {
        if (np === modeBasePath || np.indexOf(modeBasePath + '/') === 0) return baseUrl + np
        return baseUrl + modeBasePath + (cleanPath ? '/' + cleanPath : '')
      }
      return baseUrl + (cleanPath ? '/' + cleanPath : '/')
    }
    if (baseUrl.charAt(baseUrl.length - 1) === '#') return baseUrl + '/' + cleanPath
    if (baseUrl.indexOf('#/', baseUrl.length - 2) === baseUrl.length - 2) return baseUrl + cleanPath
    return baseUrl + '#/' + cleanPath
  }

  const standardUrls = dedupeUrlItems(paths.map((p) => ({ path: p, url: buildUrl(p) })))
  const baseModeUrls = canUseBaseMode ? dedupeUrlItems(paths.map((p) => ({ path: p, url: buildUrl(p, availableBasePath) }))) : []
  const mode = trustedBasePath && canUseBaseMode ? 'base' : 'standard'
  return {
    mode,
    canUseBaseMode,
    trustedBasePath,
    candidateBasePath,
    availableBasePath,
    sectionTitle: mode === 'base' ? '带基础路径 URL：' + (trustedBasePath || candidateBasePath) : '标准 URL',
    items: mode === 'base' ? baseModeUrls : standardUrls
  }
}
